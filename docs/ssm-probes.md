# Run a probe inside an instance

Use an SSM session when the check needs the instance's own network stack. The
library sends fixed DNS, TCP, TLS or HTTP operations through Systems Manager Run
Command. It creates no Lambda function, execution role, security group or probe
files, and installs nothing on the instance.

The instance must already be a running EC2 Linux node registered with SSM, with
an online agent and `python3` version 3.10 or newer on the agent's PATH. Its
existing permissions and connectivity must allow SSM to deliver commands and
collect results. The library does not enable SSM, change the instance profile,
open firewall rules or install Python.

## Open an explicit session

```python
from aws_network_asserts import expect, get, resolve

application = (
    org.in_account("111111111111")
    .in_region("eu-west-2")
    .instance("i-0123456789abcdef0")
    .named("application")
)

with application.ssm_probe_session(
    allow_write=True,
    expected_source_cidrs=["10.40.0.0/16"],
) as probe:
    result = expect(probe).to(
        get("https://api.internal.example/health")
        .returning_status(200)
        .containing("ready")
        .with_options(allowed_destination_cidrs=["10.47.0.0/16"])
    )
    expect(probe).to(resolve("api.internal.example").within_cidrs("10.47.0.0/16"))

report = result.to_dict()
assert report["evidence"]["transport"] == "ssm"
```

Each session needs literal `allow_write=True`: sending a command executes code
on the instance. Construction validates this gate and the options before making
AWS calls. Select an account explicitly. The same verified account credentials
perform the EC2 discovery, SSM reads, command submission, polling and any
cancellation; central Config and Reachability Analyzer identities stay separate.

Use an instance selector. An SSM session has no Lambda role/group options and
does not accept shell commands, a custom document, a working directory or a
different Python executable. Session construction is side-effect free. Entering
the context verifies prerequisites; terminal checks submit the commands.

The protocol methods and matchers are shared with Lambda sessions: `tcp()`,
`tls()`, `http()` and `dns()`, including DNS-bound destination restrictions,
sampling, TLS verification and HTTP status/body criteria. The direct methods
return `CheckResult`; the matchers also assert it. A failed observed check never
proves isolation, so negated protocol matchers remain unsupported.

## What the source evidence means

EC2 discovery verifies the reservation owner, matching running instance, its
complete ENI set and each live attachment. SSM discovery must identify that same
online Linux EC2 node. The session records current subnets, VPCs, Availability
Zone, exact security groups and assigned address families. It repeats these
checks before **each command**, including a connection following DNS resolution.
Changed interfaces, attachments, subnet/VPC/AZ or group sets raise before the
next command. Assigned IP changes within the requested families are allowed.
These reads are snapshots, so configuration can still change while a command runs.

A multi-ENI instance uses its normal operating-system route selection. The API
does not offer an interface-selection option because it does not bind sockets
to an interface. Evidence lists all interfaces; a single source subnet, VPC or
group set is reported only when unambiguous. A connection's reported local IP
must identify one current ENI, which is attached as `source_interface` to that
observation.

Packets originate in the instance's host network under the SSM execution user,
usually root. Runtime evidence records the effective UID. `host_firewall_tested`
is true for that host/user context. This does not reproduce an application's
user, credentials, container network namespace, proxy settings or process
environment. A host firewall rule tied to another user can behave differently.
Use an application-specific test when those distinctions matter.

Set `address_family="ipv6"` or `"dual"` on the session for IPv6 observations.
The native interface assignments must establish every requested family. Dual
checks require both A and AAAA results and per-family success; terminal calls
may narrow the family but cannot enable one outside the session. Unlike Lambda,
SSM introduces no separate dual-stack-subnet deployment prerequisite: it uses
the instance's existing network configuration.

## Commands, timeouts and evidence

| Session option | Default | Meaning |
| --- | --- | --- |
| `allow_write` | `False` | Must be literal `True` for each session |
| `address_family` | `"ipv4"` | `"ipv4"`, `"ipv6"` or `"dual"` |
| `expected_source_cidrs` | `()` | Optional permitted local source-address ranges |
| `command_timeout` | `60` | Controller polling budget in seconds for each command; positive, at most 3600 |
| `execution_timeout` | `30` | Agent execution timeout in seconds; integer 2–300 |
| `poll_interval` | `1` | Positive polling interval, at most 30 seconds |
| `cancellation_timeout` | `5` | Positive polling budget after cancellation, at most 60 seconds |

Each terminal connection check first sends a DNS operation, then a separate
operation for each selected address/attempt. DNS answers are pinned to literal
addresses for the subsequent connections. A standalone DNS assertion uses one
command. `command_timeout` is per command, not a total session or sampling
budget; SDK request timeouts and retries are separate. Reported protocol latency
measures the remote operation and excludes SSM delivery/polling overhead.

Commands always use `AWS-RunShellScript`. The packaged standard-library handler
and JSON request are base64-encoded inside a fixed program run with
`python3 -I -B`. User target strings become data, never shell syntax. The process
uses an alarm alongside the agent execution timeout and closes sockets through
the handler's `finally` blocks. It writes no probe files or bytecode.

Every result is bound to the submitted request using a nonce and handler/request
SHA-256 values. The response also identifies Linux, Python and the effective
UID. A command's `Success` status alone cannot satisfy a reachability check.
The protocol observation must still match its kind, destination, port, source
and success criteria. Missing Python, permission errors, failed commands,
unknown outcomes, malformed output and incomplete evidence raise.

SSM returns only the first 24,000 output characters through
[`GetCommandInvocation`](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetCommandInvocation.html).
The wrapper caps its JSON below 20,000 bytes, and the caller rejects output at
that limit, nonempty stderr or invalid JSON. Commands are capped at 48,000 bytes;
large CA bundles or requests may need to be reduced. No S3 or CloudWatch output
destination is requested by the library.

Results retain the command IDs, unique comments, status responses, runtime
metadata, source snapshots and cleanup state. A context shares this deployment
record across its results. Call `to_dict()` after leaving the context when you
want its final snapshot.

## Cancellation and retained records

On polling timeout, interruption or another error after confirmed command
creation, the library requests cancellation for that command and the single
selected instance, then polls within `cancellation_timeout`. The original
error remains visible even if cancellation fails or cleanup warnings are
promoted to errors.

[`CancelCommand`](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_CancelCommand.html)
does not guarantee that the underlying process stops. Cancellation emits
`CleanupWarning`; evidence records whether it was requested, the last observed
status and `process_stop_confirmed=False`. Inspect the command in SSM when
execution remains uncertain. A late success after a timeout does not turn that
timed-out check into a pass.

A missing or contradictory command identity is never used to cancel another
command. If a send response is lost or cannot confirm the target/document,
creation stays unconfirmed and the unique comment/returned ID is retained for
investigation. The library does not retry `SendCommand` itself; configured SDK
retries can still make a lost response ambiguous because this API has no
client-token field.

Even a successful send response can report SDK retries. Such a response confirms
only its returned command ID. The session warns on exit, records
`sdk_retry_attempts` and `earlier_commands_unconfirmed`, and leaves aggregate
command cleanup unconfirmed even after that returned command finishes. It does
not discover, adopt or cancel other commands by matching their names/comments.
An existing check or session-body error survives this warning when warnings
are configured as errors.

There are no library-created host files to remove. SSM keeps its own command
history, output and agent artifacts according to the existing service/agent
retention settings; the library does not delete those records or claim that
they have been cleaned up. The fixed command includes the request, so apply
the same access controls you use for other SSM execution history.

## Permissions and running the example

The [caller policy example](../iam/ssm-probe-caller-policy.example.json) scopes
`ssm:SendCommand` to `AWS-RunShellScript` and one instance. Replace its Region,
account, instance and ARN partition. Discovery, invocation reads and cancellation
use their required wildcard resource scope. Existing SCPs and boundaries still
apply. Granting RunShellScript permission permits command execution outside
this library too; use a dedicated test identity with the intended instance scope.

The existing instance profile needs the usual SSM managed-node permissions.
That setup is separate from this caller policy and is never installed by a test.
See [permissions](permissions.md) for the shared account/profile rules.

Repository examples keep the AWS gate and require a separate
`--allow-ssm-commands` option. Writing a test does not authorize running it.
No example automatically enrolls a node, installs Python or changes credentials.
