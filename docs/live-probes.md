# Observed checks from a VPC

Use a Lambda probe when you need to send traffic from a subnet, including paths
Reachability Analyzer cannot model. `probe_tcp()` checks a TCP handshake. For
TLS, HTTP, DNS, repeated samples or several checks in one deployment, see
[advanced checks](advanced-checks.md). The [expectation API](expectations.md)
adds English-style assertions over these same checks.

## Write permission belongs in the test

```python
def test_database_accepts_connections(org):
    source = org.in_account("111111111111").in_region("eu-west-2")
    result = source.subnet("subnet-0123456789abcdef0").probe_tcp(
        "database.internal.example",
        port=5432,
        execution_role_arn="arn:aws:iam::111111111111:role/NetworkProbeExecution",
        security_group_ids=["sg-0123456789abcdef0"],
        allow_write=True,
    )
    assert result, result.message
```

Every call that deploys a probe needs `allow_write=True`. Omit it and the library
raises `WriteNotAllowedError` before creating clients or reading inventory. Only
the boolean `True` is accepted. There is no builder-wide permission switch, and
an RA failure never starts a probe automatically.

A one-shot call creates its own function. A `probe_session(..., allow_write=True)`
context creates one function for the checks inside its `with` block and cleans
up when the block ends, including when an assertion or AWS call fails.

Select an account even with `config_mode="off"`. Lambda, IAM and EC2 cleanup use
that account's mapped profile/session, or central credentials after STS confirms
they belong to the account. Config keeps its central reader and fixed region.
The usual profile role assumption, endpoint overrides, TLS and SDK transport
settings apply. IAM roles belong to the selected account and partition;
functions, subnets and security groups also belong to the selected region.

## Prerequisites

- A subnet and one to five distinct security groups for its VPC, or
  `auto_create_security_group=True`. A shared subnet must already be available
  to the deploying account.
- A role in the selected account and partition that trusts `lambda.amazonaws.com`
  and grants VPC interface permissions, or `auto_create_execution_role=True`.
- A caller allowed to create, invoke and delete the function and pass its role.
  Automatic roles and groups need additional create, read and delete permissions.
  See [caller policies](permissions.md#lambda-probe-permissions).
- When Config is enabled, a subnet record available under the usual
  `required`/`prefer` rules. The new function need not appear in Config first.

The probe uses the subnet's existing routing and ACLs. It creates no routes,
endpoints or NAT gateway. Lambda gets no public IP when attached to a public
subnet; internet access normally needs an existing NAT route. See
[AWS's VPC connectivity guide][vpc]. Choose a healthy service in your existing
network for observed checks.

## API and observations

```python
result = rule.subnet(subnet_id).probe_tcp(
    host,
    execution_role_arn=role_arn,
    security_group_ids=[security_group_id],
    allow_write=True,
    port=443,
    connect_timeout=3.0,
    ready_timeout=300.0,
)
```

| Argument | Meaning |
| --- | --- |
| `host` | One IP address matching the selected family, or an ASCII DNS hostname; no URL, CIDR or scope identifier |
| `port` | TCP port 1–65535; default 443 |
| `connect_timeout` | Socket timeout in seconds, greater than zero and at most 10 |
| `ready_timeout` | Polling budget per propagation/readiness stage; default 300 seconds |
| `execution_role_arn` | Existing role in the selected account/partition; omit when creating a role |
| `auto_create_execution_role` | Boolean, default `False`; cannot be combined with `execution_role_arn` |
| `role_cleanup_timeout` | ENI/role cleanup polling budget for automatic roles; default 1200 seconds |
| `security_group_ids` | One to five distinct IDs; omit when creating a group |
| `auto_create_security_group` | Boolean, default `False`; cannot be combined with `security_group_ids` |
| `security_group_cleanup_timeout` | Group deletion polling budget; default 1200 seconds |
| `address_family` | `"ipv4"`, `"ipv6"` or `"dual"`; default `"ipv4"`. IPv6 needs an existing verified dual-stack subnet |
| `expected_addresses` | Exact expected DNS answer set checked before a protocol connection |
| `allowed_destination_cidrs` | Every resolved address must be inside these IPv4/IPv6 CIDRs before connecting |

Timeout values must be finite and positive.

The basic one-shot `probe_tcp()` resolves the hostname **inside the VPC**,
chooses its first IPv4 address and attempts one handshake. It sends no
application data. Pass `address_mode="all"` to check every answer, or select
`address_family="ipv6"` / `"dual"` for IPv6 or both families. Sessions and the
TLS/HTTP APIs test all addresses by default. With both families, `"first"` and
`"any"` apply to each family separately. No requested family can be skipped.

Connection checks can require `expected_addresses` or
`allowed_destination_cidrs` on the exact resolved set they subsequently contact.
A valid mismatch fails before any connection is attempted. A standalone DNS
assertion followed by HTTP is still two independent resolutions. See
[DNS binding](advanced-checks.md#bind-dns-expectations-to-the-actual-connection)
and [dual-stack requirements](advanced-checks.md#ipv6-and-dual-stack-observations).

A passing result means this Lambda made the requested connection at that time.
It does not test an existing instance's process or host firewall. Its subnet and
security groups determine its source access. The destination can be in another
account, region or outside AWS if the network allows it.

| Outcome | Result |
| --- | --- |
| `connected` | Passing `CheckResult` |
| `timeout`, `refused`, `unreachable` | Failing `CheckResult` |
| DNS failure, function execution error, unusable state or malformed output | `ProbeError` |
| Role propagation or readiness deadline exceeded | `ProbeTimeoutError`, a `ProbeError` subclass |
| AWS permission, service or transport failure | Original boto3/botocore exception |

A refusal may mean the host responded but has no listener. A timeout may mean
filtering, an unavailable host or a transient failure. Neither proves isolation,
so there is no negative Lambda predicate. RA's `cannot_reach()` requires a
conclusive modeled answer.

Inspect `result.evidence` for the account, region, Config record, function name,
subnet, groups, role, resolved IP, outcome, timing and cleanup status. Lifecycle
errors also carry `.evidence` where possible. Temporary roles and groups have
separate `temporary_role` and `temporary_security_group` entries; deleting a
function does not mean its other resources have been removed.

## Derive the source from an ENI or instance

```python
application = rule.eni("eni-0123456789abcdef0").named("application")
with application.probe_session(
    allow_write=True,
    execution_role_arn=role_arn,
) as probe:
    result = probe.tls("api.internal.example")
    assert result, result.message
```

This copies the verified workload ENI's subnet and exact security-group set.
It requires an in-use ENI owned by the selected account; subnet/VPC/AZ metadata
must agree with the live subnet. `instance(id).probe_session(...)` also verifies
a running instance and the selected ENI's attached state. For an instance with
several interfaces, supply `network_interface_id="eni-..."` explicitly.

Omit security-group options for a derived session. The library sets
`source_kind="workload_representative"` and checks for source drift before each
terminal call. A changed interface, membership, AZ or group set raises; open a
new session after the change. Existing or automatic execution roles work as
usual. Extra caller reads are listed in the
[permission guide](permissions.md#lambda-probe-permissions).

The selected ENI must have a usable address in each requested family. A dual
subnet alone does not make an IPv4-only workload representative of IPv6 access.
The family check runs before deployment and before each terminal call, using
that call's selected family. Addresses may change while the verified network
context remains the same; the Lambda still uses its own addresses.

The source remains a separate Lambda ENI. It has the copied groups but a different
IP, and does not execute in the workload, test its host firewall or authenticate
as its application. `source_workload` and `source_context` keep this distinction
in result evidence.

## Automatically create an execution role

```python
result = rule.subnet(subnet_id).probe_tcp(
    "database.internal.example",
    security_group_ids=[security_group_id],
    auto_create_execution_role=True,
    allow_write=True,
    role_cleanup_timeout=1200.0,
)
assert result, result.message
```

Omit `execution_role_arn`. The library creates a unique role that trusts Lambda,
with the six ENI actions in the [execution policy](../iam/probe-execution-policy.json).
It grants no logging or application access and attaches no managed policies.
The role is used only for this deployment. Existing roles are never changed.

IAM takes time to propagate changes. The library retries a newly created role's
missing inline-policy target and recognized Lambda role-assumption/ENI-permission
errors within `ready_timeout`. Lambda readiness has a separate budget. Permission
denials and unrelated invalid parameters raise immediately. See the
[API reference](api-surface.md#optional-execution-role-lifecycle) for exact retry rules.

After deleting the function, cleanup waits for matching Lambda ENIs to disappear
before removing the inline policy and role. It reads every ENI page and checks
the exact subnet and group set. AWS can share these ENIs with other functions,
so the wait may outlast the probe. With supplied groups,
`role_cleanup_timeout` defaults to 20 minutes. SDK requests and retries can add
time beyond that budget. For frequent tests sharing groups with long-lived
functions, an existing role avoids this wait.

If ENIs remain, identity information is incomplete or cleanup fails, the library
retains the role and emits `CleanupWarning`. Inspect `temporary_role` in the
result or error evidence for its name, ARN, status, reason and remaining ENI IDs.
It does not delete shared ENIs or remove permissions AWS still needs. A confirmed
but unused role is also cleaned up after partial setup failures. A lost creation
response can leave an orphan; evidence records the attempted name/ARN, but the
library will not delete an unconfirmed role. A contradictory role name or ARN
also stays unconfirmed: no policy is installed and no role is deleted by that
name. A final rejection after SDK retries may follow an earlier successful
creation. Unconfirmed creation emits `CleanupWarning` with the attempted identity.

See [automatic-role permissions](permissions.md#automatic-execution-roles).

## Automatically create a security group

```python
result = rule.subnet(subnet_id).probe_tcp(
    "database.internal.example",
    execution_role_arn=role_arn,
    auto_create_security_group=True,
    allow_write=True,
    security_group_cleanup_timeout=1200.0,
)
assert result, result.message
```

Omit `security_group_ids`; even an empty list conflicts with the automatic
option. You can create the role and group together, but still need
`allow_write=True` on the call or session.

The verified account's EC2 client reads the subnet's current VPC and creates a
uniquely named, tagged group there. In a shared VPC, the subnet owner can differ
from the deploying account; the new group belongs to the deploying account.
Cleanup uses the ID from a successful creation response, never a name-based
lookup of a group that might belong to someone else.

The group has no ingress rules and keeps AWS's default outbound rules, which
allow all outbound traffic. It is the probe's only group. It does not copy a
workload's rules. A destination restricted to another source group may reject
it, and its broad egress may allow traffic a workload would block. Supply the
workload's groups when those rules matter to the test. See
[AWS security-group rules][sg-rules].

Before creating the function, the library waits for the new group's ID, owner
and VPC to be visible and consistent. Missing groups can be retried within
`ready_timeout`; contradictory identity information and permission errors raise.
The new group does not need a Config record.

Cleanup deletes the function, then the group. Only `DependencyViolation` is
retried, within `security_group_cleanup_timeout`. An already absent group counts
as deleted only after it was confirmed visible; otherwise not-found responses
are retried to allow for EC2 propagation. The library never deletes ENIs.

An uncertain function creation/deletion or a failed group deletion retains the
group with `CleanupWarning` and diagnostic evidence. A lost group creation
response records the attempted name and VPC, but cannot safely authorize a
deletion. See the [API reference](api-surface.md) for these failure cases.

With both automatic options, cleanup runs in this order:

1. Delete the function.
2. Delete the security group once AWS releases its dependencies.
3. Remove the inline policy and execution role.

Confirmed group deletion makes a separate ENI enumeration unnecessary. If group
cleanup is uncertain after a function was created, its role stays available for
AWS cleanup. If no function could have been created, an unused role can still
be removed even when group deletion fails. Each polling budget is separate;
SDK calls can extend elapsed time.

Add the [security-group caller policy supplement](../iam/probe-auto-security-group-policy.example.json)
to your caller policy. See [permissions](permissions.md#automatic-security-groups)
for the account, region and tagging conditions.

## Lifecycle and cleanup

Contradictory security-group identity during discovery also stays unconfirmed.
The library records the reported metadata and warns instead of deleting that
ID. A normal visibility timeout or permission error can still roll back a
group whose creation returned its ID without a contradictory identity response.

Each deployment uploads a Python 3.12 ZIP under a unique
`aws-network-asserts-<uuid>` name, waits for `Active`, invokes synchronously and
attempts deletion in `finally`. It publishes no versions. Only a session shares
a function between checks; results are never reused.

Readiness polling uses the builder's `poll_interval`. Each invocation has a
15-second function timeout; DNS time is outside the TCP socket timeout. SDK
retries can repeat requests, and SDK timeouts and cleanup are separate from the
readiness budget.

Deletion requires a successful creation response confirming the function name.
A missing or contradictory name records `cleanup="creation_unconfirmed"` and
raises `ProbeError`. A lost creation response, interrupted process, revoked
permission or AWS error can leave resources behind. The function name in the
evidence helps you investigate.

Successful function deletion records `cleanup="deleted"`; a failure records
`cleanup="failed"` and emits `CleanupWarning`. Cleanup never replaces an earlier
error, even when warnings are treated as errors. Treat a warning as work still
to do, and use the resource IDs in the evidence to investigate.
A confirmed-created function that is already absent also counts as deleted.
An interruption during cleanup records retained dependencies and preserves the
original error or cancellation. Cleanup cannot run after a process is killed.

AWS releases Hyperplane ENIs asynchronously. Keep the execution role available
until that finishes, and do not manually delete shared ENIs. If a supplied role
allows CloudWatch logging, logs can outlive the function; the provided execution
policy omits logging permissions. See [AWS's ENI lifecycle guidance][vpc].

Lambda, networking and any enabled logging can incur charges. Deleting resources
does not reverse those charges. Installing the package and running its offline
tests need no deployment.

## Opt-in example

After configuring accounts and Config as described in the README:

```bash
export SOURCE_SUBNET=subnet-0123456789abcdef0
export DESTINATION_HOST=database.internal.example
export DESTINATION_PORT=5432
export PROBE_EXECUTION_ROLE_ARN=arn:aws:iam::111111111111:role/NetworkProbeExecution
export PROBE_SECURITY_GROUP_IDS=sg-0123456789abcdef0

python -m pytest -p contrib.pytest_examples examples/test_probe.py --run-aws --allow-probe-writes
```

All AWS examples skip without `--run-aws`. This example also skips without
`--allow-probe-writes`; the test itself still passes `allow_write=True`. These
flags are part of the examples, not a required pytest plugin.

To create the role, omit `PROBE_EXECUTION_ROLE_ARN` and add
`--auto-create-execution-role`:

```bash
python -m pytest -p contrib.pytest_examples examples/test_probe.py --run-aws --allow-probe-writes \
  --auto-create-execution-role
```

To create the group too, omit `PROBE_SECURITY_GROUP_IDS` and add
`--auto-create-security-group`:

```bash
python -m pytest -p contrib.pytest_examples examples/test_probe.py --run-aws --allow-probe-writes \
  --auto-create-execution-role --auto-create-security-group
```

### Dual-stack health check

[test_dual_stack.py](../examples/test_dual_stack.py) requires an existing
dual-stack source subnet and a health URL whose hostname returns both A and AAAA
answers. Set the allowed CIDRs to the real destination ranges; every answer must
be inside their union, and every address in both families must return HTTP 200.

```bash
export SOURCE_SUBNET=subnet-0123456789abcdef0
export PROBE_DUAL_STACK_URL=https://api.internal.example/health
export PROBE_DUAL_STACK_ALLOWED_CIDRS=10.47.0.0/16,2001:db8:47::/64
export PROBE_EXECUTION_ROLE_ARN=arn:aws:iam::111111111111:role/NetworkProbeExecution
export PROBE_SECURITY_GROUP_IDS=sg-0123456789abcdef0

python -m pytest -p contrib.pytest_examples examples/test_dual_stack.py --run-aws --allow-probe-writes
```

The IDs, URL and CIDRs above are placeholders. `PROBE_SECURITY_GROUP_IDS` and
`PROBE_DUAL_STACK_ALLOWED_CIDRS` take comma-separated values. To create the role
or group, omit its environment variable and add `--auto-create-execution-role`
or `--auto-create-security-group`, respectively. Both automatic options can be
used together; they still need `--allow-probe-writes` and the caller permissions.
The CloudFormation lab stacks remain IPv4 examples and do not provide this
dual-stack environment.

### Workload-derived health check

[test_workload_probe.py](../examples/test_workload_probe.py) has separate ENI and
instance cases. Set `SOURCE_ENI` or `SOURCE_INSTANCE`, `PROBE_HEALTH_URL`, and an
existing execution role. The test derives its groups from the live interface.
For example, run just the ENI case:

```bash
export SOURCE_ENI=eni-0123456789abcdef0
export PROBE_HEALTH_URL=https://api.internal.example/health
export PROBE_EXECUTION_ROLE_ARN=arn:aws:iam::111111111111:role/NetworkProbeExecution

python -m pytest -p contrib.pytest_examples examples/test_workload_probe.py -k eni --run-aws --allow-probe-writes
```

For the instance case, set `SOURCE_INSTANCE` and use `-k instance`. If the
instance has several interfaces, also set `PROBE_NETWORK_INTERFACE_ID` to the
intended ENI. Run without `-k` to select both cases; each requires its own source
variable. An unset source skips that opt-in example case. To create the role,
omit `PROBE_EXECUTION_ROLE_ARN` and add `--auto-create-execution-role`.
`--auto-create-security-group` is rejected for these tests because a new group
would change the workload context being checked.

All these examples also accept `--ministack`, using the contrib shim and the
same write gates. See [MiniStack setup](usage.md#ministack-examples) for account
and endpoint inputs. The selected service must implement the required APIs and
network behavior; the option does not itself provide IPv6 or workload execution.

[vpc]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html
[sg-rules]: https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html

## Keep a recovery record

Supply `cleanup_manifest=".probe-runs/check-unique.json"` to a one-shot deployment
or `probe_session()`. Create the parent directory first and use a fresh path for
each deployment. The private JSON file records creation intent, confirmed AWS
identities and cleanup progress; it contains no credentials. Ordinary context
cleanup still runs. The [recovery guide](recovery.md) explains how to inspect or
clean up a run after the process dies, including identity checks and role reuse
that can require manual review.

For a check that must originate inside an instance, use an explicitly authorized
[SSM probe session](ssm-probes.md). A workload-derived Lambda still uses Lambda's
own interface; SSM uses the managed host under the agent's execution user.
