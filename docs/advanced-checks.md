# Check protocols, coverage and return paths

A useful test says which sources, destinations and protocols it covers. This
guide shows how to check every DNS answer, sample connections, inspect TGW return
routes and collect results without losing track of that scope. Probes still need
`allow_write=True`; no check starts one automatically. The same checks are
available through the [English-style expectation API](expectations.md).

## TCP, TLS, HTTP and DNS in one deployment

```python
subnet = production.subnet("subnet-0123456789abcdef0")
with subnet.probe_session(
    allow_write=True,
    auto_create_execution_role=True,
    auto_create_security_group=True,
) as probe:
    assert probe.dns("api.internal.example", allowed_cidrs=["10.47.0.0/16"])
    assert probe.tcp("api.internal.example", port=443, address_mode="all")
    assert probe.tls("api.internal.example")
    result = probe.http(
        "https://api.internal.example/health",
        expected_statuses=[200],
        body_contains="ready",
    )
    assert result, result.message

# Cleanup has finished (or warned); this is a JSON-compatible snapshot.
report = result.to_dict()
assert report["evidence"]["deployment"]["cleanup"] == "deleted"
```

The context requires literal `allow_write=True` before any AWS calls. It creates
one function and, if requested, one role and one security group. Each check reads
Config again when enabled and invokes the function afresh. A session is
synchronous and can be opened only once. Leaving the block triggers cleanup,
including after an assertion or AWS error. Inspect any `CleanupWarning` as
explained in the [lifecycle guide](live-probes.md); the evidence lists resources
that still need attention.

Single-call equivalents are `subnet.probe_tls(host, **options)`,
`subnet.probe_http(url, **options)` and `subnet.probe_dns(host, **options)`.
They accept the same deployment options as `probe_tcp()` and perform validation
before deployment. Each one creates and cleans up its own deployment. A session
accepts deployment/source options; connection options belong to each terminal
`tcp()`, `tls()` or `http()` call.

Session and protocol checks first read the live source subnet, including its VPC,
owner and Availability Zone. Shared subnet owners may differ from the selected
Lambda account. Subnet discovery requires `ec2:DescribeSubnets`, even with
supplied security groups. Lambda validates that the chosen groups belong to its
VPC. Existing [caller policies](permissions.md#lambda-probe-permissions) include
this read.

### Source context

Session and protocol results record `source_context`: selected account/region, subnet and its
owner, VPC, Availability Zone, actual group IDs, group selection mode and
`host_firewall_tested=False`. Each successful connection also records the local
socket's `source_ip` and ephemeral `source_port`.

`source_kind="synthetic"` is the default. To label a check as representing a
workload's subnet/group context, supply that workload's existing security groups
and set `source_kind="workload_representative"` when opening the session or
calling a one-shot probe. On a subnet selector this is a caller declaration:
the library cannot verify which workload those supplied groups represent.
This mode rejects `auto_create_security_group=True`. A synthetic group can have
broader egress and different source-group access than the workload.

To derive the source settings from an actual workload, open the session on its
ENI or instance instead:

```python
application = production.eni("eni-0123456789abcdef0").named("application")
with application.probe_session(
    allow_write=True,
    auto_create_execution_role=True,
) as probe:
    result = probe.http("https://api.internal.example/health", body_contains="ready")
    assert result, result.message
```

The selected account must own the live, in-use ENI. The library copies its exact
security-group set and verifies its subnet, VPC and AZ before deploying Lambda.
For `instance(id).probe_session(...)`, the instance must be running and its ENI
must be attached to that instance. An instance with several ENIs needs an
explicit `network_interface_id="eni-..."`; the library never guesses one.
Omit `security_group_ids` and `auto_create_security_group=True` on derived
sessions. Their source kind is always `workload_representative`; automatic role
creation is still available.

Each terminal check re-reads the workload and its interface. A changed ENI,
subnet, VPC, AZ, attachment or group set raises and asks you to open a fresh
session. The ENI must have usable addresses for the deployment's requested
families at entry and for the selected family of each terminal call. A dual
subnet does not turn an IPv4-only ENI into a representative IPv6 source. Config
records for both the workload and the derived subnet are kept
when enabled. Results carry `source_workload` evidence as well as the Lambda's
`source_context`. These reads are observations at check time, not a lock against
infrastructure changing during a call.

Both forms deploy a separate Lambda ENI. Neither reuses the workload's address,
executes inside its process, tests its host firewall or proves application
identity. Source-group rules are reproduced only by using the selected groups;
other workload-specific controls can still differ.

Optionally set `expected_source_cidrs=["10.1.0.0/24"]` on the deployment. Each
connection must report a local source address in one of those IPv4/IPv6 ranges.
A measured mismatch fails; absent source evidence raises. This address is before
any downstream NAT, not an address observed at the remote server. Use a separate
context for each source subnet/AZ; one Lambda does not establish segment-wide
coverage.

### Protocol and address options

Session `tcp()`, `tls()` and `http()` checks resolve addresses inside the VPC
and use `address_mode="all"` by default. Every distinct address must satisfy its
own success threshold. `"any"` requires at least one passing address **in each
requested family**; `"first"` tests the first address of each requested family.
Evidence retains the complete resolved list and tested subset. An empty, invalid
or duplicated response, or more addresses than `max_addresses` (default 32,
range 1–32 across both families), raises instead of truncating coverage.
Resolution occurs once per terminal call; every sample in that call connects
directly to an address from that same set.

The one-shot `subnet.probe_tcp()` defaults to a single
handshake to the first address, with its original request shape and evidence.
Pass `address_mode="all"` to test every answer with the same evidence as a
session check. Sampling or source options also select that implementation, but
keep the one-shot default of `address_mode="first"` unless you change it.
The basic IPv4 one-shot path includes synthetic source context without an
extra live AZ read. Destination constraints or a non-default family select the
protocol implementation and its live subnet discovery.

| Option | Meaning |
| --- | --- |
| `port` | 1–65535, default 443 for TCP/TLS; HTTP takes its port from the URL |
| `connect_timeout` | Positive finite TCP socket timeout, default 3 s, maximum 10 s |
| `read_timeout` | TLS/HTTP socket timeout, default 3 s, maximum 10 s; unsupported on TCP-only checks |
| `server_hostname` | TLS certificate name and SNI; defaults to the DNS name or IP being tested |
| `ca_pem` | Optional trusted PEM CA bundle, validated before deployment, at most 128000 characters |
| `expected_statuses` | Nonempty sequence of HTTP status integers; default `[200]` |
| `http_method` | `GET` or `HEAD`; default `GET` |
| `body_contains` | Optional nonempty UTF-8 byte substring on GET responses |
| `max_body_bytes` | Body search limit, default 4096, range 1–65536 bytes |
| `address_family` | `"ipv4"` by default; `"ipv6"` or `"dual"` enables the corresponding observed coverage |
| `expected_addresses` | Optional nonempty set of expected IP answers, compared with the entire resolved set before connecting |
| `allowed_destination_cidrs` | Optional IPv4/IPv6 CIDRs; every resolved destination must lie in their union before any connection is attempted |

Explicit options must apply to the chosen protocol. HTTP status/body/method
options are rejected on TCP and TLS checks; TLS name/CA options are rejected on
TCP and plain HTTP. This also applies when composing a matcher, so an ignored
criterion cannot appear in a passing assertion.

TLS uses certificate and hostname verification with the Lambda runtime trust
store, or the supplied CA bundle. There is no insecure verification switch.
Evidence includes TLS version and certificate SHA-256. HTTP rejects port zero,
userinfo (including empty credentials), and raw ASCII
whitespace/control characters before deployment; use percent encoding for spaces
in paths. This avoids silently checking a normalised URL or a default port.
HTTP connects to each
resolved IP while preserving the URL Host header and TLS name. It requests the
exact URL and does not follow redirects, authenticate, send a request body or
retain a response body. A redirect can satisfy the test only if its status was
explicitly allowed. These methods transmit application traffic: select harmless
GET/HEAD endpoints whose behaviour you authorise.

The body search reads at most the limit plus one byte. A matching substring
within the limit can pass. A complete nonmatching body fails; a nonmatching
truncated body raises because absence was not established. A read timeout or
protocol failure fails the positive probe. Deployment, DNS, malformed output,
unknown socket failures and Lambda execution errors raise. A TLS verification
failure is a failed TLS assertion even when TCP connected.

Each invocation has a 15-second Lambda execution limit. Configured connection
plus protocol stage timeouts must total at most 12 seconds (one TLS stage and/or
one HTTP stage). Socket timeouts apply to individual operations, so this budget
does not guarantee a total deadline; slow/trickling responses or DNS can still
hit the Lambda limit and raise. SDK timeouts and retries apply separately.

### DNS expectations

```python
assert subnet.probe_dns(
    "api.internal.example",
    expected_addresses=["10.47.1.10", "10.47.2.10"],
    allowed_cidrs=["10.47.0.0/16"],
    execution_role_arn=role_arn,
    security_group_ids=[workload_group_id],
    allow_write=True,
)
```

`expected_addresses` requires exact set equality, independent of order.
`allowed_cidrs` requires every returned address to fall within the union of the
specified IPv4/IPv6 ranges. Specify either or both; both constraints apply when
combined. Missing prerequisites, resolution failures, empty responses and
oversized address sets raise. A valid but unexpected answer fails. These are
IPv4/A observations by default. Select `address_family="ipv6"` for AAAA or
`"dual"` to require both families. They do not establish resolver failover.

### Bind DNS expectations to the actual connection

A separate `dns()` call and a later `http()` call perform separate resolutions.
To constrain the addresses that are actually contacted, put the expectations
on the connection check:

```python
with subnet.probe_session(
    execution_role_arn=role_arn,
    security_group_ids=[workload_group_id],
    allow_write=True,
) as probe:
    result = probe.http(
        "https://api.internal.example/health",
        expected_addresses=["10.47.1.10", "10.47.2.10"],
        allowed_destination_cidrs=["10.47.0.0/16"],
        expected_statuses=[200],
        body_contains="ready",
    )
    assert result, result.message
```

Both expectations apply when combined. They validate the entire resolved set,
even with `address_mode="first"` or `"any"`. A valid but unexpected answer
returns a failing result before TCP/TLS/HTTP connection invocations;
`tested_addresses` and `attempts` are empty. Resolution errors and malformed
answers raise. Passing checks connect to the validated IPs while retaining the
original HTTP Host and TLS name, so a second DNS lookup cannot change the
connection target. `expected_addresses`, `allowed_destination_cidrs` and
`destination_addresses_match` stay in the result evidence.

### IPv6 and dual-stack observations

```python
with subnet.probe_session(
    execution_role_arn=role_arn,
    security_group_ids=[workload_group_id],
    allow_write=True,
    address_family="dual",
) as probe:
    result = probe.http(
        "https://api.internal.example/health",
        allowed_destination_cidrs=["10.47.0.0/16", "2001:db8:47::/64"],
    )
    assert result, result.message
    assert result.evidence["family_results"]["ipv4"]["passed"]
    assert result.evidence["family_results"]["ipv6"]["passed"]
```

`address_family` belongs to the deployment and defaults to `"ipv4"`. An IPv6 or
dual deployment requires an existing subnet with an IPv4 CIDR and an associated
IPv6 CIDR. The library validates those live fields, then sets Lambda's
`VpcConfig.Ipv6AllowedForDualStack=True`. It does not add CIDRs, routes, egress
rules, gateways or endpoints. Supply the intended IPv6 routing and security
rules yourself. [AWS's Lambda IPv6 guide](https://aws.amazon.com/blogs/compute/aws-lambda-networking-over-ipv6/)
describes the prerequisites.

A dual session may narrow an individual call with `address_family="ipv4"` or
`"ipv6"`. A call cannot widen a deployment to a disabled family. One-shot
protocol methods accept the same option and deploy for that family.
`"dual"` needs a DNS hostname with both A and AAAA answers. A missing requested
family raises `ProbeError`; it never falls back silently. IPv6-only checks
accept one IPv6 literal, and HTTP literals use brackets, for example
`http://[2001:db8:47::10]:8080/health`. Scoped (`%...`) and IPv4-mapped IPv6
addresses are rejected because they cannot establish the requested coverage.

`addresses_by_family` records the resolved A/AAAA sets. After connection
attempts, TCP/TLS/HTTP report `family_results`, with each family's addresses
and success. Every requested
family must pass; IPv4 success cannot mask IPv6 failure, even in `"any"` mode.
Failures are still failed positive observations, never proof of isolation.
RA remains IPv4-only; the IPv6 support here belongs to observed Lambda checks.
The [dual-stack example](live-probes.md#dual-stack-health-check) lists the
required inputs and command. The supplied CloudFormation labs remain IPv4.

## Connection sampling and convergence

```python
with subnet.probe_session(
    execution_role_arn=role_arn,
    security_group_ids=[workload_group_id],
    allow_write=True,
) as probe:
    result = probe.http(
        "https://api.internal.example/health",
        attempts=5,
        successes_required=4,
        interval=0.5,
        max_latency_ms=500,
        address_mode="all",
    )
    assert result, result.message
```

`attempts` is 1–10 fresh connections **per address**. `successes_required` is
1–attempts, defaulting to every attempt. `interval` is a finite 0–5 second delay
between samples of the same address. Every sample, including failures, remains
in `evidence["attempts"]`; per-address totals are in `address_results`.
`max_latency_ms` applies to the whole connection/protocol observation, excluding
DNS and Lambda invocation overhead. DNS and per-stage timings are separate.
This is a bounded sample, not an availability SLA or sustained load test.

For eventual configuration convergence, use a separate helper:

```python
from aws_network_asserts import wait_for

result = wait_for(
    lambda: production.subnet(subnet_id).has_route_to("10.47.0.0/16", via=tgw_id),
    timeout=60,
    interval=2,
    max_attempts=20,
)
assert result, result.message
```

`wait_for()` repeats fresh checks only after a conclusive failing `CheckResult`.
Exceptions propagate immediately. A successful observation ends the wait;
exhaustion returns the last failing result with all observations in
`evidence["convergence"]`. Limits bound repetition and sleeps, not callback/SDK
execution or cleanup. `max_attempts` is 1–100; timeout/interval must be positive
and finite. Waiting until one sample succeeds does not establish reliability.

## TGW association, forward routes and return routes

```python
hub = org.in_account("222222222222").in_region("eu-west-2").tgw(tgw_id)
ingress = hub.route_table(ingress_table_id)
reverse = hub.route_table(return_table_id)

assert ingress.has_association(source_attachment_id)
assert reverse.has_association(destination_attachment_id)
assert ingress.has_bidirectional_routes(
    "10.47.0.0/16",
    source="10.1.0.0/16",
    return_table=reverse,
    via=destination_attachment_id,
    return_via=source_attachment_id,
)
```

Scope these reads to the TGW owner. `has_association()` checks the selected
attachment's actual association with the specified table, consuming all pages
and validating attachment/TGW ownership and identity. A participant VPC's owner
can differ from the TGW owner. `has_route_to(cidr, via=attachment_id)` checks every
address in the requested IPv4/IPv6 range using interval boundaries. Active
supernets can provide coverage; more-specific blackholes or wrong next hops
fail. Every possible member of a selected multi-attachment route must satisfy
`via` when supplied.

`has_bidirectional_routes()` checks two explicitly selected ingress tables and
CIDRs of the same address family in the same account/region/TGW. It evaluates
both directions, even if one
fails, and retains separate results. Association is a separate assertion.
Propagation alone does not establish either association or effective routing.
These checks do not establish VPC subnet routes, security rules, endpoint health
or packet delivery; combine them with VPC route checks and RA/probes.

Route searches consume supernet/subnet results and independently discover
prefix-list references, so a reference omitted by a CIDR search is still
evaluated. They deduplicate results, expand managed prefix lists and consume
continuation pages. Truncated results without a token
raise. Longest prefix and exposed static/prefix-list/propagated precedence apply;
ambiguous equal-priority routes raise when required BGP ordering is unavailable.
AWS exposes preferred routes rather than every backup path, so this does not
prove failover routing. Older SDK models may lack continuation-token support;
use a current boto3/botocore for paginated TGW searches. The library does not
invent missing routes or infer safety from truncated responses.

## Declare the coverage you require

```python
from aws_network_asserts import CoverageCase, CoverageMatrix

matrix = CoverageMatrix(
    [
        CoverageCase(
            name="api-from-a",
            account_id="111111111111",
            region="eu-west-2",
            source_id="subnet-0123456789abcdef0",
            availability_zone="eu-west-2a",
            destination="https://api.internal.example/health",
            port=443,
            kind="http",
        ),
        CoverageCase(
            name="api-from-b",
            account_id="111111111111",
            region="eu-west-2",
            source_id="subnet-0123456789abcdef1",
            availability_zone="eu-west-2b",
            destination="https://api.internal.example/health",
            port=443,
            kind="http",
        ),
    ]
)


def evaluate(case):
    source = org.in_account(case.account_id).in_region(case.region).subnet(case.source_id)
    return source.probe_http(
        case.destination,
        execution_role_arn=role_arn,
        security_group_ids=[workload_group_id],
        allow_write=True,
    )


assert matrix.run(evaluate)
report = matrix.report()
```

A matrix is an explicit nonempty list of uniquely named cases. Its `cases` mapping
is read-only; create a new matrix to change the required coverage. It verifies
actual
account, region, source, destination, port, check kind and optional declared AZ
against each result's evidence. Kinds are `tcp`, `tls`, `http`, `dns` (with
`port=None`) or `ra`. RA destinations must match the qualified destination
recorded in evidence; RA ports must select one explicit port. An unscoped result
cannot satisfy a scoped declaration. For DNS, the destination is its hostname;
for HTTP it is the complete URL.

Alternatively call `matrix.record(case_or_name, result)` while running batches,
then `assert matrix.check()`. Duplicate and mislabeled results raise. Missing
cases raise `CoverageError`, never pass an empty `all()`; evaluated failures
produce a failing summary. `run()` preserves the original evaluation exception
and attaches `.coverage_evidence` containing partial progress. It stops at that
error; a later run resumes only missing cases. Reports include each declaration,
result and error. Capture reports after context cleanup with `report()` or
`CheckResult.to_dict()`; snapshots already taken do not update themselves.

## Isolation with a healthy positive control

```python
from aws_network_asserts import isolation_with_control

with allowed_source.probe_session(
    allow_write=True,
    execution_role_arn=role_arn,
    security_group_ids=[allowed_group_id],
) as probe:
    result = isolation_with_control(
        lambda: denied_source.eni(denied_eni_id).cannot_reach("10.47.1.10", port=443),
        positive_control=lambda: probe.tls("10.47.1.10", server_hostname="api.internal.example"),
    )
    assert result, result.message
```

A successful real TCP/TLS/HTTP control runs first. For sampled controls, the
matching destination address must satisfy its own configured success threshold;
a single passing attempt or a healthy different DNS address is insufficient. Then a conclusive RA
`cannot_reach()` answer must concern the same explicit IPv4 address and TCP port.
An inconclusive analysis, failed control or mismatch raises; a reachable RA path
fails the isolation assertion. The control demonstrates endpoint health from
its own source at that observation time. It does not prove the blocked source
has an identical return path or explain every packet drop. A failed Lambda
connection still cannot establish isolation, and controls are not run implicitly.

## Opt-in example

[The protocol example](../examples/test_protocol_probe.py) skips without
`--run-aws` and also requires `--allow-probe-writes`. Set `SOURCE_SUBNET`,
`PROBE_TLS_HOST`, `PROBE_HEALTH_URL` (a harmless GET endpoint returning 200) and
comma-separated `PROBE_DNS_ALLOWED_CIDRS`, plus the account/Config settings and
role/group choices from the [lifecycle example](live-probes.md#opt-in-example).
The existing automatic role/group command options also apply. Running it sends
DNS, TLS and HTTP traffic to those explicit targets and can incur AWS charges.

## Exact populations and complete connection grids

Before asserting properties of a discovered collection, compare it with the
intended scoped resources using `contain_exactly_resources(*expected)`. Missing,
unexpected and duplicate observed resources fail. An invalid expected population
raises. This comparison is local; discovery itself can read AWS.

`expect(every(sources)).to(reach_each(destinations).over_tcp(443, 8443))` evaluates
the complete directed source × destination × port grid. It does not infer reverse
connections. Inspect `.plan(matcher)` before running and set `max_ra_analyses=N`
to reject excessive execution before any case starts. See the
[expectation guide](expectations.md#every-source-destination-and-port).

## Stability is different from convergence

`.consistently(checks=5, interval=2)` requires every sample to pass and stops on
the first conclusive failure. `.eventually(...)` needs one passing sample before
its deadline. Errors are never retried as failures. Stability runs sequentially
per source/case, not simultaneously across a fleet, and cannot prove availability
between samples. Connection-attempt thresholds inside one probe remain a
separate requirement. Timing wrappers cannot be stacked.

For host-network observations use the [SSM source](ssm-probes.md). It shares
protocol checks, coverage reporting and healthy isolation controls with Lambda
sessions. For interrupted Lambda processes, use an explicit
[cleanup manifest and recovery](recovery.md). Inspection routing requirements
have their own [topology guide](inspection-checks.md).
