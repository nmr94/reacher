# Tests that read like requirements

Use named fixtures for your resources and matchers for the requirement. These
are ordinary Python tests run by pytest; there is no extra runner or plugin.

```python
from aws_network_asserts import expect, reach


class TestDatabaseAccess:
    def test_allows_application_connections(self, application, database):
        expect(application).to(reach(database).over_tcp(5432))

    def test_blocks_ssh_from_application(self, application, database):
        expect(application).not_to(reach(database).over_tcp(22))
```

Here `application` and `database` are fixtures returning scoped ENI or instance
selectors. Bind them to real resources once in your fixtures:

```python
production = org.in_account("111111111111").in_region("eu-west-2")
shared = org.in_account("222222222222").in_region("eu-west-2")
application = production.eni(app_eni_id).named("application")
database = shared.eni(db_eni_id).named("database")
```

Names improve reports; the resource IDs, accounts and regions stay visible.
`.named()` returns an independent selector and makes no AWS call. Config, central
analysis credentials, scoped live reads and MiniStack sessions work as before.

## When a check runs

`reach(database).over_tcp(5432)` describes a check. `expect(application)` chooses
its source. Only `.to(matcher)` or `.not_to(matcher)` evaluates and asserts it.
Each assertion runs a fresh check. A failed predicate raises `AssertionError`
with `.result` and `.evidence`; a passing assertion returns its `CheckResult`.
AWS errors and evaluation errors keep their original types and diagnostics.

Matchers are immutable, so you can reuse a description safely:

```python
database_access = reach(database).over_tcp(5432)
expect(application_a).to(database_access)
expect(application_b).to(database_access)
```

A bare matcher, expectation or `every()` collection raises on a truth test. An
incomplete propagation or DNS matcher is rejected before evaluation. Matchers
do not deploy a probe or silently choose another analysis method.

The direct API remains useful when you need an unasserted `CheckResult`, for
example inside a custom diagnostic tool. `application.can_reach(database,
port=5432)` returns that result; the expectation form asserts it for you.

## Modeled packet paths

`reach()` uses Reachability Analyzer. TCP port 443 is the default; make the
protocol and port explicit when they are part of the requirement.

```python
expect(application).to(
    reach(database)
    .over_tcp(5432)
    .at_address("10.47.1.10")
    .from_address("10.40.1.10")
    .from_port(45000)
)
```

The address filters refer to the packet leaving the source. `over_udp(port)`
selects UDP. RA supports IPv4 and one region per analysis. It models AWS
configuration and sends no application traffic.

### Require or forbid a component

```python
expect(application).to(reach(database).over_tcp(5432).through(tgw_id).avoiding(internet_gateway_id))
```

These constraints inspect the reported **forward** path. They do not tell AWS
to search for a different path or prove which hops live packets took.

A constrained check needs an explicit resource destination and a successful,
endpoint-anchored forward path with usable component identities and sequence
numbers. IP-only destinations are unsupported for this claim. Missing, gapped,
contradictory, warned or explained path evidence raises rather than proving
that a forbidden hop was absent. ARN constraints need the matching ARN identity;
a bare ID does not establish its ownership. Each reported ID/ARN pair is checked
independently; ownership cannot come from another hop with the same short ID.
Components must be in the analysis
region. A fully reported path missing a required component, or containing a
forbidden one, fails the positive assertion. A conclusive blocked path also
fails a positive expectation without claiming that its required hops were checked.

Use traffic component IDs/ARNs: instances, ENIs, gateways, peering connections,
VPC endpoints and supported firewall/load-balancer ARNs. SGs, ACLs and route
tables are configuration objects; check their relationships/routes separately.
Path constraints cannot be negated to establish isolation. They retain AWS's
[analysis limitations](https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html),
including the limits on TCP return analysis through TGW tables.
Unsupported or unknown AWS `AdditionalDetails`, such as omitted firewall or
GWLB inspection, raise for ordinary reachability checks too. They cannot become
a passing modeled denial. Documented informational details remain visible under
RA's limits.

Results also contain structured `explanations`: AWS's code, a short description,
reported ingress/egress direction, forward/return context where available,
resource roles/IDs and the original explanation. Unrecognized codes remain
visible as AWS codes; the library does not invent a diagnosis.

## Route and topology requirements

```python
from aws_network_asserts import be_peered_with, have_route_to

expect(application_subnet).to(have_route_to(database_cidr).via(tgw_id))
expect(vpc_a).to(be_peered_with(vpc_b))
```

A positive route check covers the whole requested IPv4/IPv6 range. Supernets
can supply coverage; more-specific blackholes or wrong targets fail it. It is
a routing check, separate from modeled delivery or service health.

| Matcher | Source |
| --- | --- |
| `have_route_to(cidr).via(target_id)` | Subnet, VPC route table or TGW route table |
| `be_peered_with(other_vpc)` | VPC |
| `have_attachment(vpc_id)` | TGW |
| `have_association(attachment_id)` | TGW route table |
| `propagate_to(tgw_table_id).from_vpc(vpc_id)` | TGW |
| `be_in_subnet(subnet_id)` / `be_in_vpc(vpc_id)` | ENI |
| `be_recorded()` | Typed Config resource selector |

`not_to(have_route_to(host))` can test lack of an effective route for that one
address. A negated non-host CIDR is rejected: incomplete route coverage would
only prove that some addresses lack the requested route. Negating `.via(id)`
says the selected route is not via that target; it does not prove no route exists.
Use native EC2 target IDs in `.via()`. EC2 target ARNs are rejected because a
route response's target ID does not establish the ARN's ownership. Targets
reported natively as ARNs, such as Cloud WAN core networks, use exact ARN matching.

## Every declared source

```python
from aws_network_asserts import every

expect(every(application_enis)).to(reach(database).over_tcp(5432))
```

`every()` requires a finite, nonempty sequence of distinct scoped sources. It
checks subject types before running the first case, evaluates every conclusive
case, and includes all evaluated results in its report. A native error stops
evaluation and carries partial `.coverage_evidence`; it never counts as a pass.
With `not_to(reach(...))`, every declared source must have a conclusive denial.
Select an account for each source, or use an account-qualified endpoint ARN.
Bare IDs under an unscoped builder cannot establish distinct ownership and are
rejected in collections; single unscoped `expect()` checks remain supported.

An endpoint ID and its equivalent scoped ARN declare the same source, so listing
both is rejected. On error, partial `coverage_evidence["results"]` retains
`CheckResult` objects; take `.to_dict()` snapshots when you need a JSON report
after cleanup.

The collection declares coverage. It does not discover every workload for you.
Validate expected IDs/counts when the requirement names a fixed population. For
separate source/destination/protocol/AZ declarations and report-label validation,
use [CoverageMatrix](advanced-checks.md#declare-the-coverage-you-require).

### Verify what discovery found

Before checking every discovered endpoint, compare the population with the
resources the requirement names:

```python
from aws_network_asserts import contain_exactly_resources, every, expect, reach

discovered = application_subnet.enis()
expect(discovered).to(contain_exactly_resources(application_a, application_b))
expect(every(discovered)).to(reach(database).over_tcp(5432))
```

The expected selectors must be scoped, nonempty and unique. The comparison uses
account, region and resource identity; labels and equivalent ID/ARN spellings
do not change the population. Missing, unexpected or duplicate discoveries,
including an empty discovery, fail the assertion. Unknown ownership or malformed
selectors raise. The comparison makes no AWS calls; `enis()` is the separate
live discovery step. Both the expected declaration and discovered sequence are
snapshotted when composed, so changing a caller's list does not change the test.

### Every source, destination and port

```python
from aws_network_asserts import every, expect, reach_each

expect(every(applications)).to(reach_each(databases).over_tcp(5432, 6432))
```

`reach_each()` takes a finite, nonempty sequence of distinct, scoped endpoint
selectors. The port list must also be nonempty and unique. Two applications,
two databases and two ports produce eight fresh analyses. `over_udp(53, 5353)`
uses the same expansion for UDP; TCP/443 is the default. Packet address/source
filters and path constraints work as on `reach()` and apply to every case.

All source/destination/port declarations are checked before the first case
runs. Every conclusive case is evaluated, including after a failed predicate;
results retain their source, destination, protocol and port. A native error
stops execution and keeps partial `.coverage_evidence`. No discovery, probe
deployment or alternate analysis is started by this expansion.

Overlapping source and destination lists include self-pairs. Use explicit
directed cases when the requirement excludes them. Negating `reach_each()` is
rejected: “not every destination is reachable” is different from “none is
reachable.” Declare each required modeled denial with `not_to(reach(...))`.

### Preview the work and cap analyses

```python
requirement = reach_each(databases).over_tcp(5432, 6432).consistently(checks=5)
expectation = expect(every(applications))
plan = expectation.plan(requirement)
print(plan["case_count"], plan["max_ra_analyses"])
expectation.to(requirement, max_ra_analyses=40)
```

With two applications and two databases this declares eight cases and at most
40 analyses. `plan()` validates local declarations and returns their descriptions,
`source_count`, `case_count`, `max_checks`, `max_ra_analyses` and individual cases.
It creates no AWS clients and performs no inventory, topology or connectivity
reads. Provide already resolved selectors; planning does not run discovery.
Use `plan(matcher, negated=True)` to preview a supported negative assertion.

The optional `max_ra_analyses` limit on `.to()` and `.not_to()` rejects the whole
assertion before evaluation when its upper bound exceeds the limit. Counts
include every source, destination, port and maximum convergence or stability
sample. Errors and early mismatches may reduce the actual work. This is a count
of analyses, not a currency estimate or a cap on all SDK requests. Protocol
sampling can open multiple sockets inside one terminal check. RA charges and
the existing probe write gates still apply; a plan grants no execution permission.

## Observed protocol checks

Open a probe session explicitly, then use protocol matchers against that session:

```python
from aws_network_asserts import expect, get

with application_subnet.probe_session(
    allow_write=True,
    execution_role_arn=role_arn,
    security_group_ids=application_groups,
    source_kind="workload_representative",
) as probe:
    result = expect(probe).to(
        get("https://api.internal.example/health")
        .returning_status(200)
        .containing("ready")
        .for_every_address()
        .with_options(allowed_destination_cidrs=["10.47.0.0/16"])
    )
report = result.to_dict()
```

The CIDR restriction validates the exact DNS answers subsequently used by this
HTTP check, before any connection is attempted. `expected_addresses=[...]`
requires exact set equality. A mismatch fails the positive check and sends no
connection traffic. Separate `resolve()` and connection calls still resolve
independently; use connection options when both expectations must bind together.

| Matcher | Observation |
| --- | --- |
| `connect_to(host).over_tcp(port)` | TCP handshake |
| `establish_tls(host)` | TLS with certificate and hostname verification |
| `get(url).returning_status(200).containing("ready")` | HTTP GET status/body; redirects are not followed |
| `resolve(host).to_addresses(*ips)` | Exact observed DNS address set |
| `resolve(host).within_cidrs(*cidrs)` | Every observed DNS address is in the allowed union |

Use `.with_options(...)` or factory keyword arguments for sampling, timeouts,
TLS names, destination address expectations and family selection. Protocol
options must apply to the selected check: HTTP status/body criteria require
`get()`, and TLS options require TLS or HTTPS. Inapplicable explicit options
raise during matcher construction, before any check runs. Protocol
matchers default to all resolved addresses. `.for_every_address()` makes that
intent visible. Negated observed matchers are rejected: a failed connection or
DNS observation is not proof of isolation. For healthy controls combined with
modeled denial, use [isolation_with_control](advanced-checks.md#isolation-with-a-healthy-positive-control).

### Derive settings from an actual workload

```python
with application.probe_session(
    allow_write=True,
    auto_create_execution_role=True,
) as probe:
    expect(probe).to(get("https://api.internal.example/health").returning_status(200))
```

For an ENI or instance selector, the library discovers and verifies the current
subnet, VPC, AZ, owner and exact group set. Multi-ENI instances require
`network_interface_id=...`. Group overrides and automatic groups are rejected
in this mode. Each terminal check rechecks the source; drift raises and triggers
normal cleanup. Evidence retains `source_workload` and the actual Lambda source.
The workload's ENI must also have assigned addresses for every requested family;
a dual-stack subnet alone does not make an IPv4-only workload representative of IPv6.
The probe still does not execute inside the instance or test its host firewall,
process or credentials. See [source context](advanced-checks.md#source-context).

### Dual-stack observations

```python
with application_subnet.probe_session(
    allow_write=True,
    execution_role_arn=role_arn,
    security_group_ids=application_groups,
    address_family="dual",
) as probe:
    expect(probe).to(
        get("https://api.internal.example/health", address_family="dual")
        .with_options(allowed_destination_cidrs=["10.47.0.0/16", "2001:db8:47::/48"])
        .for_every_address()
    )
```

`ipv4` is the default. `ipv6` and `dual` require an existing dual-stack subnet;
the function enables Lambda's outbound IPv6 option. No VPC, route or security
rule is created for IPv6. `dual` requires both families and reports each
separately. Even `address_mode="any"` requires success in each requested family.
A dual session can narrow a call to IPv4 or IPv6; a call cannot widen a deployment.
For literal IPv6 matcher targets, pass `address_family="ipv6"` explicitly.
The [dual-stack example](../examples/test_dual_stack.py) shows the opt-in inputs.

## Wait for a change

```python
expect(application_subnet).to(
    have_route_to(database_cidr).via(tgw_id).eventually(timeout=60, interval=2, max_attempts=20)
)
```

`.eventually()` delegates to `wait_for()`: it repeats only conclusive false
results and asserts after convergence or exhaustion. Errors propagate
immediately. Each retry makes a fresh check. This is a convergence test, not an
availability SLA. Sampling options on protocol matchers measure a bounded set
of connections; keep those separate from waiting for a configuration change.
With `every()`, each source gets its own convergence budget and runs in sequence.
That establishes individual convergence, not simultaneous health of every source.

## Require a stable sample

```python
expect(application_subnet).to(
    have_route_to(database_cidr).via(tgw_id).consistently(checks=5, interval=2)
)
```

`.consistently()` requires every fresh observation to pass and stops at the first
false result. Errors propagate immediately with partial `.stability_evidence`.
Passing and failing results retain the observations under `evidence["stability"]`;
their cleanup evidence remains live until the enclosing probe context closes.
Take `.to_dict()` snapshots after cleanup when you need a JSON report.

`checks` accepts 1–100 observations; `interval` must be positive and finite.
The direct helper `consistently(lambda: fresh_check(), checks=5, interval=2)`
returns an unasserted result. The sample does not prove uninterrupted service
between checks, and its sleeps do not bound an SDK call's duration.

Timing wrappers cannot stack. In particular, retrying failed observations inside
a stability sample could hide flapping behavior. If a requirement needs both,
make a convergence assertion and then a separate stability assertion. With
`every()` or `reach_each()`, each expanded case has its own sequential sample;
this does not establish simultaneous availability across the population.

The [coverage example](../examples/test_coverage.py),
[workload example](../examples/test_workload_probe.py), and
[protocol example](../examples/test_protocol_probe.py) use these forms. All AWS
examples use the [optional runner](../examples/README.md) and require `--run-aws`;
Lambda examples also require
`--allow-probe-writes`. MiniStack examples keep the same gates and semantics.

## Inspection requirements

```python
from aws_network_asserts import expect, have_appliance_mode, have_firewall_endpoints

expect(network.tgw(tgw_id)).to(have_appliance_mode(inspection_vpc_id))
expect(network.vpc(inspection_vpc_id)).to(
    have_firewall_endpoints(firewall_arn, subnets_by_az=firewall_subnets)
)
```

`have_bidirectional_routes(...)` checks explicit forward and return coverage on
VPC subnet/route-table or TGW route-table selectors. Declare the corresponding
next hops rather than inferring them from a successful attachment check.
See the [inspection guide](inspection-checks.md) for the argument forms and limits.

Protocol matchers also work on an explicitly opened [SSM session](ssm-probes.md).
A Lambda session can record a [cleanup manifest](recovery.md) without changing
its matcher syntax.
