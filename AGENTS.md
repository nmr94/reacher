# AGENTS.md

## Purpose and scope

This repository provides a small Python library for pytest-style AWS network
assertions. Its main entry points are `RuleBuilder` and `expect()` from
`aws_network_asserts`. It combines a central AWS Config aggregator, current EC2
topology reads, VPC Reachability Analyzer (RA), temporary Lambda probes and SSM
commands on existing instances across an AWS organization. Observed DNS, TCP,
TLS and HTTP checks require explicit write permission. Population checks,
coverage plans, convergence, stability samples and healthy controls build on
these checks; they do not supply a separate analysis engine.

These instructions apply throughout the repository. Follow the user's current
task and any more specific instructions in the area being changed. Preserve the
contracts below unless the requested change explicitly revises them; explain
any resulting compatibility change.

Keep the project simple: synchronous boto3 calls, small modules, ordinary
pytest assertions, and no required deployment or pytest plugin. Avoid introducing
frameworks, provider registries, background services, or dependencies for a
problem the existing code and standard library can solve clearly.

## Start here

- Read [README.md](README.md) for public usage and assertion semantics.
- Read `pyproject.toml` for supported Python, dependencies, and tool settings.
- When writing tests from English requirements, read the
  [expectation guide](docs/expectations.md), then follow the translation workflow
  below. Prefer RSpec-style matchers in new tests; direct predicates remain useful
  when a caller needs an unasserted `CheckResult`.
- Before protocol, sampling, coverage-matrix, healthy-control or TGW return-route
  changes, read [advanced checks](docs/advanced-checks.md). For Lambda lifecycle
  changes, also read [live probes](docs/live-probes.md).
- Before SSM, interrupted-run recovery or inspection-topology changes, read
  [SSM probes](docs/ssm-probes.md), [recovery](docs/recovery.md) or
  [inspection checks](docs/inspection-checks.md), respectively.
- When reviewing matchers, path evidence or cleanup, trace the terminal call
  through its actual evaluator and `finally` blocks. Check the native failure
  boundary as well as the successful response; use the review workflow below.
- Inspect the relevant implementation and tests before editing. Use `rg` for
  focused searches; do not repeatedly read the entire repository.
- For AWS operations or identity changes, also read `docs/permissions.md` and
  `docs/api-surface.md`. The usage guide documents profile conventions.
- The user deliberately removed the former CloudFormation labs, example
  `conftest.py` and profile configuration file. Preserve those deletions; do not
  restore them to repair documentation or test imports. Example execution uses
  the optional `contrib.pytest_examples` runner described below.
- Treat `docs/validation.md` as a historical report, not evidence that the
  current working tree has passed validation.

## Turn English requirements into reachability checks

Use this workflow when asked to write tests from a network requirement, review
what a test proves, or expand coverage. Generate ordinary Python/pytest code
using the public API. The English requirement is input to your reasoning; it is
not a request to add a parser, policy language or new test framework.

### 1. Write down the claim

Split a request into separately testable statements. For each statement, resolve
these fields before treating the test as complete:

| Field | Questions to answer |
| --- | --- |
| Source | Which account, region and ENI/instance/subnet? Which VPC, AZs and security groups matter? |
| Observation source | Modeled packet, separate Lambda interface, or the existing instance through SSM? Which host user or application environment matters? |
| Destination | Which account and region? Is it a resource, one IP, a CIDR, a DNS name or a URL? |
| Traffic | TCP or UDP, which destination ports, and any required source IP/port? For observed checks: TCP, TLS, HTTP or DNS? |
| Address family | IPv4, IPv6, or both? RA remains IPv4-only; dual observed checks require both families. |
| Direction | Who initiates the connection? Is the requirement also for a separately initiated reverse connection? |
| Expected result | Recorded inventory, an active relationship, route coverage, an allowed/blocked modeled packet, or an observed protocol result? |
| Coverage | One example, any endpoint, every known endpoint, every DNS answer, specified AZs, or a finite list of source/destination pairs? |
| Success criteria | Handshake, verified certificate/name, HTTP status/body, exact DNS answers, latency or a sample success threshold? |
| Timing | Current state, convergence after a change, or consecutive passing observations? What analysis/sample budgets apply? |
| Writes | Are Lambda deployments, SSM commands or recovery deletions requested? Are role/group creation and the exact execution scope authorized? |

For example, “the application must reach the database” leaves its source,
account, port and evidence level unresolved. “Every application ENI in account
111111111111, eu-west-2, must have a modeled TCP path to the database ENI in
account 222222222222 on port 5432” is ready to translate once the ENIs are known.

Resolve values from the user's context, repository fixtures, IaC and documented
stack outputs first. Ask only for missing facts or choices that change the
claim. State reasonable assumptions, such as using RA for a network-path check,
and make them visible in the test description. Never guess account ownership,
resource IDs, credentials, required coverage or permission to run AWS writes.

Finish this step with a short requirement-to-check list. Each requirement needs
a proposed test, its evidence level, and any unresolved input or unsupported
part. A test's name and explanation must describe what it can actually prove.

### 2. Choose the evidence that answers the question

| English wording | API to start with | What a passing check means |
| --- | --- | --- |
| “Config records this resource/tag” | Typed selector `.is_recorded()`, `.has_config_tag()`; `.config_snapshot()` for inspection | The selected aggregator has the expected record/data |
| “Find the recorded ENIs” | Scoped `.resource_ids("AWS::EC2::NetworkInterface")` | These IDs were discovered in Config; completeness still needs an expected population |
| “Discovery must find exactly these workloads” | `expect(discovered).to(contain_exactly_resources(*expected))` | The scoped identity sets match, with no missing, unexpected or duplicate discoveries |
| “Every application must reach every database on these ports” | `expect(every(apps)).to(reach_each(databases).over_tcp(5432, 6432))` | Every declared source/destination/port has its own conclusive modeled pass |
| “Preview the cases and limit RA work” | `expect(subject).plan(matcher)`; `.to(matcher, max_ra_analyses=limit)` | A local plan describes the analysis upper bound; the cap rejects excess work before execution |
| “This ENI is in the subnet/VPC” | `.eni(id).in_subnet(id)` / `.in_vpc(id)` | Current membership matches |
| “The subnet routes the whole CIDR through the TGW/peer” | `.subnet(id).has_route_to(cidr, via=id)` | Effective VPC routes cover every address using that target |
| “These VPCs are peered” | `.vpc(id).has_peering_with(other_vpc)` | The peering relationship is active |
| “The VPC attaches to this TGW” | `.tgw(id).has_attachment(vpc_id)` | An available matching attachment exists |
| “The attachment uses this TGW table” | `.tgw(id).route_table(id).has_association(attachment_id)` | The actual association matches |
| “The VPC propagates into this TGW table” | `.tgw(id).propagates(table_id).from_vpc(vpc_id)` | The VPC's route propagation into that table is enabled |
| “The TGW has forward and return routes” | TGW table `.has_bidirectional_routes(...)` | The two selected tables cover the supplied forward/return CIDRs |
| “AWS should allow/block this packet” | Endpoint `.can_reach(...)` / `.cannot_reach(...)` | RA gives a conclusive modeled answer for the specified packet |
| “A TCP connection actually opens” | Subnet `.probe_tcp(...)` or an explicit session `.tcp(...)` | The selected Lambda or SSM source completed the handshake |
| “TLS works with a valid certificate” | `.probe_tls(...)` or session `.tls(...)` | TLS and certificate/hostname verification passed |
| “The service's health endpoint responds correctly” | `.probe_http(...)` or session `.http(...)` | The requested URL met the status/body criteria |
| “DNS answers are exactly these IPs / stay inside these CIDRs” | `expect(probe).to(resolve(host).to_addresses(...))` / `.within_cidrs(...)` | Observed answers in the requested families meet the expectations |
| “The same addresses used for this connection must stay private” | Connection matcher `.with_options(allowed_destination_cidrs=[...])` | The exact resolved set used by that connection meets the restriction |
| “The modeled path must use this link” | `reach(target).through(id).avoiding(other_id)` | A complete reported forward path matches the constraints |
| “The configuration must pass several fresh observations” | `matcher.consistently(checks=5, interval=2)` | Every observation in the bounded stability sample passed |
| “Run from this instance's own host network” | `instance.ssm_probe_session(allow_write=True)` with protocol matchers | The SSM execution user's host network met the protocol criteria |
| “Recover an interrupted Lambda probe” | `recover_probes(scoped_builder, manifest)`; explicit `allow_write=True` for deletion | The dry-run report or confirmed cleanup concerns only resources owned by that recorded run |
| “The inspection VPC has appliance mode and ready endpoints” | `have_appliance_mode(vpc_id)` / `have_firewall_endpoints(arn, subnets_by_az=...)` | Current attachment settings and the exact ready firewall AZ/subnet layout match |
| “Both selected ingress tables use this inspection endpoint” | `have_bidirectional_routes(..., via=..., return_via=...)` | Both explicit effective route selections cover their supplied ranges |

When “can reach” means a network configuration path, start with RA. When it
means a working listener, certificate or application response, choose the
corresponding observed check and identify its Lambda or SSM source. Use topology
checks alongside these when the requirement names a route or relationship.

Keep distinct claims distinct. A Config record, peering connection, propagation
or active route does not by itself prove packet delivery. RA does not prove
listener health. TCP success does not prove TLS, HTTP or authentication. The
library has no application-authentication check or generic ICMP probe. SSM runs
inside the instance's host network under the agent execution user; it does not
reproduce an application's user, credentials, container namespace, proxy or
process environment. Describe those remaining gaps when relevant.

### 3. Resolve accounts, resources and addresses

Create independent views for each owner and region. Preserve the central
Config/RA identities and select the TGW owner for TGW topology checks. A shared
VPC's ENI owners may differ from its subnet owner.

```python
source = org.in_account("111111111111").in_region("eu-west-2")
destination = org.in_account("222222222222").in_region("eu-west-2")
```

Use typed selectors for known resources. For cross-account endpoints, pass the
destination's scoped selector or a correctly scoped explicit ARN. A bare ENI or
instance ID string inherits the source account. A bare IPv4 address has no
inferred resource owner. Use `.resource()` for supported generic RA endpoints,
but remember that it does not infer a Config resource type.

RA accepts one IPv4 address or `/32`, or a supported resource endpoint. Use
`destination_ip` to constrain an ENI/resource destination to a particular packet
address. Specify `source_ip`/`source_port` only when those packet fields are part
of the requirement. A subnet, VPC, hostname, URL, non-/32 CIDR or IPv6 address is
not a substitute for an RA packet endpoint. RA supports TCP/UDP; set the actual
protocol and port rather than accepting the TCP/443 defaults accidentally.

Use one region per RA analysis. Regional routes and separate regional analyses
can contribute evidence, but they do not prove an entire inter-region path.
Observed probes can contact a reachable remote-region target, with the usual
limitations of their own source context.

Human-friendly names need a documented resolution step. Use the caller's
fixtures, validated IaC outputs or scoped discovery. Read live AWS inventory
only when live execution is in scope. A discovered empty collection is not
coverage: verify expected IDs/counts or fail setup before evaluating predicates.

### 4. Expand words such as “all”, “both” and “only”

Translate quantifiers into a finite, reviewable set of cases before running them:

- “Every source subnet/AZ” needs each named subnet/AZ. One Lambda deployment is
  attached to one source subnet; create a separate context for each required one.
- “Every instance can initiate to every other instance” needs all directed
  non-self pairs. Four instances need 12 cases. A TCP response on an established
  connection is different from a separately initiated reverse connection.
- “Both directions route” needs forward and return VPC/TGW tables and CIDRs.
  A source's `can_reach()` result does not replace a requested reverse test;
  retain RA's documented limits for TCP return-path modeling through TGWs.
- “Every endpoint in this subnet” needs an explicit endpoint population or live
  `.enis()` enumeration with a nonempty/expected-population assertion. That
  covers the observed ENIs, not every possible future workload or free IP.
  Use `contain_exactly_resources(*expected_selectors)` when the population is
  known. Expected declarations must be nonempty, unique and scoped. Empty,
  duplicate, missing or unexpected actual discoveries fail the positive
  comparison; unknown or malformed scope raises.
- “Every DNS answer works” needs `address_mode="all"`. Session TCP/TLS/HTTP
  defaults to `"all"`; one-shot `probe_tcp()` defaults to `"first"`. `"any"`
  proves only that some address met its threshold within each requested family.
  Select `address_family="dual"` to require both IPv4 and IPv6; default IPv4
  coverage does not include AAAA answers. At most 32 total distinct addresses
  are supported; excess answers raise rather than being truncated.
- “The entire CIDR routes through X” needs `.has_route_to(cidr, via=X)` on the
  appropriate VPC/TGW table. A supernet can cover it, while more-specific
  blackholes or wrong next hops fail. Do not sample one IP as proof of the CIDR.
- “These ports work” needs separate checks for each required port/protocol.
  `reach_each(destinations).over_tcp(443, 8443)` expands an explicit finite port
  list for every source/destination pair. Reject empty or duplicate lists.
  `port=None` is unconstrained RA analysis, not proof that every port works.
- “Only the application can reach the database” needs allowed sources and a
  defined set of denied sources on the same destination/port. One denial is
  evidence about that source, not universal isolation.
- “No internet access” needs a defined scope: selected modeled public paths,
  absence of intended public routes, or a broader routing/security review.
  A missing route or failed connection to one public IP does not prove all
  internet destinations are blocked. A failed Lambda or SSM probe is never isolation.

`reach_each()` uses distinct scoped endpoint selectors and includes the full
Cartesian product. Overlapping source/destination lists include self-pairs;
declare individual directed cases for a non-self mesh. Negation is rejected:
“not all reachable” cannot stand in for “all denied.” Declare required denials
individually with `not_to(reach(...))`.

Before a large run, inspect `expect(every(sources)).plan(matcher)`. Its
`case_count`, `max_checks` and `max_ra_analyses` include finite ports and the
maximum convergence or stability count for every case. Planning performs no
discovery or SDK calls. Apply `max_ra_analyses=N` to `.to()` / `.not_to()` to
reject the entire assertion before evaluation if its upper bound exceeds the
cap. This is an analysis-count budget, not a total AWS request or monetary cap.

For internet egress, distinguish a route from a working external service.
`has_route_to("198.51.100.1/32", via=nat_id)` checks that sample's effective route.
`has_route_to("0.0.0.0/0", via=nat_id)` instead requires every IPv4 address to use
NAT, including addresses covered by local/peer routes; it is not a test for the
presence of a default route. RA ending at an IGW models that boundary, not a
remote server's health. Use an authorized real HTTPS target for observed egress.
A VPC Lambda gets no public IP, so a public subnet alone does not give it internet
access; use the existing NAT/egress path. Keep documentation addresses in modeled
checks only, never as supposed real public HTTP servers.

Use pytest parametrization for a small fixed set. For a declared multi-source,
AZ or protocol plan, use `CoverageCase` and `CoverageMatrix`; they check labels
against result evidence and raise on missing cases. A matrix does not discover
what should have been declared. DNS cases use `port=None`; RA destinations must
match the qualified destination in evidence and select a single port. See
[coverage examples](docs/advanced-checks.md#declare-the-coverage-you-require).

Finish this step with every required case accounted for, including both
positive and negative cases where “only” requires them. If a population is
unknown, report the coverage gap rather than presenting a sample as complete.

### 5. Write small tests with useful failures

The snippets below assume an `org` fixture configured as described in the
[usage guide](docs/usage.md#a-pytest-fixture). IDs and fixture inputs are examples;
resolve them for the user's environment before presenting code as runnable.
Import the matchers you use from `aws_network_asserts`. Use public selectors
with `expect(subject).to(matcher)` or `.not_to(matcher)`; they assert and return
a `CheckResult`. Matchers and expectations are immutable descriptions until the
terminal assertion. A bare selector or matcher is not an assertion. Use the
direct predicates when composing an unasserted result for an existing helper.

**“The application ENI can reach the database ENI on PostgreSQL.”**

```python
def test_application_has_a_modeled_database_path(org):
    app = org.in_account("111111111111").in_region("eu-west-2")
    database = org.in_account("222222222222").in_region("eu-west-2")
    expect(app.eni("eni-0123456789abcdef0").named("application")).to(
        reach(database.eni("eni-0123456789abcdef1").named("database"))
        .over_tcp(5432)
        .at_address("10.47.1.10")
    )
```

This tests the specified modeled packet. It makes no database login or listener
health claim. If two ENIs or several database addresses are required, declare
separate cases rather than choosing whichever succeeds.

**“Every currently enumerated ENI in this subnet can reach the service.”**

```python
def test_subnet_enis_have_modeled_service_paths(org):
    source = org.in_account("111111111111").in_region("eu-west-2")
    interfaces = source.subnet("subnet-0123456789abcdef0").enis()
    assert interfaces, "Expected at least one source ENI; no coverage was evaluated"
    expect(every(interfaces)).to(reach("10.47.1.10").over_tcp(443))
```

Use an expected ID set/count as well when the requirement names a fixed
population. Enumeration preserves each ENI's actual account in shared subnets;
keep those selectors rather than rebuilding them under the subnet owner.

**“Discovery must find these two applications, and both must reach every database.”**

```python
def test_declared_application_database_paths(application_subnet, app_a, app_b, databases):
    discovered = application_subnet.enis()
    expect(discovered).to(contain_exactly_resources(app_a, app_b))
    requirement = reach_each(databases).over_tcp(5432, 6432)
    expectation = expect(every(discovered))
    plan = expectation.plan(requirement)
    assert plan["case_count"] == 2 * len(databases) * 2
    expectation.to(requirement, max_ra_analyses=16)
```

The expected selectors and database list need explicit accounts/regions.
Changing their names does not add coverage. Choose the cap from the actual
requirement and reviewed plan; never raise it automatically to make a test run.
Population comparison snapshots the supplied sequence and does not repeat
discovery. Native errors retain per-case evidence and stop evaluation.

**“The entire remote VPC CIDR has forward and return routes over the peer.”**

```python
def test_peering_routes_cover_both_vpc_ranges(org, peer_id):
    side_a = org.in_account("111111111111").in_region("eu-west-2")
    side_b = org.in_account("222222222222").in_region("eu-west-2")
    expect(side_a.subnet("subnet-0123456789abcdef0")).to(have_route_to("10.50.0.0/16").via(peer_id))
    expect(side_b.subnet("subnet-0123456789abcdef1")).to(have_route_to("10.40.0.0/16").via(peer_id))
```

This checks two effective subnet route tables. Repeat for other required
subnets/tables. Add `has_peering_with()` for active peering and RA/probes for
packet or service requirements. The route library uses standard-library IP
intervals; no extra routing dependency is needed for supernet coverage.

**“Traffic between the VPCs uses the intended TGW tables in both directions.”**

```python
def test_tgw_forward_and_return_routes(
    org, tgw_id, table_a_id, table_b_id, attachment_a_id, attachment_b_id
):
    hub = org.in_account("222222222222").in_region("eu-west-2").tgw(tgw_id)
    ingress_a = hub.route_table(table_a_id)
    ingress_b = hub.route_table(table_b_id)
    expect(ingress_a).to(have_association(attachment_a_id))
    expect(ingress_b).to(have_association(attachment_b_id))
    routes = ingress_a.has_bidirectional_routes(
        "10.50.0.0/16",
        source="10.40.0.0/16",
        return_table=ingress_b,
        via=attachment_b_id,
        return_via=attachment_a_id,
    )
    assert routes, routes.message
```

The forward table belongs to the source attachment's ingress; the return table
belongs to the other attachment's ingress. Verify `has_attachment()` and
`propagates(...).from_vpc(...)` when those relationships are also required.
Propagation is into a TGW route table, not into a VPC `rtb-...` table. Add the
VPC subnet route checks separately, and use RA/probes for delivery evidence.

**“Every resolved service address returns a healthy HTTPS response.”**

```python
def test_service_is_healthy_from_the_workload_subnet(org, role_arn):
    source = org.in_account("111111111111").in_region("eu-west-2")
    application = source.eni("eni-0123456789abcdef0").named("application")
    with application.probe_session(
        allow_write=True,
        execution_role_arn=role_arn,
        expected_source_cidrs=["10.40.1.0/24"],
    ) as probe:
        result = expect(probe).to(
            get("https://api.internal.example/health")
            .returning_status(200)
            .containing("ready")
            .for_every_address()
            .with_options(allowed_destination_cidrs=["10.47.0.0/16"])
        )
    report = result.to_dict()
    assert report["evidence"]["deployment"]["cleanup"] == "deleted"
```

This sends real HTTPS requests with certificate/name verification and does not
follow redirects. Choose an authorized, harmless GET/HEAD endpoint. The source
is a Lambda using the verified workload subnet/groups, which are rechecked
before each observation. It does not recreate the instance's ENI, process,
authentication or host firewall. A derived source must have assigned addresses
in every requested family; a dual-stack subnet alone is insufficient. Expected
source CIDRs refer to the local address before downstream NAT. For an IP target with a
certificate for a DNS name, use `probe.tls(ip, server_hostname=name)` when the
requirement is TLS; HTTP normally takes its host and TLS name from the URL.

Use `resolve(host).to_addresses(...)` for exact address set equality, or
`resolve(host).within_cidrs(...)` to require every answer in the allowed union.
You can combine both and select the family explicitly. Separate DNS and later
connection calls still resolve separately. For a single connection's own DNS
set, use `expected_addresses` / `allowed_destination_cidrs` on its protocol
matcher. Validate the exact set before connection invocations; a valid mismatch
fails without packets, while malformed/missing-family DNS raises.

**“A synthetic probe should create and remove its own role and security group.”**

```python
def test_synthetic_tcp_connection(org):
    source = org.in_account("111111111111").in_region("eu-west-2")
    with source.subnet("subnet-0123456789abcdef0").probe_session(
        allow_write=True,
        auto_create_execution_role=True,
        auto_create_security_group=True,
    ) as probe:
        expect(probe).to(connect_to("10.47.1.10").over_tcp(443))
```

Omit the existing role/group arguments when requesting their automatic
counterparts. Each option is independent. The automatic group has no ingress
and default outbound access; it may differ from a workload group. Keep the
source synthetic in this mode. Check each resource's cleanup evidence and
warnings; the function's deletion alone does not confirm role/group deletion.
See [probe cleanup](docs/live-probes.md#lifecycle-and-cleanup).

**“The restricted source is isolated while the destination is healthy.”**

Use endpoint `.cannot_reach(ip, protocol="tcp", port=port)` for a conclusive
modeled denial. For endpoint health as an additional prerequisite, use
`isolation_with_control()` with a successful observed TCP/TLS/HTTP control from
an allowed source. Both must concern the same explicit IPv4 address and TCP
port; a healthy different DNS answer is insufficient. A failed or mismatched
control raises. See the
[worked isolation example](docs/advanced-checks.md#isolation-with-a-healthy-positive-control).

A refused connection, timeout, DNS error, AWS error or unsupported RA result
cannot satisfy isolation. Keep unknowns as errors. This helper still does not
prove the denied source shares the control's return path or establish every
possible reason a packet might be dropped.

**“The change should converge, then pass a bounded reliability sample.”**

Use `matcher.eventually(timeout=..., interval=..., max_attempts=...)` inside
an expectation for convergence, or the direct `wait_for(lambda: fresh_check(),
...)` helper when composing unasserted predicates. The matcher retries conclusive
false results and asserts after convergence or exhaustion. The direct helper
returns the last result; assert it. Both propagate exceptions and do not
retry permission or unknown-state errors into a pass. For connection samples,
set `attempts`, `successes_required`, `interval` and optionally `max_latency_ms`
on the protocol check. With `address_mode="all"`, every address must meet the
threshold. A successful retry is evidence of convergence, not an availability
SLA; bounded samples do not prove sustained reliability. Consult
[sampling and convergence](docs/advanced-checks.md#connection-sampling-and-convergence)
for limits and timing semantics.

For consecutive fresh checks, use
`matcher.consistently(checks=5, interval=2)`, or the direct
`consistently(lambda: fresh_check(), checks=5, interval=2)` helper. Every
observation must pass; the first false result fails the sample and errors stop
it immediately. `eventually()` instead accepts the first conclusive success.
Timing wrappers cannot stack, because retrying failures inside a stability
sample could hide flapping. When both are required, make a convergence assertion
followed by a separate stability assertion. Samples are sequential per expanded
case and prove neither uninterrupted service nor simultaneous fleet health.

**“Check the service from the application's existing EC2 host network.”**

```python
def test_service_from_existing_host(application_instance):
    with application_instance.ssm_probe_session(allow_write=True) as probe:
        result = expect(probe).to(
            get("https://api.internal.example/health")
            .returning_status(200)
            .with_options(allowed_destination_cidrs=["10.47.0.0/16"])
        )
    assert result.evidence["transport"] == "ssm"
```

The instance must already be a running online Linux SSM node with Python 3.10+
available to the agent. No enrollment, package install or networking changes
are implied. This sends a fixed command under the SSM execution user, usually
root; retain the effective UID and selected source interface evidence. It does
not run as the application's user or inside its container. The library accepts
no arbitrary shell command, alternate document or custom interpreter here.
Read the [SSM guide](docs/ssm-probes.md) for cancellation and retained command history.

**“Verify inspection topology and recover a probe after an interrupted run.”**

Keep these separate from packet-delivery assertions. Use
`have_appliance_mode(vpc_id)` on the TGW owner's selector, and
`have_firewall_endpoints(firewall_arn, subnets_by_az=...)` on the inspection VPC
owner's selector. Use explicit endpoint IDs from the intended AZ for forward
and return route requirements. The checks establish settings, ready placement
and route selection; they do not inspect firewall rules or prove per-flow
symmetry. Add supported RA path constraints or authorized observations for
delivery. See [inspection checks](docs/inspection-checks.md).

For an interruptible Lambda run, pass a fresh `cleanup_manifest` path to its
deployment and retain the file privately. `recover_probes(scoped_builder, path)`
inspects without deleting; `allow_write=True` explicitly permits recovery
deletions. A manifest is creation evidence, not permission to adopt unknown
resources. Recovery keeps unconfirmed identities, dependencies and reused
resources for review. Follow [recovery](docs/recovery.md), including its
cross-region role-consumer checks.

### 6. Keep writes, errors and cleanup visible

Writing tests and running tests are separate actions. A request to author AWS
checks does not itself authorize deployment or live AWS execution. RA creates
chargeable analyses even though it sends no packets; describe those costs when
planning an authorized run. Preserve the examples' `--run-aws` gate.

When the requirement calls for observed checks, author them as opt-in tests
with literal `allow_write=True` on each deployment call or session. Preserve
`--allow-probe-writes` in repository examples, check it before deployment, and
use the separate `--allow-ssm-commands` gate for SSM. Keep the literal permission
inside the test. Recovery also defaults to dry run and needs its own explicit
write option. There is no global library write switch. Never turn a failed RA
analysis into an automatic Lambda deployment or SSM command.
Automatic role/group creation additionally requires its respective explicit
option and caller permissions. Network, Config and Organizations setup are
separate operations.

Use context managers for batches so assertions and errors trigger cleanup.
Inspect evidence after the block for final cleanup state. `CheckResult.to_dict()`
and matrix reports are snapshots; an earlier snapshot does not update itself.
Report `CleanupWarning` and retained names/IDs so unfinished cleanup is visible.
Do not suppress warnings or remove AWS-managed/shared ENIs to make a test pass.
SSM command history and agent artifacts remain under existing retention;
requesting cancellation does not prove that a remote process stopped. Keep
Lambda cleanup, SSM command completion/cancellation and recovery actions distinct.

Let AWS, unsupported-check and missing-prerequisite errors propagate. Return a
failing assertion for an evaluated mismatch. For a negative RA requirement use
`cannot_reach()`, rather than negating `can_reach()` or a probe result. Keep test
failures and setup errors visible in required suites; use skips for deliberately
unselected opt-in examples, not missing required coverage or denied API access.

### 7. Check the translation and report its limits

Before presenting generated tests, check each requirement against the code:

- Its source/destination accounts, regions, resources and packet/protocol fields
  match; any named AZ, group or address expectation is represented.
- Every declared source, target, direction, port and DNS coverage mode has a case;
  empty populations and missing cases fail instead of passing vacuously.
- The population comparison uses actual scoped identities; Cartesian/self-pair
  behavior is explicit, and the reviewed plan/cap includes timing expansions.
- The assertion's evidence supports its wording. Topology, modeled delivery,
  observed service health and broad isolation are separate claims.
- Every probe has a per-deployment or per-session write gate and a cleanup path.
  Execution authorization and IAM prerequisites are stated separately from code generation.
- Required false results fail. Unknown, malformed, inaccessible and unsupported
  states remain errors. A blocked positive path is not silently reclassified.

Check imports, actual signatures and supported options against the current
implementation. For a library behavior change, follow the focused regression
rules below. For generated user tests, validate their syntax and assumptions
without contacting AWS unless an AWS run is authorized. Do not write unit tests
that fabricate a successful RA response and present them as live network proof.

Deliver a short mapping from each English requirement to its tests, expected
result and evidence type. State assumptions, untested scope, write/cost/cleanup
requirements and the checks actually executed. If part of a request needs an
unsupported protocol, application/container-specific execution or unbounded
coverage, name that gap and complete the parts this library can support.

### Use the examples as assertion patterns

The files in `examples/` show network, organization, protocol and workload
assertions against existing resources. They do not deploy an environment or
provide the removed CloudFormation stacks. Bind their resource inputs to the
user's fixtures or outputs and use the optional runner below when executing
them. Keep offline SDK contract tests separate from evidence of a live path.

## Repository map

| Path | Responsibility |
| --- | --- |
| `src/aws_network_asserts/builder.py` | Public selectors, account/region views, topology assertions, Config evidence |
| `src/aws_network_asserts/accounts.py` | Lazy member profiles/sessions and STS account verification |
| `src/aws_network_asserts/clients.py` | Boto3 clients, endpoint selection, transport settings, client reuse |
| `src/aws_network_asserts/inventory.py` | Config snapshots and account/region-scoped discovery |
| `src/aws_network_asserts/reachability.py`, `path_evidence.py` | RA lifecycle, forward-path constraints and reported blocker explanations |
| `src/aws_network_asserts/expectations.py` | Immutable matchers, exact populations, Cartesian cases, read-only plans and analysis caps |
| `src/aws_network_asserts/routes.py` | Effective VPC route selection and complete CIDR coverage |
| `src/aws_network_asserts/probe.py`, `_probe_handler.py`, `probe_role.py`, `probe_security_group.py` | Opt-in Lambda, TCP observations, and optional temporary role/group lifecycles |
| `src/aws_network_asserts/probe_session.py`, `_application_handler.py` | Explicit batches, DNS coverage, sampling and protocol observations |
| `src/aws_network_asserts/ssm_probe.py` | Fixed protocol commands on existing instances, source verification, bounded polling and cancellation |
| `src/aws_network_asserts/_recovery.py`, `recovery.py` | Durable Lambda manifests, recovery identity/dependency checks and the recovery CLI |
| `src/aws_network_asserts/inspection.py` | Appliance mode, exact firewall endpoint layout and paired VPC route checks |
| `src/aws_network_asserts/tgw_routes.py` | Effective TGW route selection and complete CIDR coverage |
| `src/aws_network_asserts/checks.py` | Declared coverage, convergence, stability samples and healthy isolation controls |
| `src/aws_network_asserts/result.py` | Truth-testable `CheckResult` and diagnostics |
| `src/aws_network_asserts/errors.py` | Library evaluation errors and cleanup warnings |
| `src/aws_network_asserts/__init__.py` | Public exports |
| `tests/` | Offline tests using synthetic data and botocore models |
| `examples/` | Opt-in assertion examples using existing resources |
| `contrib/ministack_boto3.py` | Standalone MiniStack session/account shim used by examples with `--ministack` |
| `contrib/pytest_examples.py` | Optional example fixtures and opt-in flags, loaded explicitly with `-p` |
| `docs/`, `iam/` | Usage/API contracts, permissions, historical validation and policy templates |

## Local development

Use an existing suitable virtual environment, or create one from the repository
root. The package supports Python 3.10+; keep syntax and standard-library usage
compatible with that minimum.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Run tools through the selected interpreter:

```bash
# Focused checks during development; choose the relevant files or test names.
python -m pytest tests/test_accounts.py tests/test_organization.py -q
python -m pytest tests/test_reachability.py -k cleanup -q

# Lint and formatting. Scope to changed files during iteration when useful.
python -m ruff check .
python -m ruff format --check .

# Broader checks when warranted by the change.
python -m pytest -q
python -m pytest -p contrib.pytest_examples examples/ -q
python -m build
```

`pytest` defaults to `tests/`. Examples must remain skipped without `--run-aws`,
including when the optional runner is absent. To execute them, load the runner
explicitly: `python -m pytest -p contrib.pytest_examples examples/ --run-aws`.
Lambda examples additionally require `--allow-probe-writes`; SSM execution needs
its separate `--allow-ssm-commands` gate and literal `allow_write=True` in the
session call. This contrib runner is optional and is not a library requirement.
`--ministack` uses the contrib shim's dummy account sessions and endpoint; it
still needs `--run-aws` and the appropriate write gate.
Member sessions cover `NETWORK_ACCOUNT_ID` (or its legacy alias), `ACCOUNT_A`
and `ACCOUNT_B`; central credentials come from `MINISTACK_ACCOUNT_ID`. Follow
the [MiniStack setup](docs/usage.md#ministack-examples) for defaults and Config.
The test/dev extras include PyYAML for offline template checks; boto3 remains
the only runtime dependency. Ruff's settings in
`pyproject.toml` include 100-column lines.

If imports unexpectedly reflect old code, check the interpreter and imported
package path. An installed wheel can hide source changes when the checkout is
not installed editable. Fix the environment rather than changing the code to
match a stale installation.

## Contracts to preserve

### Accounts, credentials, and regions

Credential contexts stay separate:

| Work | Required context |
| --- | --- |
| Aggregate Config reads | `config_clients`, using the central session or separate Config reader, in fixed `config_region` |
| Entire RA lifecycle | `analysis_ec2`, using the central management/delegated-admin session in the resource region |
| Live EC2 topology | `ec2`, using credentials verified for the selected resource account and region |
| Entire opt-in Lambda lifecycle | `_live_client("lambda")`, verified for the selected account and region |
| Optional temporary IAM role | `_live_client("iam")`, using the same verified account as Lambda; IAM is account/partition scoped |
| Optional temporary security group and ENI cleanup reads | Verified live EC2 credentials in the selected account and resource region |
| Entire opt-in SSM session | Verified selected-account EC2/SSM clients in the instance's region |
| Manifest recovery | Verified recorded-account clients in the recorded region, plus complete enabled-region Lambda inventory before role deletion |

- `.in_account()` selects resource ownership and the Config source account; it
  must not switch central Config or RA credentials.
- `.in_region()` selects the network region; it must not move the aggregator.
  Both methods return independent views without changing existing selectors.
- Account IDs are strings containing exactly 12 ASCII digits. Reuse
  `validate_account_id()` rather than adding different validation rules.
- Preserve lazy member profile loading. Config-only and central RA operations
  must work without loading member profiles.
- Before creating a scoped live service client, verify its account through STS
  `GetCallerIdentity`. An unmapped account may use central credentials only if
  the verified account matches. Errors or mismatches never authorize a fallback.
- Let boto3 profiles handle role assumption and credential refresh. Preserve
  the underlying sessions; do not copy temporary keys into static sessions or
  add a separate credential-refresh implementation.
- Preserve cache boundaries and locking: clients belong to a credential
  context, service and region; successful identity checks belong to a factory
  and region. Do not cache Config snapshots or assertion results.

### Resource ownership and shared networks

Verified caller identity does not establish ownership of every visible resource.
For scoped checks, preserve `OwnerId` validation on ENIs, route tables and
fallback subnet lookups, and owner matching for VPC peering.

Subnet enumeration must retain each ENI's actual owner, including participant
accounts in shared VPCs. TGW checks use the TGW owner's account. An attachment's
`TransitGatewayOwnerId` and VPC `ResourceOwnerId` can legitimately differ; do not
compare the latter with the selected TGW account. Missing or contradictory
ownership metadata must not produce a passing scoped assertion.

### Config inventory

- Public builders require an aggregator name and region whenever Config is
  enabled. Internal regional inventory support is not a silent builder fallback.
- Aggregate requests include the selected account and resource region. Never
  infer resource ownership from the aggregator's credentials.
- Preserve modes: `required` is the default; `prefer` tolerates genuinely
  missing/deleted/unrecorded inventory; `off` disables automatic Config use.
- Permission, transport and malformed-response errors must propagate in both
  enabled modes. Missing inventory is not the same as an inaccessible API.
- Typed network checks attach source/subject Config evidence. Generic
  `resource()` selectors do not infer a Config type. Explicit inventory methods
  remain distinct from live network checks.
- Keep Config's native JSON keys and capture metadata. Do not interpret an old
  capture time alone as proof of stale state, or use snapshots in place of live
  routing, membership, peering or propagation responses.

### Assertion results and network semantics

- Terminal predicates return `CheckResult` with useful messages and evidence.
  Bare selectors and incomplete propagation builders must raise on truth tests.
- Return a failing result only for an evaluated, unsatisfied predicate. Unknown
  state, unsupported scope, missing prerequisites and AWS failures raise.
  Never convert broad exceptions into `False` or a successful isolation check.
- `cannot_reach()` reverses only a conclusive RA answer. Failed/timed-out
  analyses and unsupported or missing-information codes remain errors.
  This includes unknown or omitted inspection in forward/return
  `AdditionalDetails`. Preserve documented informational limits without
  converting an unmodeled portion into proof of isolation.
- Account-scoped endpoint IDs become correctly partitioned ARNs. A bare
  destination ID string uses the source account; selectors carry their own
  account/region; explicit ARNs must agree with applicable scope. Preserve
  rejection of ambiguous unscoped destination selectors in organization mode.
- One RA analysis stays in one region. Do not present successful regional
  checks or topology assertions as proof of an entire cross-region path.
- RA packet checks accept one IPv4 address or `/32`, not an entire CIDR or IPv6.
  The default is TCP port 443. An unconstrained port does not prove all ports.
- Subnets are not RA endpoints; use explicit or enumerated ENIs. Empty
  enumeration must not be presented as successful coverage of a segment.
- Route assertions evaluate the whole requested IPv4/IPv6 range, honoring
  longest-prefix choice, blackholes, prefix lists and route precedence. Preserve
  subnet explicit-association/main-table behavior. Use interval boundaries;
  do not enumerate every IP in a CIDR. Ambiguous results raise.
- Effective subnet table selection requires complete current native association
  evidence: a unique matching association ID, echoed table ID, boolean `Main`
  and known `AssociationState`, with the selected association `associated`.
  Contradictory explicit data must raise, never trigger a main-table fallback.
  Fallback reads must paginate and verify the live subnet's ID, VPC, availability
  and owner, then the table's VPC and active main association. Keep owner checks
  before association errors. Explicit route-table reads must echo the requested ID.
- Route targets and supplied `via` values must be usable ID/ARN text. Reject
  whitespace, control characters and malformed attachment IDs as errors; a
  malformed expectation must not become a passing negated route check.
  Require native EC2 target IDs for `via`; an EC2 ARN cannot match an ID-only
  response without evidence of target ownership. Preserve exact matching for
  targets reported natively as ARNs, such as Cloud WAN core networks.
- Active route selection does not establish packet reachability. TGW
  propagation does not establish attachment association or end-to-end routing.
  `.to_vpc()` remains an alias for `.from_vpc()`: VPC routes propagate into the
  `tgw-rtb-...` table. An `rtb-...` VPC table is a different resource.

### RA lifecycle and endpoint support

- Keep request construction, polling and cleanup in `reachability.py`. Each
  terminal reachability call creates its own analysis; do not reuse stale paths
  or cache outcomes as an optimization.
- Preserve documented request shapes, including `FilterAtSource` and omission
  of `Destination` for IP-only targets. Consume every page of paginated APIs.
  Keep unique request tokens for independent lifecycle operations.
  Validate echoed analysis filters, additional accounts and partition against
  the requested scope before using an answer.
- Create, start, poll and delete with the same central analysis credentials.
  Preserve `keep_analysis`, bounded polling and diagnostic path/analysis IDs.
- Cleanup is best effort after success or failure. `CleanupWarning` must not
  replace the original error. Delete the analysis before its path, and do not
  delete objects the check did not create. A polling timeout does not cancel AWS
  execution or bound SDK requests and cleanup.
  Record each path/analysis cleanup status. Confirm the requested ID in native
  deletion responses before recording `deleted`; missing/contradictory identity
  warns as unconfirmed. Preserve an existing error during cleanup cancellation,
  attempt remaining safe deletion, and propagate cancellation if no prior error
  exists. Warning promotion must preserve either original exception.
- Endpoint precedence is `region:service`, then `service`, then `endpoint_url`,
  then boto3 defaults. Inherit overrides, TLS and transport settings across
  central, Config and member clients. Do not hard-code AWS endpoint URLs.
- Boto3's internal profile `AssumeRole` client is outside this client factory.
  Document SDK endpoint configuration separately; a library STS override alone
  does not redirect the profile's credential request.
- Endpoint compatibility is an API contract. Do not weaken AWS semantics to
  make a partial emulator pass, or invent an analysis engine inside this library.

### Protocol coverage and TGW checks

- Preserve the original one-shot TCP request/default-first-address behaviour.
  Session TCP/TLS/HTTP and one-shot TLS/HTTP checks default to all resolved
  addresses in the requested family; IPv4 is the default. Dual mode requires
  both IPv4 and IPv6; even any/first modes must satisfy each family. Do not
  silently truncate address coverage or reinterpret failed probes as isolation,
  disable TLS verification or follow HTTP redirects.
- Batch contexts share their transport context only. Refresh Config evidence and
  observations per check, retain each sample, and clean up on context exit.
  Recognized connection/protocol failures fail a positive check. Deployment,
  DNS, malformed/unknown observations and truncated nonmatching bodies raise.
- Lambda source context is evidence about the Lambda. Subnet representative labels
  require supplied groups. ENI/instance sessions derive the verified live subnet,
  AZ, ownership, required address-family presence and exact groups, and recheck
  before every observation. Drift raises with cleanup; no mode implies instance
  host firewall/process equivalence for Lambda. SSM uses the selected instance's
  host/user context and must retain its actual instance identity and transport.
- DNS-bound connection constraints check the exact resolved set subsequently
  contacted; a mismatch fails without connection traffic. Dual-stack deployment
  requires a verified IPv4 subnet with an associated IPv6 CIDR and the explicit
  Lambda IPv6 VPC option. Keep family evidence separate and never widen a
  deployment's enabled families in a terminal check.
  Statically known family conflicts must fail during planning and all-case
  preflight, before the first protocol observation. Use the effective session
  family with `_check_family()` and the shared protocol/DNS validators; do not
  merely type-check mixed sessions and discover their conflict after execution.
- Coverage requires a nonempty declaration and verified result labels; missing
  cases raise. Convergence retries only conclusive false results. Healthy
  isolation controls must match a conclusive RA TCP destination address/port.
- TGW route assertions verify the TGW owner/table, full address coverage and all
  continuation pages. Incomplete search responses and ambiguous BGP priority
  raise. Associations, propagation, route selection and packet delivery remain
  separate claims; paired forward/return tables belong to one scoped TGW.

### Matchers and modeled path evidence

- Construct immutable descriptions without SDK calls; execute a fresh check at
  `.to()` or `.not_to()`. Validate explicit options against the selected
  protocol. HTTP status/body requirements belong to HTTP checks, and TLS
  requirements need a TLS connection. Reject ignored options rather than
  returning a passing result with an unevaluated requirement in its description.
- Reach matchers use RA; observed matchers need an explicitly opened session.
  A negated reachability check requires a conclusive modeled denial. Negated
  observed checks remain unsupported. Reject non-host CIDR route negation;
  incomplete coverage cannot prove route absence across the range.
- `every()` declares distinct, finite, nonempty sources. Normalize scoped
  endpoint IDs and equivalent ARNs, including partition, when detecting duplicates.
  Names and labels do not add coverage. Preflight subject kinds, then evaluate all conclusive
  cases. Require an explicit selected account or an account-qualified endpoint
  ARN for each source; an unscoped ID cannot prove distinct ownership. Single
  unscoped expectations remain valid. A native error carries partial coverage
  and keeps its original type.
  Attach diagnostics without eagerly encoding prior evidence as JSON: a
  reporting failure must not replace the error being reported.
  Convergence wrapped by `every()` runs sequentially with a budget per source;
  describe individual convergence rather than simultaneous availability.
- Exact population matchers require nonempty unique scoped expectations. Their
  observed sequence is snapshotted. Empty, duplicate, missing or unexpected
  discoveries yield a conclusive mismatch; missing/invalid scope raises.
  Validate explicit ARN partition against the selector's session/region,
  account and resource type before canonical comparison. Never trust the ARN's
  own partition to validate itself or merge identities across partitions.
- `reach_each()` expands distinct scoped endpoints and explicit finite ports
  into the existing evaluation loop. Include the full Cartesian product, even
  self-pairs; do not silently omit cases. Preflight every expanded declaration
  before any check. Retain per-pair/port evidence and partial native-error
  coverage. Reject ambiguous negation rather than inverting “all reachable.”
- `plan()` is read-only: no clients, discovery or evaluation. Its upper bound
  must include every expanded case and maximum convergence/stability count.
  Enforce `max_ra_analyses` against the whole assertion before the first SDK call.
  A plan or a cap neither grants write permission nor estimates every AWS charge.
- `consistently()` requires all fresh observations to pass and stops on the first
  false result; `eventually()` retries conclusive false results until a success
  or exhaustion. Reject stacked timing wrappers so retries cannot hide failed
  stability observations. Preserve original errors, partial samples and live
  cleanup evidence; serialize only when the caller requests a report snapshot.
- Path constraints need a complete, endpoint-anchored forward path. Required
  and forbidden hops inspect AWS's reported path; they do not request a search
  for an alternate path. Missing evidence or qualifications that omit modeled
  inspection raise, including unsupported inspection in `AdditionalDetails`.
  Validate component region and partition during local preflight too, so a late
  invalid case cannot run after earlier valid cases have already incurred work.
- Keep each reported resource's ID and ARN paired. An unrelated ARN with the
  same short ID cannot supply ownership for an ID-only hop. Interpret ARN
  aliases using their service/resource type, and distinguish traversal
  identities from route/explanation metadata. Accept native configuration
  components as evidence without treating them as requested traffic hops.
- A blocked positive analysis fails without claiming hop constraints were
  evaluated. Neither a path mismatch nor incomplete evidence can establish
  isolation. Preserve the analysis IDs and normal cleanup on these failures.

### Lambda probes

- One-shot probes and `probe_session()` require literal `allow_write=True`
  on each deployment call, before any AWS calls. Keep it explicit; never add
  automatic fallback from RA to writes.
- Use a selected account and its verified credentials. Use explicit security
  groups unless `auto_create_security_group=True` is explicit on the call.
  Use an existing role unless `auto_create_execution_role=True` is explicit on
  the call. Never change existing roles/groups or provision other networking resources.
- Auto-created groups use the live subnet's VPC, no ingress rules and AWS's
  default outbound rules, and carry the probe tag. Confirm group identity and
  visibility before Lambda creation. Cleanup retries dependency errors after
  function deletion; retain the group on uncertain function state or timeout.
  With both automatic options, delete the group before removing the role so
  ENI cleanup retains its permissions. Keep each option behind `allow_write=True`.
  If discovery contradicts the created group's ID, owner, VPC or reported name,
  mark its identity unconfirmed and retain it for investigation.
- Auto-created roles trust Lambda and receive only the VPC ENI inline policy.
  Delete the function first and wait for matching ENIs before removing the
  policy/role. On an unsafe or timed-out cleanup, retain the role and warn.
  Keep propagation and cleanup polling bounded; preserve original errors.
- Confirm the requested IAM role name and exact account/partition ARN before
  installing a policy or authorizing deletion. A contradictory creation response
  remains unconfirmed and needs diagnostic evidence; never roll it back by an
  unconfirmed name. Apply the same creation-uncertainty rules to Lambda, IAM and
  security groups: a final 4xx after SDK retries can follow an earlier successful
  write. Retain uncertain identities and warn with the names needed to investigate.
- Delete only a function whose successful creation response confirms its
  requested name, in `finally`. Uncertain creation/deletion retains dependent
  resources with warnings. Preserve the original error and report attempted or
  retained names/IDs for investigation; never delete an unconfirmed resource by name.
- A confirmed-created function reporting not-found during deletion is already
  absent. Cleanup interruptions retain dependent-resource state and keep the
  original error or cancellation visible; a process kill cannot run `finally`.
- A failed TCP handshake does not prove isolation. DNS, deployment and execution
  errors raise. The probe tests its own Lambda context, not a workload's ENI.

### SSM instance probes

- `instance(...).ssm_probe_session()` requires literal `allow_write=True`
  before clients, discovery or command submission. Use verified selected-account
  EC2/SSM credentials for the entire session; central Config/RA credentials stay
  separate. The node must already be running, online in SSM, Linux and able to
  run Python 3.10+. Do not enroll it, install software or alter its instance profile.
- Submit only the fixed protocol program through `AWS-RunShellScript` to the
  one selected instance. No arbitrary command, document, interpreter, working
  directory, Lambda role or group options are supported. Reuse the shared
  protocol/DNS/sampling validators and complete observation-evidence checks.
- Verify reservation ownership, instance identity, complete ENIs and each live
  attachment, then the matching online SSM node. Recheck source geometry before
  every command, including the connection after DNS. Multi-ENI hosts use normal
  OS route selection; do not invent an interface-binding option. Match every
  observed local source address to one current ENI and retain that evidence.
- Report `transport="ssm"`, actual instance ID and runtime effective UID.
  Host firewall evidence concerns the SSM execution user, usually root; it does
  not establish application-user, container, proxy, authentication or process
  equivalence. Keep source labels and healthy controls bound to this context.
- Confirm native command ID, target and document before authorizing cancellation;
  bind observations to their request token before accepting a result. Lost or
  contradictory creation responses remain unconfirmed. SDK retries can leave
  earlier commands unconfirmed even when the returned command is identified.
  Never discover/adopt extra commands by comment or name. Preserve the original
  error and inspectable command records.
- Cancellation is bounded and best effort. `CancelCommand` does not confirm
  process termination; record `process_stop_confirmed=False` and warn as needed.
  Retained service history and agent artifacts are not deleted by the library.
  Do not describe SSM cleanup as removal of those records or host files.

### Cleanup manifests and recovery

- `cleanup_manifest` is optional for Lambda deployments only. Use a fresh private
  path, save intent before each create and confirmed identity afterward, and
  preserve atomic durable writes and exclusive locks. An initial write failure
  must prevent creation. Later manifest failures still run normal owned-resource
  cleanup without replacing the original error.
- Recovery defaults to dry run and requires a builder scoped to the recorded
  account/region, verified credentials, and explicit `allow_write=True` to delete.
  It performs no Config reads, probes, networking changes or ENI deletions.
  An active deployment/recovery lock must exclude another recovery operation.
- Revalidate strong native identities: exact Lambda ARN/name and creation
  revision plus role/subnet/groups; security-group ID/owner/VPC/name/tag; IAM
  ARN/name and immutable RoleId. A replacement under the same name must not be
  adopted. Never turn a write-ahead name or unconfirmed creation into ownership.
- Delete confirmed resources in function, temporary group, temporary role order.
  Preserve dependencies on uncertain deletion. Supplied roles/groups are never
  temporary recovery targets. Keep the role's ENI permissions until dependencies
  are gone, including when the run used supplied groups.
- Before role deletion, verify unchanged trust/policies, no extra consumers,
  profiles or boundary, and scan Lambda functions including published versions
  in every currently enabled account region. Missing regional visibility,
  another role consumer, changed policy or unexplained last-used region retains
  the role. Do not limit this check to the original region or default versions.
- Reports must distinguish would-delete, deleted, absent, skipped and retained
  resources. Retry pending/retained records with fresh identity reads; a saved
  deletion records cleanup of the original object and never grants ownership of
  a replacement under the same name. Incomplete recovery warns; preserve API errors and partial
  evidence. A manifest cannot make reads/deletes atomic or prove historical
  non-use, so uncertainty remains for manual investigation.

### Inspection topology

- Appliance mode requires one available matching VPC attachment on the verified
  TGW, with explicit enabled mode and a valid attachment ID. Validate the VPC
  owner field without confusing it with the TGW owner; shared owners may differ.
- Firewall placement checks use the VPC/firewall owner's account and region.
  Require exact ARN identity, live VPC/subnet ownership and AZ placement, known
  state, synchronized configuration and distinct ready endpoints in precisely
  the declared nonempty AZ/subnet set. Unknown state or contradictory identity
  raises; a valid incomplete/different layout fails. Do not inspect or infer rules.
- Paired VPC routes are two explicit effective coverage checks in one region;
  paired TGW tables must belong to one scoped TGW. Validate both declarations
  before reads. New paired VPC checks retain completed forward evidence if
  the return check errors. Do not convert incomplete route coverage into isolation.
- A ready firewall, appliance mode and two matching route targets do not prove
  every intermediate hop, per-flow symmetry or packet inspection. Bind endpoint
  IDs to the intended AZ in the caller's declarations and add modeled/observed
  checks where needed. Reject ambiguous endpoint-layout/paired-route negation.

### Optional examples

- Keep default collection harmless without the contrib runner and without AWS
  opt-in. Load `contrib.pytest_examples` explicitly for its fixtures and flags;
  do not add a required library plugin or restore the deleted shared conftest.
- Preserve separate AWS, Lambda and SSM gates. Resolve inputs from existing
  resources or caller fixtures, fail incomplete required coverage, and keep
  authorization to execute separate from authoring a test.
- Preserve the removed labs/configuration file. Update package inclusion rules
  for files that actually exist, and never record mocked paths as live validation.

## Making changes

1. Identify the public behavior and the smallest responsible module. Keep
   unrelated edits intact; avoid broad formatting changes or speculative cleanup.
2. Reuse existing client factories, validators, selectors and result types.
   For new topology predicates, reuse `_context()` and `_decorate()` for evidence.
3. Add a focused regression test for a behavior change or bug. Exercise the
   meaningful failure boundary as well as the expected result.
4. Update public exports only when adding a public API. Update the relevant
   README, examples, API and permission documentation when behavior or AWS calls
   change. Keep packaged docs/examples included through `MANIFEST.in`.
5. Use primary AWS/boto3 documentation and the installed botocore service model
   when checking new API shapes, ownership fields or service constraints. Make
   changed assumptions explicit instead of relying on an old test fixture.

### Reviewing assertions and cleanup

Start with a concrete requirement and follow its public matcher through the
direct evaluator. For every supplied option, identify the observation or AWS
request field that evaluates it. Complete the review when all supplied criteria
are evaluated or rejected explicitly, and each error path keeps unknown state
distinct from a conclusive false result.

For a suspected false positive, add the smallest regression that reproduces it.
Cover the nearby passing case as well: a required-hop error must not disable
ordinary valid paths, and strict option validation must preserve valid defaults.
Exercise `.to()` and `.not_to()` when the predicate permits negation. Check
empty/duplicate declarations, ID/ARN aliases, partial coverage and native errors
where a collection or convergence wrapper is involved.
Include wrong-partition aliases, a malformed final Cartesian case and mixed
session address families. Verify plans and budget rejection make no SDK calls,
and that stability cannot hide a failed sample through retries.

For temporary resources, cover failure before creation, confirmed creation,
unconfirmed creation and interrupted deletion. Stub only deletions that are
authorized by confirmed identity, assert exhausted SDK queues, and inspect
resource status/evidence after the context exits. Verify that reporting and
warnings-as-errors preserve the original exception. Use mocked time and dummy
credentials throughout; live deployment is a separate task.
For recovery, cover killed-run/write-ahead uncertainty, replacement identities,
all enabled-region inventory including published versions, and incomplete
dependency visibility. For SSM, cover ambiguous sends, canceled/late commands,
the actual host/user/source context and retained command artifacts.

Prefer standard-library solutions and existing helpers. Keep boto3 the only
runtime dependency unless a justified task requirement needs another. Preserve
type annotations, Python 3.10 compatibility and `py.typed`. Do not add async APIs,
a required plugin or a new configuration format without a concrete requirement.

## Verification: proportional and offline by default

Use `botocore.stub.Stubber` with dummy credentials for SDK contracts. Assert
meaningful request parameters, pagination and exhausted response queues. Mock
time, sleeps or profile construction where necessary; keep real network access
and wall-clock waits out of unit tests. Owner fields and response states in test
fixtures should reflect the API contract, including deliberately malformed cases.

| Change area | Start with |
| --- | --- |
| Profiles, sessions, identity or endpoints | `test_accounts.py`, `test_clients.py`, relevant `test_organization.py` cases |
| Aggregator inventory or Config behavior | `test_inventory.py`, relevant builder/organization cases |
| RA requests, endpoint qualification or lifecycle | `test_reachability.py`, relevant builder/organization cases |
| Coverage, stability, convergence and healthy controls | `test_checks.py` |
| Exact populations, Cartesian ports, plans/caps, family preflight and safe negation | `test_expectations.py` |
| Modeled path intent and blocker evidence | `test_path_evidence.py`, relevant `test_reachability.py` cases |
| Derived workload sources and live drift | `test_workload_probes.py` |
| IPv6/dual-stack and bound DNS connections | `test_dual_stack_probes.py`, `test_application_handler.py` |
| TGW association and routes | `test_tgw_routes.py`, relevant shared-resource cases |
| Route evaluation | `test_routes.py`, relevant `test_builder.py` cases |
| Lambda probe lifecycle or packet observations | `test_probe.py`, `test_probe_role.py`, `test_probe_security_group.py`, `test_probe_session.py`, `test_application_handler.py`, relevant account/organization cases |
| SSM execution, source drift, command identity and cancellation | `test_ssm_probe.py`, relevant `test_checks.py` controls |
| Durable manifests, strong recovery identity and regional role consumers | `test_recovery.py`, relevant Lambda lifecycle tests |
| Appliance mode, firewall placement and paired inspection routes | `test_inspection.py`, `test_inspection_matchers.py` |
| Shared resources and ownership | `test_shared_resources.py`, relevant builder/organization cases |
| Native explicit/main subnet association selection | Relevant `test_builder.py`, `test_shared_resources.py`, `test_organization.py` cases |
| Optional example runner, default skip gates and MiniStack sessions | `test_example_sessions.py`; collect examples with and without `-p contrib.pytest_examples` |

- Run the affected tests during iteration. Do not run the full suite after
  every small edit or repeat checks against unchanged code without a reason.
- Run the full offline suite once after a meaningful cross-cutting change or
  before a release. Broaden testing to address a concrete remaining risk.
- For documentation-only changes, check wording, links, commands and example
  syntax; do not invent tests that merely assert the documentation text exists.
- For packaging changes, build and inspect the relevant artifact. Run an
  installed-package smoke check when imports, exports or distribution contents
  could have changed. A packaging edit alone does not require every AWS test.
- Reuse successful checks until a later edit affects them. If collaborating,
  divide file ownership and avoid duplicate test/build runs or competing edits.

Live AWS execution must be part of the requested task, with the intended scope
understood. Keep `--run-aws` opt-in; RA creates chargeable analyses. Do not enable
Config recording, change IAM/Organizations, alter networking, or use the user's
real credentials as incidental unit-test setup. Respect authorization already
given rather than repeatedly asking for the same confirmation. Never commit
credentials, tokens, local AWS configuration, caches, environments or build output.

## Completion

Report the behavior changed, the checks actually run, their results, and any
material limitation or remaining blocker. Distinguish offline SDK validation
from live AWS validation. Do not claim service compatibility from mocked responses
alone, or update recorded validation results with checks that were not executed.

Keep summaries concise and useful. Preserve the requested scope; deployment,
publishing, unrelated refactors and infrastructure provisioning are separate work
unless included in the task.
