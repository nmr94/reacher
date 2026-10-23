# AWS network assertions

Test AWS networks with plain Python assertions. Use AWS Config to find resources,
EC2 to inspect routes, Reachability Analyzer to model packet paths, and temporary
Lambda or SSM probes to make real connections.

The library runs with Python 3.10+ and boto3. You do not need a pytest plugin or a
permanent deployment.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

The tests in `tests/` run offline with dummy credentials. To run the opt-in
examples, load the optional repository runner:

```bash
python -m pytest -p contrib.pytest_examples examples/ --run-aws
```

Examples skip unless both the runner and `--run-aws` are supplied. The runner
is for these examples; your own tests can use ordinary fixtures.

To run the examples through `contrib/ministack_boto3.py`, also pass `--ministack`.
The [MiniStack setup](docs/usage.md#ministack-examples) explains account selection
and endpoint options.

## Start with your organization

```python
from aws_network_asserts import RuleBuilder, expect, have_route_to, propagate_to, reach

org = RuleBuilder(
    profile_name="org-network-admin",
    region_name="eu-west-2",
    config_aggregator="organization-network",
    config_region="eu-west-2",
    account_profiles={
        "111111111111": "production-network-tests",
        "222222222222": "shared-network-tests",
    },
)

production = org.in_account("111111111111")
shared = org.in_account("222222222222")

application = production.eni("eni-app").named("application")
database = shared.eni("eni-db").named("database")

expect(application).to(reach(database).over_tcp(5432))
expect(application).not_to(reach(database).over_tcp(22))
expect(production.subnet("subnet-app")).to(have_route_to("10.47.0.0/16").via("tgw-hub"))
expect(shared.tgw("tgw-hub")).to(propagate_to("tgw-rtb-shared").from_vpc("vpc-app"))
```

Replace the example IDs and profiles. Account IDs must be 12-digit strings.
`.in_account()` and `.in_region()` create new views, so an existing selector keeps
its original account and region.

Config reads use the central reader in `config_region`. RA uses the central
management or delegated-admin identity in the network's region. Live EC2,
Lambda and SSM calls use the selected account's profile, verified through STS. Selecting
an account does not change the central identities.

Config records are required by default. `config_mode="prefer"` allows missing
records; permission and API errors still raise. Use `config_mode="off"` for a
standalone environment without an aggregator. See [setup and permissions](docs/permissions.md)
and the [profile setup](docs/usage.md#assume-a-role-through-a-standard-boto3-profile).

## Write the requirement directly

```python
from aws_network_asserts import every, expect, reach


class TestDatabaseAccess:
    def test_allows_every_application_server(self, application_enis, database):
        expect(every(application_enis)).to(reach(database).over_tcp(5432))

    def test_uses_the_intended_connection(self, application, database, tgw_id):
        expect(application).to(reach(database).over_tcp(5432).through(tgw_id))
```

Fixtures bind names to scoped resources. Matchers describe the requirement;
`.to()` and `.not_to()` run and assert a fresh check. Unknown state and AWS errors
still raise. A negated reachability expectation requires a conclusive RA denial.
`every()` rejects an empty collection. See the [expectation guide](docs/expectations.md)
for routes, protocol matchers, safe negation and convergence.

## Choose the check you need

| Question | Check | What you learn |
| --- | --- | --- |
| What did Config record? | `config_snapshot()`, `resource_ids()` | Recorded inventory |
| Which route wins? | `subnet(id).has_route_to(cidr, via=target)` | Active routes cover the entire range |
| Are the VPCs peered? | `vpc(id).has_peering_with(other)` | The peering is active |
| Is the TGW set up correctly? | `tgw(id).route_table(id)` checks | Attachment association and forward/return routes |
| Does AWS model a working path? | `eni(id).can_reach(destination, port=443)` | RA's answer for that packet |
| Does AWS model a blocked path? | `eni(id).cannot_reach(destination, port=22)` | A completed, supported RA analysis reports no path |
| Does a connection actually work? | `probe_tcp()`, `probe_tls()`, `probe_http()` | A connection from a VPC Lambda |
| What does DNS return inside the VPC? | `probe_dns()` | Answers match the expected IPs or CIDRs |

A route alone cannot tell you whether security groups, ACLs or the server will
accept traffic. RA models configuration and sends no packets. A probe sends
packets from its own network interface, so its result does not test another
instance's operating system or firewall.

## Make real connections

```python
from aws_network_asserts import expect, get

with application.probe_session(
    allow_write=True,
    execution_role_arn=role_arn,
) as probe:
    result = expect(probe).to(
        get("https://api.internal.example/health")
        .returning_status(200)
        .containing("ready")
        .for_every_address()
        .with_options(
            allowed_destination_cidrs=["10.47.0.0/16"],
            attempts=3,
            successes_required=2,
            max_latency_ms=500,
        )
    )
```

An ENI or instance session derives and verifies its actual subnet, AZ and security
groups. It rechecks that source before each observation and rejects drift.
The connection still comes from Lambda; it does not execute inside the workload.
Destination CIDRs constrain the exact DNS answers used by that connection.

Every deployment requires `allow_write=True` and cleans up when the context
ends. Use `auto_create_execution_role=True` to create its temporary role. For a
synthetic subnet probe, you can also request `auto_create_security_group=True`;
a workload-derived probe always uses the workload's groups.

Protocol matchers test every resolved address by default. Set
`address_family="ipv6"` or `"dual"` on a probe session for IPv6 observations in
an existing dual-stack subnet. Dual checks require and report both families;
IPv4 success cannot hide IPv6 failure. The original direct `probe_tcp()` keeps
its first-address IPv4 default.

A timeout or refused connection fails a positive probe. DNS, deployment, unknown
state and API failures raise. A failed probe does **not** prove isolation.
Cleanup failures warn and record the resources that need attention. See the
[probe guide](docs/live-probes.md) for timing, permissions and cleanup details.

## Results and limits

Checks return `CheckResult`. Use `assert result, result.message`,
`result.assert_ok()`, or inspect `result.evidence`. `result.to_dict()` makes a
JSON-compatible report. Missing information and unsupported checks raise instead
of returning a reassuring answer.

Route checks handle IPv4 and IPv6 supernets, more-specific routes, blackholes and
prefix lists without enumerating every IP. RA packet checks support IPv4 and
stay in one region. Observed probes support IPv4, IPv6 and explicit dual-stack
coverage. RA results retain structured, direction-aware blocker explanations;
path assertions require complete reported forward-path evidence.

`CoverageMatrix` requires every declared test case. `wait_for()` waits for a
configuration to converge. `isolation_with_control()` requires a healthy probe
for the same IP and port before accepting an RA isolation result. See
[advanced checks](docs/advanced-checks.md) for examples and options.

## Documentation

- [Expectation guide](docs/expectations.md): English-like assertions, collections and safe negation.
- [Usage reference](docs/usage.md): accounts, packets, Config and custom endpoints.
- [Probe guide](docs/live-probes.md): Lambda, role and security-group lifecycles.
- [Advanced checks](docs/advanced-checks.md): DNS coverage, sampling, TGW routes and reports.
- [Permissions](docs/permissions.md): profiles, organization setup and policy templates.
- [API surface](docs/api-surface.md): request shapes and requirements for test doubles.

## Development and validation

```bash
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m pytest -p contrib.pytest_examples examples/ -q
python -m build
```

Examples skip without `--run-aws`; Lambda examples also need
`--allow-probe-writes`, and SSM examples need `--allow-ssm-commands`.
RA, EC2, NAT, TGW, Lambda and SSM can incur charges.
[Earlier validation notes](docs/validation.md) are kept as history.

## Check populations, coverage and stability

```python
from aws_network_asserts import contain_exactly_resources, every, expect, reach_each

applications = production.subnet(application_subnet_id).enis()
expect(applications).to(contain_exactly_resources(app_a, app_b))
requirement = reach_each([database_a, database_b]).over_tcp(5432, 6432)
plan = expect(every(applications)).plan(requirement)
results = expect(every(applications)).to(requirement, max_ra_analyses=20)
```

The population check catches missing and unexpected resources before a sampled
population can look like complete coverage. `reach_each()` checks every declared
source/destination/port combination. `plan()` performs no AWS calls; its analysis
count is an upper bound, including retry wrappers. The optional cap rejects an
oversized run before its first check. Discovery such as `.enis()` still reads AWS.

Use `.consistently(checks=5, interval=2)` to require five consecutive fresh passes.
It stops at the first failure; `.eventually(...)` instead waits for one pass.
Neither establishes continuous availability between observations.

For the actual instance's host network, open
`instance.ssm_probe_session(allow_write=True)`. It needs an existing SSM-managed
Linux instance with Python 3.10+ and runs fixed protocol operations under the
SSM execution user. See the [SSM guide](docs/ssm-probes.md) for scope and command
cancellation limits.

For recoverable Lambda cleanup, supply a unique `cleanup_manifest` path to the
probe deployment. After an interrupted process, inspect it with the
[recovery command](docs/recovery.md); deletion needs a separate explicit write
option and verified resource identities. The [inspection guide](docs/inspection-checks.md)
covers appliance mode, Network Firewall endpoint placement and paired routes.
