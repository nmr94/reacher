# Complete usage reference

Start with the [quick start](../README.md), or use this reference for detailed options.
The [expectation guide](expectations.md) covers the RSpec-style matchers,
including `every()`, path constraints, protocol checks and convergence.

Write AWS network tests as ordinary pytest assertions. The library reads a
central Config aggregator, queries current EC2 topology, models packet paths
with Reachability Analyzer, and can send traffic through temporary Lambda probes.
It supports Python 3.10+ and uses boto3 as its only runtime dependency.

Choose the check that answers your question:

| Question | Use | Evidence |
| --- | --- | --- |
| What resources are recorded? | `resource_ids()`, `config_snapshot()` | Central Config aggregator |
| Are the routes and network relationships correct? | `has_route_to()` and other topology predicates | Current EC2 state, with the source Config record |
| Does AWS model a path for this packet? | `can_reach()`, `cannot_reach()` | Reachability Analyzer |
| Does a connection or DNS lookup work from this subnet? | `probe_tcp()`, `probe_tls()`, `probe_http()`, `probe_dns()` | Temporary VPC Lambda, with `allow_write=True` |

An active route alone does not prove connectivity. RA models configuration;
a probe observes traffic from its own network context. An error never starts
a different check automatically or counts as proof of isolation.

```python
from aws_network_asserts import (
    RuleBuilder,
    be_peered_with,
    expect,
    have_route_to,
    propagate_to,
    reach,
)

org = RuleBuilder(
    profile_name="org-network-admin",
    region_name="eu-west-2",
    config_aggregator="organization-network",
    config_region="eu-west-2",
    account_profiles={
        "111111111111": "production-network-read",
        "222222222222": "shared-network-read",
    },
)

rule = org.in_account("111111111111")
shared = org.in_account("222222222222")

application = rule.eni("eni-1234567").named("application")
expect(application).to(reach("10.47.1.1").over_tcp(443))
expect(application).not_to(reach("10.47.1.1").over_tcp(22))
expect(rule.subnet("subnet-12345")).to(have_route_to("10.1.1.1/32"))
expect(shared.tgw("tgw-12345")).to(propagate_to("tgw-rtb-12345").from_vpc("vpc-12345"))
expect(rule.vpc("vpc-12345")).to(be_peered_with(shared.vpc("vpc-124444")))
```

Replace IDs and profile names with your own. The default packet is **TCP to
port 443**. Account IDs are 12-digit strings. Select the account that owns the
resource; for a shared TGW route table, use the TGW owner's account.

Matchers describe a check without calling AWS. `.to()` or `.not_to()` runs a
fresh check, asserts its result and returns the `CheckResult` for inspection.
`not_to(reach(...))` requires a conclusive modeled denial; errors remain errors.
`.named()` returns an independent selector with a readable label while retaining
its resource ID, account and region in diagnostics.

## Organization credentials

The central builder keeps the analysis identity separate from resource ownership:

| Operation | Credentials | Region |
| --- | --- | --- |
| Config snapshots and discovery | Central session, or optional `config_profile_name` / `config_session` | Fixed `config_region` |
| Reachability Analyzer create, start, poll, and cleanup | Central management/delegated-admin session | Selected network region |
| Live routes, peering, TGW state, ENIs | Selected account's mapped profile/session | Selected network region |
| Opt-in Lambda create, readiness, invoke and cleanup | Selected account's mapped profile/session, verified through STS | Selected network region |

`.in_account()` selects the **source account in the aggregator** and the owner of
network resources. It keeps the central Config and analysis credentials.
`.in_region()` changes the resource region while leaving the aggregator region
fixed. Both return independent views; existing builders and selectors are unchanged.

`account_profiles` is optional. Config-only checks and central Reachability
Analyzer checks do not load member profiles. Live EC2 checks need credentials
for the selected account. With no mapping, the central credentials can be used
only when STS `GetCallerIdentity` confirms that they belong to that account.
A mismatch raises `AccountMismatchError` before the EC2 topology call. Successful
identity checks and clients are reused per credential context and region;
network results and Config snapshots are not cached.

Use `profile_name="..."` or `session=boto3.Session(...)` for central credentials.
Omit both to use the normal boto3 credential chain, including `AWS_PROFILE`.
`region_name` overrides the session region; no region is invented by the library.
Set `account_id="111111111111"` in the constructor for a default resource account.

### Assume a role through a standard boto3 profile

```ini
# ~/.aws/config
[profile org-network-admin]
# Configure your normal SSO, role, or other credential source here.
region = eu-west-2

[profile production-network-read]
role_arn = arn:aws:iam::111111111111:role/NetworkAssertionsReadOnly
source_profile = org-network-admin
role_session_name = network-assertions
region = eu-west-2

[profile shared-network-read]
role_arn = arn:aws:iam::222222222222:role/NetworkAssertionsReadOnly
source_profile = org-network-admin
role_session_name = network-assertions
region = eu-west-2
```

The profile names are the values in `account_profiles`. Boto3 performs the
configured STS role assumption and refreshes temporary credentials. Profiles can
also use SSO or other supported providers. The library does not copy temporary
credentials or maintain its own role cache. Use `config_profile_name` for a
separate Config reader, or pass a `config_session` as shown below. For local
services, see [custom boto3 endpoints](#custom-boto3-endpoints).

If your test harness already manages sessions, pass them directly:

```python
org = RuleBuilder(
    session=central_session,
    config_session=config_reader_session,  # Optional; central is the default.
    region_name="eu-west-2",
    config_aggregator="organization-network",
    config_region="eu-west-2",
    account_sessions={"111111111111": production_session},
)
```

`account_profiles` and `account_sessions` can cover different accounts; one
account cannot have both. Likewise, supply a session or profile name for each
central credential context, not both.

Cross-account Reachability Analyzer requires AWS Organizations trusted access and
management/delegated-administrator setup. An existing Config aggregator does not
enable this automatically. Member profiles grant live topology access; they do
not grant central analysis access. This project uses existing organization
configuration and roles. See [permissions and setup](permissions.md).

## Install and run

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
python -m pytest
```

The default suite uses synthetic fixtures and `botocore.stub.Stubber`; it makes
no AWS requests. [Earlier validation notes](validation.md) are historical; run
the checks against your own checkout. The AWS examples use the optional
[repository runner](../contrib/pytest_examples.py), loaded explicitly with `-p`:

```bash
export AWS_PROFILE=org-network-admin
export CONFIG_AGGREGATOR=organization-network
export CONFIG_AGGREGATOR_REGION=eu-west-2
export NETWORK_ACCOUNT_ID=111111111111
export NETWORK_ACCOUNT_PROFILES='{"111111111111":"production-network-read","222222222222":"shared-network-read"}'
export SOURCE_ENI=eni-0123456789abcdef0
export DESTINATION_IP=10.47.1.1
export SOURCE_SUBNET=subnet-0123456789abcdef0
export DESTINATION_CIDR=10.47.0.0/16

python -m pytest -p contrib.pytest_examples examples/ --run-aws --aws-region eu-west-2
```

Set `CONFIG_PROFILE` only if the aggregator needs a different profile from the
analysis identity. `--aws-profile` explicitly selects the central profile.
`NETWORK_ACCOUNT_ID` is the default resource account; organization examples also
use `ACCOUNT_A` and `ACCOUNT_B`. `CONFIG_SOURCE_ACCOUNT` remains a legacy alias
for the default account. Tests skip missing resource inputs. All examples skip
without `--run-aws`. Direct terminal methods and expectation `.to()` / `.not_to()`
calls run their checks immediately.
Lambda examples additionally require `--allow-probe-writes`; see the
[live probe guide](live-probes.md) for their inputs and IAM setup. SSM examples
require the separate `--allow-ssm-commands` option and a preconfigured managed
instance; see the [SSM guide](ssm-probes.md). Without the runner, the examples
skip. Your own tests can use the ordinary fixture below instead.

Each `can_reach()` or `cannot_reach()` creates a new, chargeable AWS analysis.
Deleting its temporary objects does not undo the charge. Config recording and
aggregation must already cover the desired accounts, regions and resource types.

## A pytest fixture

```python
# conftest.py in your test project
import pytest
from aws_network_asserts import RuleBuilder


@pytest.fixture(scope="session")
def org():
    return RuleBuilder(
        profile_name="org-network-admin",
        region_name="eu-west-2",
        config_aggregator="organization-network",
        config_region="eu-west-2",
        account_profiles={
            "111111111111": "production-network-read",
            "222222222222": "shared-network-read",
        },
    )


@pytest.fixture(scope="session")
def rule(org):
    return org.in_account("111111111111")
```

```python
from aws_network_asserts import expect, have_route_to, reach


def test_app_can_access_shared_database(org, rule):
    application = rule.eni("eni-app").named("application")
    database = org.in_account("222222222222").eni("eni-database").named("database")
    expect(application).to(reach(database).over_tcp(5432))


def test_database_cannot_initiate_ssh_to_admin(rule):
    expect(rule.eni("eni-database")).not_to(reach("10.47.1.1").over_tcp(22))


def test_application_segment_routes_through_tgw(rule):
    expect(rule.subnet("subnet-app")).to(have_route_to("10.47.0.0/16").via("tgw-hub"))
```

Expectation failures include the source, matcher and underlying diagnostic.
The passing return value has full observations in `result.evidence`, including
account, region, Config provenance and the analysis or topology response.
The direct predicates below return an unasserted `CheckResult`, which supports
`assert result, result.message` and `result.assert_ok()` outside pytest.

## Supported assertions

| Expression | What a passing result establishes |
| --- | --- |
| `rule.eni(id).can_reach(ip_or_endpoint, port=443)` | RA reports the selected modeled IPv4 path reachable |
| `rule.eni(id).cannot_reach(ip_or_endpoint, port=22)` | A conclusive analysis reports the selected path unreachable |
| `rule.instance(id).can_reach(destination)` | The same check with an EC2 instance as source |
| `rule.resource(id_or_arn).can_reach(destination)` | The same check for another supported RA endpoint |
| `endpoint.can_reach(destination, through=[gateway], avoiding=[other])` | A complete reported forward path includes required components and excludes forbidden ones |
| `rule.subnet(id).has_route_to(cidr, via=target)` | Every address in the range selects an active effective route, optionally to that target |
| `rule.route_table(id).has_route_to(cidr, via=target)` | The same route check against an explicit VPC table |
| `rule.subnet(id).probe_tcp(host, ..., allow_write=True)` | A temporary Lambda establishes an observed TCP handshake; defaults to IPv4 and the first resolved address |
| `rule.subnet(id).probe_tls()` / `probe_http()` / `probe_dns()` | Verified TLS, HTTP predicates or explicit VPC DNS expectations |
| `rule.subnet(id).probe_session(..., allow_write=True)` | One explicit deployment for multiple fresh observations |
| `rule.eni(id).probe_session(..., allow_write=True)` / `rule.instance(id).probe_session(...)` | A Lambda session derives the workload's current subnet and security groups |
| `rule.tgw(id).route_table(id)` | Association, effective CIDR routes and paired forward/return routes |
| `rule.vpc(id).has_peering_with(other)` | Active peering matches the peer VPC and any account/region selected by `other` |
| `rule.tgw(id).propagates(table).from_vpc(vpc)` | VPC attachment propagation into the TGW table is enabled |
| `rule.tgw(id).has_attachment(vpc)` | An available VPC attachment exists on that TGW |
| `rule.eni(id).in_subnet(subnet)` | The live ENI belongs to the selected subnet |
| `rule.eni(id).in_vpc(vpc)` | The live ENI belongs to the selected VPC |
| `rule.eni(id).is_recorded()` | The aggregator has a usable configuration for this account/region/resource |
| `rule.vpc(id).has_config_tag("Environment", "test")` | That tag is present in the Config snapshot |
| `selector.named("application")` | Labels an independent selector; this is not an assertion |

Typed ENI, instance, subnet, VPC, VPC route-table and TGW selectors all support
`config_snapshot()`, `is_recorded()` and `has_config_tag()`.

### Real connection checks with explicit write permission

```python
result = rule.subnet("subnet-0123456789abcdef0").probe_tcp(
    "database.internal.example",
    port=5432,
    execution_role_arn="arn:aws:iam::111111111111:role/NetworkProbeExecution",
    security_group_ids=["sg-0123456789abcdef0"],
    allow_write=True,
)
assert result, result.message
```

The selected account and either an existing execution role or
`auto_create_execution_role=True` are required. Every call
creates a new Lambda in that subnet, waits for readiness, attempts a TCP
connection and deletes the function in `finally`. Omitting `allow_write=True`
raises before any AWS calls. Deployment, DNS and execution errors raise;
connection timeout/refusal returns a failing result. A failed probe does not
prove isolation. The Lambda's security groups and source address can differ from
the workload being tested.

The [live probe guide](live-probes.md) documents all parameters, DNS behavior,
cross-region destinations, timeout limits, cleanup diagnostics and opt-in examples.
See [probe permissions](permissions.md#lambda-probe-permissions) for caller
and execution-role policy templates. Set `auto_create_security_group=True`
instead of `security_group_ids` to create a tagged, no-ingress group with AWS
default outbound rules in the selected subnet's live VPC. Both automatic
options still require per-call `allow_write=True`. The group is removed after
function deletion, with dependency retries bounded by
`security_group_cleanup_timeout` (default 1200 seconds). AWS manages ENI removal asynchronously;
cleanup failures warn with resource names for investigation. Auto-created roles
are removed after function deletion and ENI cleanup, bounded by
`role_cleanup_timeout` (default 1200 seconds). If safety cannot be established,
cleanup retains the role and warns. Existing roles are never changed.

To reuse a workload's current network settings, open a session on its ENI or
instance selector:

```python
from aws_network_asserts import expect, get

application = rule.instance("i-0123456789abcdef0").named("application")
with application.probe_session(
    allow_write=True,
    auto_create_execution_role=True,
) as probe:
    result = expect(probe).to(
        get("https://api.internal.example/health")
        .returning_status(200)
        .containing("ready")
        .for_every_address()
        .with_options(allowed_destination_cidrs=["10.47.0.0/16"])
    )
report = result.to_dict()  # Inspect cleanup after leaving the context.
```

The session verifies the live owner, subnet, VPC, AZ and exact security-group
set, then rechecks them before each observation. Multi-ENI instances require
`network_interface_id="eni-..."`. Group overrides and automatic groups are
rejected for workload sessions. The Lambda runs in that network context; it
does not execute inside the instance or test its processes, credentials or host
firewall. Drift raises and follows the usual cleanup path. See
[source context](advanced-checks.md#source-context).

Protocol sessions default to every resolved address; one-shot `probe_tcp()`
defaults to the first. `expected_addresses=[...]` requires an exact DNS answer
set. `allowed_destination_cidrs=[...]` requires every answer inside the allowed
union. TCP, TLS and HTTP validate these expectations against the answers used
by that same check, before opening connections. A mismatch fails without
connection traffic. `probe_dns()` / `probe.dns()` use `allowed_cidrs` for their
standalone DNS assertion; a separate connection resolves again. Session checks
accept at most 32 distinct addresses across the requested families; excess
answers raise instead of being truncated. Observed matchers reject `.not_to()`;
use conclusive modeled denial for an isolation check.

| `address_family` | Observation |
| --- | --- |
| `"ipv4"` (default) | IPv4 addresses only |
| `"ipv6"` | IPv6 addresses only |
| `"dual"` | Both families must resolve and meet the connection criteria |

Choose the family when creating the session or one-shot probe. IPv6 and dual
sessions require an existing dual-stack subnet and enable Lambda's outbound
IPv6 option; the library does not create IPv6 routes or rules. Session methods
inherit that family and may narrow it, but cannot widen it. Make the requested
family visible in protocol matchers with
`get(url, address_family="dual")` for a dual check or
`connect_to(ip, address_family="ipv6")` for a literal IPv6 target.
Even `address_mode="any"` requires a successful address in each requested
family. See the [protocol guide](advanced-checks.md#protocol-and-address-options).

### Cross-account reachability

```python
production = org.in_account("111111111111").in_region("eu-west-2")
shared = org.in_account("222222222222").in_region("eu-west-2")

assert production.eni("eni-app").can_reach(shared.eni("eni-db"), port=5432)
assert production.eni("eni-app").can_reach("eni-localdb", port=5432)
assert production.eni("eni-app").can_reach(
    "arn:aws:ec2:eu-west-2:222222222222:network-interface/eni-db", port=5432
)
```

Account-scoped IDs become ARNs before RA is called. A bare destination ID string
uses the source account; a selector carries its own account and region; an
explicit destination ARN names its account. In Config-enabled organization mode,
an unscoped bare-ID destination selector is rejected. Explicit ARNs must agree
with any selected account and the analysis region.

Create/start/poll/delete calls all use the central analysis credentials. Set
`additional_accounts=("333333333333",)` if AWS needs additional intermediate
resource accounts. This is an analysis argument, not a role-assumption setting.

### Packets and segments

```python
assert rule.eni("eni-app").can_reach(
    rule.eni("eni-database"),
    protocol="tcp",
    port=5432,
    source_ip="10.0.1.20",
    source_port=49152,
    destination_ip="10.0.2.30",
)
assert rule.eni("eni-app").can_reach("10.0.2.53/32", protocol="udp", port=53)
```

IP filters describe the packet at the source using AWS's `FilterAtSource` API.
`destination_ip` can disambiguate multiple resource addresses. A bare IPv4
address and its `/32` are equivalent. Reachability checks reject broader CIDRs
and IPv6; route checks support IPv4 and IPv6 ranges. `port=None` leaves the
port unconstrained; it does not prove all ports work.

Positive `can_reach()` checks also accept `through=[component_id_or_arn]` and
`avoiding=[component_id_or_arn]`. These inspect AWS's reported forward path;
they do not direct AWS to find a different path. Supply an explicit resource
destination: an IP alone cannot anchor the complete resource path. Missing,
contradictory, warned or partial component evidence raises. A complete path
that violates the constraint fails. These options are rejected by
`cannot_reach()` because a path mismatch cannot establish isolation. See
[path constraints](expectations.md#require-or-forbid-a-component) for matcher
forms, supported components and ownership rules.

A subnet is not an RA endpoint. Select representative ENIs or enumerate its
current ENIs and test each:

```python
enis = rule.subnet("subnet-app").enis()
assert enis, "Expected ENIs in the application subnet"
for eni in enis:
    assert eni.can_reach("10.47.1.1", port=443)
```

Enumeration needs live EC2 access. For a scoped shared-VPC subnet, each returned
ENI retains its own `OwnerId`, including participant-owned ENIs. Its Config
record and RA ARN therefore use that owner. This checks current ENIs, not
future ENIs or every packet; each iteration runs one analysis.

### Route and TGW semantics

Subnet checks use the explicitly associated table or the current VPC main table.
Complete CIDR coverage is checked using interval boundaries and longest-prefix
selection, including more-specific blackholes. Managed prefix lists and
explicit-static/prefix-list/propagated priorities are considered. Ambiguous ties
or unknown selected route states raise.

An exact destination route is unnecessary: `10.0.0.0/8` covers `10.47.0.0/16`
unless a more-specific route changes the effective next hop or selects a
blackhole. IPv6 follows the same rule. The standard-library `ipaddress` module
already provides the overlap and containment operations needed here, so adding
`netaddr` would not change routing behavior. Coverage uses finite interval
boundaries rather than enumerating addresses, including for IPv6 `::/0`.

`has_route_to()` establishes active route selection. Return routing, security
groups, NACLs, next-hop health and applications need their own checks. Use `via=`
when the next hop matters; otherwise an active default route can satisfy the check.

TGW tables start with **`tgw-rtb-`**; **`rtb-`** is a VPC table and is rejected.

```python
hub = org.in_account("222222222222")  # TGW owner, even for a shared attachment.
assert hub.tgw("tgw-hub").propagates("tgw-rtb-shared").from_vpc("vpc-app")
assert hub.tgw("tgw-hub").propagates("tgw-rtb-shared").to_vpc("vpc-app")
```

Both mean **VPC attachment routes propagating into the TGW table**. Propagation
alone establishes neither a subnet route to the TGW nor a TGW table association
nor every eventual propagated route. Where topology APIs expose resource owner
fields, scoped checks validate those owners; sharing a resource does not make
the caller its owner.

## Cross-region testing

Account and region views compose in either order:

```python
london = org.in_account("111111111111").in_region("eu-west-2")
ireland = org.in_region("eu-west-1").in_account("222222222222")

assert london.vpc("vpc-london").has_peering_with(ireland.vpc("vpc-ireland"))
assert london.subnet("subnet-london").has_route_to("10.20.0.0/16", via="pcx-shared")
assert ireland.subnet("subnet-ireland").has_route_to("10.10.0.0/16", via="pcx-shared")

# Separate regional analyses in one suite.
assert london.eni("eni-londonapp").can_reach("eni-londondb", port=5432)
assert ireland.eni("eni-irelandapp").can_reach("eni-irelanddb", port=5432)
```

**One RA analysis requires both endpoints in the same region.** A selector or
ARN from another region raises `UnsupportedCheckError`. A raw IP does not
identify its region, so IP-only analysis is limited to what AWS can model from
the selected region. It is not proof of a complete inter-region or external
path. The examples check peering and both sides' routes. AWS's
[multi-region analysis sample](https://github.com/aws-samples/vpc-reachability-analyzer-multi-region)
uses extra orchestration outside this starter's scope.
For an observed TCP connection across regions, use the explicit
[Lambda probe](live-probes.md) from the source subnet to the destination
IP or hostname; it uses the existing inter-region network path.

## Config aggregator behavior

`config_aggregator` and `config_region` are required unless `config_mode="off"`.
Every aggregate query specifies the selected account and resource region; no
account is guessed from central credentials. `resource_ids()` discovers only
that scope. Config can use a separate central identity through
`config_profile_name` or `config_session`.

Each typed terminal network check first fetches the latest usable aggregate
snapshot of its **source/subject**, attached as `result.evidence["config"]`.
The destination's snapshot is available through its own typed selector.

| `config_mode` | Behavior |
| --- | --- |
| `"required"` (default) | Missing usable inventory raises before the network check |
| `"prefer"` | Missing/deleted/unrecorded inventory becomes `config_unavailable` evidence; the current check proceeds |
| `"off"` | No automatic Config calls; explicit Config methods raise |

Permission, transport and malformed-response errors raise in both enabled modes.
`is_recorded()` returns false for genuinely absent/unusable inventory;
`config_snapshot()` raises. Generic `resource()` selectors do not infer a Config
type; use typed selectors when Config evidence is required.

```python
snapshot = rule.eni("eni-app").config_snapshot()
print(snapshot.account_id, snapshot.region, snapshot.arn, snapshot.captured_at)
print(snapshot.configuration)  # Original Config lowerCamelCase JSON keys.
assert rule.eni("eni-app").is_recorded()
assert rule.vpc("vpc-app").has_config_tag("Environment", "test")
ids = rule.resource_ids("AWS::EC2::NetworkInterface")
assert ids, "An empty inventory must not pass all network checks"
```

Aggregators provide replicated read-only data and can lag changes. An old capture
timestamp can also describe an unchanged resource. Timestamps are preserved
without inventing a universal freshness guarantee. Routes, membership, peering
and propagation query live EC2; Config supplies inventory and provenance.

## Custom boto3 endpoints

For standalone checks without Config:

```python
import boto3
from aws_network_asserts import RuleBuilder

local_session = boto3.Session(
    aws_access_key_id="testing",
    aws_secret_access_key="testing",
    region_name="eu-west-2",
)
rule = RuleBuilder(
    session=local_session,
    endpoint_url="http://localhost:4566",
    config_mode="off",
)
```

For an organization-aware endpoint implementing aggregator and identity APIs,
keep the organization settings and override services:

```python
org = RuleBuilder(
    session=local_session,
    region_name="eu-west-2",
    config_aggregator="organization-network",
    config_region="eu-west-2",
    endpoint_urls={
        "ec2": "http://localhost:5001",
        "config": "http://localhost:5002",
        "sts": "http://localhost:5003",
        "eu-west-1:ec2": "http://localhost:6001",
        "eu-west-1:sts": "http://localhost:6003",
    },
    account_sessions={"111111111111": local_session},
)
```

Precedence is **`region:service` -> `service` -> `endpoint_url` -> boto3 defaults**.
Overrides apply to central, Config and member clients. Region changes create
the correctly signed regional client even when regions share a URL. Config
continues to use `config_region`. Account-scoped live checks require STS
`GetCallerIdentity` to return the expected account.

These overrides cover clients created by the library. **Boto3's internal STS
client for profile `AssumeRole` is created by its credential provider**. To send
that call to a custom endpoint, also configure `AWS_ENDPOINT_URL_STS` or SDK
profile `services` endpoint settings. A library `endpoint_urls["sts"]` entry
alone redirects only its explicit identity calls.

Pass `boto_config=botocore.config.Config(...)` for retries, timeouts and proxies,
or `verify="/path/to/ca-bundle.pem"` for a private CA. Defaults are standard
retries with three total attempts, five-second connect and 30-second read
timeouts. Dummy credentials above are for emulators.

An endpoint must implement the APIs and analysis behavior; an override supplies
no analysis engine. See [API surface](api-surface.md). `prefer` does not
swallow missing API or permission errors.

### MiniStack examples

All example tests can use the standalone
[MiniStack shim](../contrib/ministack_boto3.py) through the optional example
runner. Load it with `-p contrib.pytest_examples` and add `--ministack`; no AWS
credentials or member role profiles are needed. For a
same-account run without Config:

```bash
export MINISTACK_ACCOUNT_ID=111111111111
# Set the resource inputs needed by your chosen example, such as SOURCE_ENI.
env -u AWS_PROFILE -u AWS_DEFAULT_PROFILE \
python -m pytest -p contrib.pytest_examples examples/test_network.py \
  --run-aws --ministack --aws-region eu-west-2 \
  --aws-endpoint-url http://localhost:4566 --config-mode off
```

The shim signs requests with the 12-digit account ID as the access key and a
dummy secret. The examples pass both its sessions and its endpoint into
`RuleBuilder`: a bare shim session does not carry the endpoint itself. The usual
STS account checks still run for live topology and probes.

| Setting | MiniStack behavior |
| --- | --- |
| Endpoint | `--aws-endpoint-url`, then `MINISTACK_ENDPOINT`, then `AWS_ENDPOINT_URL`, then `http://localhost:4566` |
| Region | The examples' `--aws-region` option, including its usual environment/default values |
| Central RA account | `MINISTACK_ACCOUNT_ID`; default `000000000000` |
| Resource account | `NETWORK_ACCOUNT_ID`, then legacy `CONFIG_SOURCE_ACCOUNT`, then the central MiniStack account |
| Member sessions | Created through the shim for the resource account and `ACCOUNT_A` / `ACCOUNT_B`, when supplied |
| Config reader | Central session by default; set `MINISTACK_CONFIG_ACCOUNT_ID` for a separate reader account |
| Config mode | Unchanged: `required` needs `CONFIG_AGGREGATOR` and `CONFIG_AGGREGATOR_REGION`; use `--config-mode off` deliberately when appropriate |

For organization examples, set `ACCOUNT_A` and `ACCOUNT_B` plus their resource
inputs. Set `MINISTACK_ACCOUNT_ID` to the account holding the central analysis
context. `NETWORK_ACCOUNT_PROFILES` and `CONFIG_PROFILE` are unused in this mode;
an explicit `--aws-profile` conflicts with `--ministack`. Unset `AWS_PROFILE` and
`AWS_DEFAULT_PROFILE` as shown so boto3 does not try to load a local profile.
Without `--ministack`, examples retain the normal AWS credential/profile behavior.

The resources must already exist in MiniStack. `--ministack` does not deploy
templates, seed inventory or grant permissions. It also does not enable tests
on its own: `--run-aws` is still required, and Lambda examples additionally need
`--allow-probe-writes` with literal `allow_write=True` inside the test. SSM
examples need `--allow-ssm-commands` and a managed node with the required runtime.
Unsupported APIs or incomplete analysis results remain errors; this adapter does not supply
a reachability engine or establish emulator compatibility.

## Diagnostics and lifecycle

```python
result = rule.eni("eni-app").can_reach("10.47.1.1", port=443)
assert result, result.message

import json

print(json.dumps(result.evidence, default=str, indent=2))
```

False means an evaluated predicate was unsatisfied. AWS errors, unknown scope,
unsupported conditions, missing prerequisites and timeouts raise.
`cannot_reach()` only reverses a conclusive answer. Missing-information and
unsupported-analysis codes, including ambiguous `NO_PATH`, cannot pass an
isolation assertion. `AnalysisError` and `AnalysisTimeoutError` expose
`.evidence` and path/analysis IDs. AWS permission and transport exceptions
retain their boto3/botocore types.

Set `keep_analysis=True` for console inspection. Otherwise cleanup is attempted
after success or failure with the creating central credentials. Cleanup problems
emit `CleanupWarning` with IDs without replacing the original error. A polling
timeout does not cancel an AWS analysis; SDK retries, HTTP calls and cleanup
can add time beyond the polling `timeout`.

RA models configuration and sends no packets. It does not test application
listeners or host firewalls. AWS documents forward-only TCP analysis through
TGW route tables; test reverse direction where needed and retain those limits.

## Project structure and extension

| File | Responsibility |
| --- | --- |
| `src/aws_network_asserts/builder.py` | Fluent account/region views, selectors, topology checks |
| `src/aws_network_asserts/accounts.py` | Lazy profiles/sessions and STS account verification |
| `src/aws_network_asserts/clients.py` | Service/region endpoints and client reuse |
| `src/aws_network_asserts/inventory.py` | Aggregator snapshots and scoped discovery |
| `src/aws_network_asserts/reachability.py` | Endpoint ARNs, RA lifecycle and conclusive results |
| `src/aws_network_asserts/routes.py` | Complete-range VPC route evaluation |
| `src/aws_network_asserts/probe.py` | Explicit temporary Lambda lifecycle and TCP results |
| `src/aws_network_asserts/probe_security_group.py` | Optional security group discovery, creation and dependency cleanup |
| `src/aws_network_asserts/probe_role.py` | Optional IAM execution role and safe cleanup |
| `src/aws_network_asserts/_probe_handler.py` | Standard-library code uploaded to the Lambda |
| `src/aws_network_asserts/result.py` | Truth-testable assertion results |
| `src/aws_network_asserts/errors.py` | Evaluation errors |
| `tests/` | Offline library and SDK contract checks |
| `examples/` | Opt-in network, organization and cross-region tests |
| `contrib/pytest_examples.py` | Optional pytest runner and fixtures for these examples |

To add an assertion, add a terminal method to a selector, read the AWS API and
return `CheckResult`. Reuse `_context()` and `_decorate()` for provenance. Raise
for unknown data; return false only after evaluating the predicate. Add focused
Stubber cases for real request shapes and meaningful failure boundaries. There
is no provider registry or background service.

## Primary references

- [Organizations and cross-account RA](https://docs.aws.amazon.com/vpc/latest/reachability/multi-account.html)
- [Boto3 credentials and assume-role profiles](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html)
- [SDK service-specific endpoints](https://docs.aws.amazon.com/sdkref/latest/guide/feature-ss-endpoints.html)
- [Config multi-account/multi-region aggregation](https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html)
- [Aggregate configuration API](https://docs.aws.amazon.com/config/latest/APIReference/API_GetAggregateResourceConfig.html)
- [RA behavior and limitations](https://docs.aws.amazon.com/vpc/latest/reachability/how-reachability-analyzer-works.html)
- [IP destinations and lifecycle](https://docs.aws.amazon.com/vpc/latest/reachability/getting-started-cli.html)
- [RA explanation codes](https://docs.aws.amazon.com/vpc/latest/reachability/explanation-codes.html)
- [Python standard-library IP networks](https://docs.python.org/3/library/ipaddress.html)
- [Subnet route tables](https://docs.aws.amazon.com/vpc/latest/userguide/subnet-route-tables.html)
- [VPC route priority](https://docs.aws.amazon.com/vpc/latest/userguide/route-tables-priority.html)
- [TGW propagation API](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/get_transit_gateway_route_table_propagations.html)
- [Shared VPC permissions](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-share-limitations.html)

See [historical validation notes](validation.md); current checks must be run against the current source.

## Coverage, protocol probes and convergence

See [advanced checks](advanced-checks.md) for full public contracts and examples
covering TLS/HTTP/DNS, source context, sampling thresholds, explicit batch
contexts, TGW association and forward/return routing, `CoverageCase`,
`CoverageMatrix`, `wait_for()`, `isolation_with_control()`, and JSON-compatible
`CheckResult.to_dict()` reports. All live-probe entry points require literal
`allow_write=True`; topology and report helpers do not provision resources.

## Population, execution plans and new probe sources

The [expectation guide](expectations.md#verify-what-discovery-found) covers
`contain_exactly_resources()`, `reach_each()` with finite port lists, read-only
`.plan()`, and the `max_ra_analyses` execution cap. The cap includes timing
wrapper attempts and is checked across the entire declaration before execution.
Planning does not resolve discovery, guarantee AWS acceptance or estimate price.

Use `.consistently(checks=..., interval=...)` for consecutive fresh successes;
`consistently(callback, checks=..., interval=...)` offers the same behavior for
direct checks. A failed sample returns failure immediately; errors propagate.

`instance(id).ssm_probe_session(allow_write=True)` runs the protocol methods and
matchers on an existing managed Linux instance. Its source is the host under the
SSM execution user, not necessarily the application's user/container. Read the
[SSM guide](ssm-probes.md) before running commands.

Lambda deployment methods accept `cleanup_manifest=path` for a durable private
record. Use a fresh path for each deployment and keep it after the test. See
[recovery](recovery.md) for dry-run inspection and explicit cleanup.

`have_appliance_mode()`, `have_firewall_endpoints()` and
`have_bidirectional_routes()` add the [inspection topology checks](inspection-checks.md).
Their direct equivalents return ordinary `CheckResult` values. They complement
modeled and observed paths; they do not establish end-to-end inspection.
