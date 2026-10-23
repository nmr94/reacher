# API surface for custom endpoints

The library calls boto3 clients directly. Endpoint overrides use the same service
request shapes as AWS; an emulator needs to implement the subset exercised by
its tests. An unimplemented API raises its original error. The
[expectation API](expectations.md) delegates to these same checks; it does not
supply a second analysis or invocation engine.

| Function | boto3 client and operations | Credential context |
| --- | --- | --- |
| Aggregated Config snapshot | `config.get_aggregate_resource_config` | Central Config |
| Aggregated resource IDs | `config.list_aggregate_discovered_resources` | Central Config |
| Member account identity | `sts.get_caller_identity` | Selected member profile/session, or verified central fallback |
| Packet reachability | `ec2.create_network_insights_path`, `start_network_insights_analysis`, `describe_network_insights_analyses` | Central analysis |
| Analysis cleanup | `ec2.delete_network_insights_analysis`, `delete_network_insights_path` | Central analysis |
| Subnet route table | `ec2.describe_route_tables`; `describe_subnets` for main-table inheritance | Member |
| VPC route table | `ec2.describe_route_tables` | Member |
| Prefix-list routes | `ec2.get_managed_prefix_list_entries` | Member |
| Peering | `ec2.describe_vpc_peering_connections` | Source VPC owner |
| TGW propagation | `ec2.describe_transit_gateways` for scoped owner verification; `describe_transit_gateway_route_tables`, `get_transit_gateway_route_table_propagations` | TGW owner |
| TGW association / effective routes | `ec2.describe_transit_gateways`, `describe_transit_gateway_route_tables`, `describe_transit_gateway_attachments`, `get_transit_gateway_route_table_associations`, `search_transit_gateway_routes`, `get_transit_gateway_prefix_list_references`; prefix-list reads when needed | TGW owner |
| TGW attachment | `ec2.describe_transit_gateway_attachments` | TGW owner |
| ENI membership or subnet ENI list | `ec2.describe_network_interfaces` | Selected owner |
| Explicit protocol probe source discovery | `ec2.describe_subnets` | Selected account, STS verified |
| Workload-derived probe source | `ec2.describe_network_interfaces`; `describe_instances` for an instance selector; `describe_subnets` | Workload owner, STS verified |
| Explicit probe deployment/readiness | `lambda.create_function`, `get_function_configuration` | Selected account, STS verified |
| Explicit probe invocation/cleanup | `lambda.invoke`, `delete_function` | Same selected account as creation |
| Optional temporary execution role | `iam.create_role`, `put_role_policy`, `delete_role_policy`, `delete_role` | Same verified selected account as Lambda |
| Safe temporary role cleanup | `ec2.describe_network_interfaces` (paginated) | Same verified account, selected resource region |
| Optional temporary security group | `ec2.describe_subnets`, `create_security_group`, `describe_security_groups`, `delete_security_group` | Same verified selected account/region as Lambda |

The public builder uses an aggregator whenever Config is enabled. Aggregate
requests always target `config_region`; source account and resource region are
explicit request fields. The internal `ConfigInventory` class retains regional
`get_resource_config_history` and `list_discovered_resources` support for direct
use, but the builder does not silently fall back to regional inventory.

Account-scoped live clients verify STS identity before creating an EC2 or Lambda client.
An emulator must return the requested 12-digit account in `Account` and include
resource owner fields in scoped topology responses. Unscoped `config_mode="off"`
topology checks preserve standalone single-session behavior without the identity call.
Lambda probes always require an explicit account and identity verification.

Standard role profiles cause boto3's credential provider to call STS
`AssumeRole` and refresh the credentials. This is outside the library's explicit
client factory. To redirect that request, configure `AWS_ENDPOINT_URL_STS` or
the SDK profile's service endpoint settings. Library `endpoint_urls` options
alone do not redirect profile-internal credential requests.

All list operations consume the boto3 paginator or explicit continuation pages, so implement pagination tokens
and complete collections. Return an explicit empty list for a valid empty
result. Missing collections and missing decisive state fields are evaluation
errors. Config configuration fields remain JSON strings with Config's native
lowerCamelCase keys. They are not assumed to match EC2's response schema.

## Analyzer contract

The create request selects `Source` and `Protocol`. `FilterAtSource` contains
the requested destination IP and port range, with optional source IP/port.
For a resource destination, `Destination` is also set. For a plain IPv4
destination, `Destination` is omitted.

Account-scoped resource IDs become EC2 ARNs for both endpoints. The central
analysis credentials create and delete the objects even when endpoint owners
have member profile mappings. A destination selector contributes its account
and region; a plain destination ID string inherits the source account. Passing
an explicitly different region fails before analysis.

Start must return a valid analysis ID and the created path ID. Missing or
contradictory path identity raises without deleting an untrusted analysis ID.
Polling consumes all response pages and validates the returned analysis ID and
any supplied path ID before using the result. `keep_analysis` accepts only a
boolean, so a string such as `"False"` cannot silently retain resources.

Start returns an analysis ID and status. The supported status values are
`running`, `succeeded`, and `failed`. A succeeded result must contain a boolean
`NetworkPathFound`. `failed`, missing results, and known unsupported/unknown
explanation codes raise; they cannot pass `cannot_reach()`.
Reported analysis filters must be empty, and echoed additional accounts must
match the request. A changed scope cannot establish the requested denial.
Both forward and return `AdditionalDetails` are checked: unknown codes and
omitted/assumed inspection raise for positive and negative checks. The known
AZ-crossing, forward-only/return-route informational and appliance-mode advisory
codes retain their documented limited meaning.

`can_reach(..., through=[component_id_or_arn], avoiding=[...])` adds positive
forward-path requirements. These options need an explicit resource destination;
IP-only targets and `cannot_reach()` with path constraints are rejected before
analysis. A reachable result must include ordered, continuous forward components
with usable sequence numbers and matching source/destination boundary identities.
Reported `AttachedTo`,
TGW and load-balancer listener identities are included where relevant. IDs and
ARNs must agree. ARN syntax, partition, region, service/resource kind and reported
ownership must match; a bare ID cannot establish an explicit ARN's ownership.
Traffic components such as ENIs, instances and gateways are supported. Security
groups, ACLs and route tables are configuration objects, so inspect their
relationships and routes separately. Any reported warning or explanation, or
malformed or incomplete forward path, prevents constrained success and raises.
A conclusive blocked path returns a failing result for the positive predicate,
with constraints marked unevaluated. Its partial hops establish neither path
coverage nor isolation.

`path_constraints` evidence records required/forbidden components, the reported
forward hops and evaluated result. These checks describe AWS's modeled forward
path, not packet observation or TCP return traffic. A route-table `via=` check is
a different claim. `explanations` retains the reported code, path/direction and
resource roles beside plain-language blocker summaries; unknown codes retain
AWS's code rather than receiving a guessed cause.

SDK exceptions and interruptions retain diagnostic `.evidence` where the
exception permits attaching attributes. Diagnostic handling never replaces the
original error, including exceptions exposing read-only attributes.

The SDK `ClientToken` values are unique per operation. Tests stub these tokens
with `botocore.stub.ANY`. Paths and analyses are independent between calls, which
avoids stale answers when tests change infrastructure.
`cleanup` records path and analysis status separately. A deletion response must
return the requested native ID before that object's status becomes `deleted`.
Missing or contradictory deletion identity records `unconfirmed` and warns;
cleanup still attempts the other owned object and preserves an earlier error.
Explicit `keep_analysis=True` records confirmed objects as `retained`.

Implementing the response shape alone is sufficient for unit-test doubles. To
use an emulator for meaningful network assertions, it must also calculate the
network behavior it reports. The included tests verify library/API contracts
and known routing cases, not a third-party emulator's analysis engine.

## Lambda probe contract

The public `SubnetRule.probe_tcp()` call requires `allow_write=True` on that
individual call, an explicitly selected account, an execution role ARN in that
account/partition or `auto_create_execution_role=True`, and either one to five
security groups or `auto_create_security_group=True`. Each automatic option is
mutually exclusive with its explicit counterpart. Validation and the write
gate precede AWS calls. Config evidence follows the usual subnet selector rules.

`CreateFunction` uploads a standard-library Python 3.12 ZIP with handler
`probe_handler.handler`, a unique `aws-network-asserts-<uuid>` name, 128 MiB of
memory, a 15-second function timeout, and `Publish=False`. `VpcConfig` contains
exactly the selected subnet and the supplied or auto-created security groups. AWS validates
access to those VPC resources. A successful creation response must confirm the
requested function name before invocation or deletion is authorised. An IAM role and inline policy are provisioned only
when `auto_create_execution_role=True`. A security group is provisioned only
when `auto_create_security_group=True`; no other network resources are provisioned.
For protocol deployments with `address_family="ipv6"` or `"dual"`, `VpcConfig`
additionally contains `Ipv6AllowedForDualStack=True`. Source discovery must
confirm an IPv4 subnet CIDR and at least one associated IPv6 CIDR before any
creation. IPv6-native-only subnets are rejected. Default IPv4 creation requests
omit the flag.

`GetFunctionConfiguration` is polled until `State="Active"`. Only `Pending`
is retried. Failed, inactive, unknown or missing states raise. `Invoke` uses
`InvocationType="RequestResponse"` and `LogType="None"`. The JSON payload contains
`host`, `port` and `connect_timeout`; a DNS hostname is resolved inside the VPC.
A successful SDK HTTP response alone is insufficient: `FunctionError`, malformed
JSON, missing/mismatched destination fields or an unknown observation raise.

The handler returns `outcome`, `resolved_ip`, `port` and `elapsed_ms`. An outcome
of `connected` passes; `refused`, `timeout` and `unreachable` fail the positive
connection test. DNS and unexpected socket errors are function execution errors.
The basic default TCP call tests only the first IPv4 address and one handshake.
Address-family, sampling, source and destination-constraint options select the
protocol runtime described below.
An emulator must actually execute the function in the intended network context
to establish observed connectivity; a fabricated response tests only contracts.

`DeleteFunction` runs in `finally` once creation has returned successfully,
using the same account/region client. No published version or retained-function
option exists. Cleanup failures emit `CleanupWarning`, retain the original
error if present, and provide the function name/region. Function deletion is not
synchronous deletion of AWS-managed Hyperplane ENIs. Full operational details,
including lost responses and process interruption, are in the
[live probe guide](live-probes.md).

### Optional execution-role lifecycle

IAM operations use `_live_client("iam")` with the same account verification and
inherited endpoints/transport as Lambda. The role is global in that account and
partition. `CreateRole` uses the unique function name, Lambda-only trust, and
`PutRolePolicy` installs `VpcNetworkInterfaces` with just the six EC2 VPC ENI
permissions; no managed policies or log permissions are attached.
The response must confirm the exact requested role name and account/partition
ARN before policy installation or deletion is authorized. Contradictory identity
stays unconfirmed and warns; cleanup does not delete that role by name.

New-role visibility (`PutRolePolicy` returning `NoSuchEntity`) and recognized
Lambda role-assumption/ENI-permission propagation rejections are retried within
a shared `ready_timeout` budget. Other AWS failures keep their original types.
Existing-role calls make no IAM calls and retain their existing retry behavior.

After `DeleteFunction` succeeds, `DescribeNetworkInterfaces` polls filters for
the selected subnet, `interface-type=lambda`, and the specified security groups.
Every page is consumed. Because the group filter is OR, each returned group set
is checked for exact equality. Missing collections/metadata cannot establish
that cleanup is safe. Shared ENIs may keep the role alive until
`role_cleanup_timeout` expires (default 1200 seconds).

Only after no matching ENIs remain does cleanup call `DeleteRolePolicy`, then
`DeleteRole`. A retry after a role-deletion conflict also retries deletion of its
own inline policy, covering late policy visibility after an earlier not-found.
IAM deletion conflicts/concurrent changes are retried within the
same cleanup budget; already-absent items are tolerated. A partial setup failure
rolls back the successfully created role if no function could depend on it.
An unconfirmed function creation/deletion retains the role, as do ENI read
failures/timeouts. Cleanup failures emit `CleanupWarning`, preserve an earlier
error, and record `temporary_role` names/status/reasons in evidence. The library
never modifies a pre-existing role or deletes a role without confirmed creation.

### Optional security-group lifecycle

`DescribeSubnets(SubnetIds=[selected_id])` discovers the live VPC. All pages are
consumed. Exactly one matching, available subnet with a VPC and valid owner ID
is required. A shared subnet's owner can differ from the selected account.

`CreateSecurityGroup` receives that `VpcId`, the unique function name as
`GroupName`, and `TagSpecifications` tagging the security group with
`aws-network-asserts:probe=<name>`. The caller also needs `ec2:CreateTags` for
tag-on-create. No ingress or egress rule APIs are called: AWS's initial no-ingress
and allow-all outbound rules apply. No existing groups or rules are changed.

`DescribeSecurityGroups(GroupIds=[created_id])` consumes all pages and confirms
the ID, selected-account owner and VPC before Lambda creation. Only not-found
errors or explicit empty collections are retried for this new group, within a
separate `ready_timeout` budget. Incomplete/contradictory metadata and permission
errors raise. New group Config recording is not a prerequisite.
If a nonempty discovery response contradicts the created ID, VPC, owner or
reported name, the group identity becomes unconfirmed. Its reported metadata
is retained for investigation, and deletion is not authorized. A normal
visibility timeout or read error still permits rollback of the returned ID.

After function deletion, `DeleteSecurityGroup(GroupId=created_id)` retries
`DependencyViolation` within `security_group_cleanup_timeout` (default 1200
seconds). A previously visible group reporting `InvalidGroup.NotFound` is
already deleted; for a never-visible group that error is retried because of
eventual consistency. An explicit false/mismatched deletion response is an
error. Cleanup never deletes by group name or follows a lost creation response
with a search that could select an existing group.

With both options, successful group deletion replaces the role cleanup's ENI
enumeration: AWS prevents deletion while ENIs use the group. The role's inline
policy/role are removed after the group. If group cleanup is unconfirmed after
Lambda creation, the role is retained for ENI cleanup. A partial setup failure
before possible Lambda creation still permits independent unused-role cleanup.
Both resource statuses and reasons remain in `temporary_security_group` and
`temporary_role` evidence; cleanup warnings do not replace an earlier error.

A creation error reporting SDK retries, a timeout, server error or conflict
retains dependencies for a possibly created function. Even a final 4xx rejection
after retries does not prove that an earlier attempt failed. Such errors and
unconfirmed creation responses record `cleanup="creation_unconfirmed"`; resources
are identified for investigation rather than deleting an unknown function.
The same uncertainty classification applies to IAM and security-group creation.
A definitive rejection requires a valid 4xx status and zero SDK retries;
unknown or contradictory transport metadata stays unconfirmed. Unconfirmed
creation warns with the attempted name or ARN, even when no dependent resource
has been created.

## Protocol sessions and application observations

`SubnetRule.probe_tls()`, `probe_http()`, `probe_dns()` and `probe_session()`
reuse the write gate and optional role/group lifecycle above. A session validates
one live available subnet via `DescribeSubnets(SubnetIds=[id])`, requiring its
matching ID, valid owner, VPC and Availability Zone. Shared subnet owners may
differ from the verified deployment account. The session creates one function;
checks refresh Config provenance and invoke fresh observations. Cleanup occurs
when the explicit context exits, in the same function/group/role order above.

The application ZIP contains `probe_handler.py` and `application_handler.py`.
Invocations remain `RequestResponse` / `LogType="None"`. DNS requests contain
`kind="dns"` and `host`, plus `address_family` for IPv6 or dual queries.
IPv4 queries use `AF_INET`; IPv6 queries use `AF_INET6`; dual queries resolve
both independently. Responses require a nonempty, distinct, valid `addresses`
list, a finite nonnegative `dns_ms`, and coherent family information when
provided. The consumer records canonical `addresses_by_family`. Every requested
family must have an answer; empty/missing families raise rather than falling
back. Scoped or IPv4-mapped IPv6 addresses cannot establish family coverage.
TCP/TLS/HTTP requests contain `kind`,
`resolved_ip`, `port`, socket timeouts, TLS name/CA options, and HTTP path/Host/
method/body-search options. They connect to the resolved IP with the original
host name preserved for TLS and HTTP. DNS is resolved once per terminal call;
every address/attempt then uses a fresh connection invocation. IPv6 connections
use `AF_INET6` with a four-part socket address. HTTP preserves bracketed IPv6
literal Host headers and continues verifying the intended TLS name.

`expected_addresses` and `allowed_destination_cidrs` validate that one resolved
set before any connection invocation. An unexpected but valid set returns a
failing result with empty attempts/tested addresses. A matching set is pinned
as literal connection destinations; subsequent DNS changes cannot redirect those
invocations. Separate standalone DNS and connection calls still resolve
separately. `address_mode="any"` and `"first"` operate per family, so successful
IPv4 cannot mask failed IPv6. For attempted connection checks, `family_results`
records each requested family's address results. Terminal calls may narrow a dual deployment's family, but may
not enable a family absent from its deployment configuration.

Responses must identify the requested kind/IP/port, a known kind-appropriate
outcome and finite nonnegative `elapsed_ms`. Successful observations include
`source_ip` and `source_port`; TLS success additionally includes `tls_version`
and a 64-character lowercase `certificate_sha256`. HTTP success includes an
integer `status` and, when body matching is requested, boolean `body_matches`
and `body_truncated`. Evidence retains DNS, selected source context, per-address
and per-attempt results, timings, and a shared deployment/cleanup record.
`CheckResult.to_dict()` snapshots that evidence into JSON-compatible values,
including native Config datetimes and nested results.
Explicit protocol-inapplicable options are rejected before evaluation. TCP
cannot accept TLS settings, read timeouts or HTTP criteria; TLS cannot accept
HTTP criteria; plain HTTP cannot accept TLS name/CA settings. Omitting these
options preserves each protocol's defaults.

The handler sends only GET/HEAD, does not follow redirects, and reads at most
`max_body_bytes+1` bytes for a requested substring. It returns no response body.
A nonmatching truncated body raises because absence is unknown. TLS uses
`ssl.create_default_context()` and hostname verification; no verification bypass
is supported. DNS/function execution/malformed-response errors raise rather than
becoming negative reachability evidence. Compatibility doubles must implement
these semantics, not just return a successful outcome string. See the
[advanced guide](advanced-checks.md) for options, sampling limits and source claims.

### Workload-derived source contract

`eni(id).probe_session(...)` and `instance(id).probe_session(...)` resolve source
configuration after the literal write gate and before deployment. Instance
lookup consumes all `DescribeInstances(InstanceIds=[id])` reservations, verifies
the reservation owner and matching running instance, then selects its sole ENI
or the explicitly supplied `network_interface_id`. An incomplete or ambiguous
interface list raises. ENI lookup consumes all
`DescribeNetworkInterfaces(NetworkInterfaceIds=[id])` pages and requires the
matching, in-use interface, selected account owner, complete subnet/VPC/AZ and
one to five distinct group IDs. Instance ENIs must also confirm the selected
instance's attached state. Those groups replace the deployment settings; group
overrides and automatic group creation are rejected.

Live subnet metadata must agree with the discovered workload. Every terminal
check re-reads the instance/ENI identity, attachment and source configuration;
drift raises `ProbeError` before protocol invocation. Native IPv4/IPv6 address
fields must establish the requested families at entry and the selected family
before each check. A workload without IPv6 addresses cannot supply an IPv6
source claim merely because its subnet is dual-stack. Config evidence refreshes
for the workload and derived subnet under the usual mode rules. Deployment and
result evidence include `source_workload`; `source_context` still identifies a
separate Lambda with `host_firewall_tested=False`. No instance process, existing
interface IP, application identity or host firewall is reproduced.

VPC routes with contradictory target fields raise rather than satisfying `via`
against one arbitrary field. The documented instance/network-interface target
alias pair remains supported.

## TGW effective routes and associations

`TGW.route_table(id)` first validates `DescribeTransitGateways` owner/state and
`DescribeTransitGatewayRouteTables` gateway/table identity and available state.
Account-scoped propagation also verifies the live TGW owner and exact route-table
identity before examining propagations. `has_association()` additionally describes the selected attachment, validates
its `TransitGatewayOwnerId`, and consumes every association page filtered by
`transit-gateway-attachment-id`. Association identity must agree with the
attachment; VPC `ResourceOwnerId` can differ from the selected TGW owner.

`has_route_to()` sends two `SearchTransitGatewayRoutes` requests with
`TransitGatewayRouteTableId`, `MaxResults=1000` and filters
`route-search.supernet-of-match` / `route-search.subnet-of-match` containing the
normalised requested CIDR. Each consumes `NextToken` pages, rejects repeated or
malformed tokens, and requires `Routes` plus boolean `AdditionalRoutesAvailable`.
Additional results without a continuation token raise as incomplete coverage.
Use current boto3/botocore models for service-supported pagination; older models
can reject continuation-token requests rather than silently skipping them.

`GetTransitGatewayPrefixListReferences` independently consumes all references
and validates table identity, prefix-list owner, available state and boolean
`Blackhole`; references need not be visible in CIDR-filtered searches.
Routes are deduplicated, prefix lists expanded with all entry pages, and entire
IPv4/IPv6 ranges evaluated using interval boundaries. Longest-prefix selection
and exposed route precedence apply. Selected active routes need usable attachment
IDs; selected blackholes fail. Unavailable BGP ordering for conflicting
same-priority routes raises. Multi-attachment routes satisfy `via` only if every
possible member matches. Paired forward/return checks evaluate two explicit
tables and same-family destination/source CIDRs in the same account/region/TGW. They preserve
both results and do not claim packet reachability or infer associations.

## Source references

- [boto3 EC2 operations](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2.html)
- [boto3 Config operations](https://docs.aws.amazon.com/boto3/latest/reference/services/config.html)
- [boto3 AssumeRole profiles](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html#assume-role-provider)
- [SDK service endpoint settings](https://docs.aws.amazon.com/sdkref/latest/guide/feature-ss-endpoints.html)
- [AWS documented IP-only path request](https://docs.aws.amazon.com/vpc/latest/reachability/getting-started-cli.html)
- [AWS explanation-code semantics](https://docs.aws.amazon.com/vpc/latest/reachability/explanation-codes.html)
- [AWS additional-detail semantics](https://docs.aws.amazon.com/vpc/latest/reachability/additional-detail-codes.html)
- [Delete analysis response](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkInsightsAnalysis.html)
- [Delete path response](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkInsightsPath.html)
- [boto3 Lambda CreateFunction](https://docs.aws.amazon.com/boto3/latest/reference/services/lambda/client/create_function.html)
- [boto3 Lambda Invoke](https://docs.aws.amazon.com/boto3/latest/reference/services/lambda/client/invoke.html)
- [Lambda VPC permissions and ENI lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html)
- [IAM role creation](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/create_role.html)
- [IAM inline role policies](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/put_role_policy.html)
- [IAM role deletion prerequisites](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/delete_role.html)
- [EC2 security group creation](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/create_security_group.html)
- [EC2 security group deletion dependencies](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/delete_security_group.html)
- [EC2 eventual consistency](https://docs.aws.amazon.com/ec2/latest/devguide/eventual-consistency.html)
- [Security group rule defaults](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)

- [TGW route search and pagination](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/search_transit_gateway_routes.html)
- [TGW table associations](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/get_transit_gateway_route_table_associations.html)
- [TGW route evaluation](https://docs.aws.amazon.com/vpc/latest/tgw/transit-gateway-centralized-router.html)
- [Python TLS defaults](https://docs.python.org/3/library/ssl.html#ssl.create_default_context)
- [Python HTTP response handling](https://docs.python.org/3/library/http.client.html)
- [TGW prefix-list references](https://docs.aws.amazon.com/boto3/latest/reference/services/ec2/client/get_transit_gateway_prefix_list_references.html)

## Coverage, inspection, recovery and SSM additions

Population matching, matcher construction and `.plan()` are local. Planning
preflights the complete declaration without opening clients. The plan's maximum
RA count multiplies sources, destinations, finite ports and timing-wrapper
attempts. An execution cap is checked before the first case. Each actual case
and stability sample still creates a fresh RA lifecycle; no result is cached.

Subnet route selection requires complete active native association evidence,
including IDs, table identity, Main and AssociationState. Main-table fallback
verifies the live subnet ID, VPC, availability and owner. Contradictory explicit
associations cannot authorize fallback. Returned route-table IDs must match.

Inspection uses `ec2.describe_transit_gateway_vpc_attachments` (all pages), current
TGW owner verification, `describe_vpcs`, `describe_subnets` and
`network-firewall.describe_firewall`. Native VPC attachments contain VpcOwnerId;
TGW ownership comes from the gateway read. Ready firewall layouts require exact
AZ/subnet membership and complete native readiness/synchronization evidence.
Paired routes reuse existing VPC/TGW effective route evaluation.

SSM uses the verified selected account for EC2 instance/ENI reads,
`ssm.describe_instance_information`, `send_command`, `get_command_invocation` and
`cancel_command`. Commands use AWS-RunShellScript with the packaged in-memory
Python handler, never arbitrary caller shell. An invocation must match its
command/instance identity, nonce and handler/request hashes, and contain complete
protocol/source evidence; native Success alone cannot pass. Unknown sends and
SDK retries remain explicitly unconfirmed. See the [SSM contract](ssm-probes.md).

Optional Lambda manifests record intent before creation, strong confirmed
identities afterward and cleanup stages. Recovery verifies STS, native function,
group and role identities and dependencies before deletion; it never adopts an
object by name. Role checks read IAM policies/attachments/profiles and
`ec2.describe_regions`, then paginate `lambda.list_functions` with
FunctionVersion=ALL in all enabled regions. Missing visibility retains resources.
See [recovery](recovery.md) for operations, partial progress and timeout limits.
