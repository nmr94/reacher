# AWS organization setup and permissions

This package uses existing boto3 identities. It creates temporary execution roles and security groups only
when their individual Lambda probe options are enabled with `allow_write=True`.
It does not enable AWS Config or change AWS Organizations settings. Reachability checks create temporary Network Insights
paths and analyses; topology and Config checks use read APIs.

## Starting configuration

1. Enable AWS Config recording for the resource types your tests select, in each
   source account and Region. Configure an [organization aggregator][config-aggregation]
   and wait for its configuration items to arrive.
2. Configure a central boto3 profile or session in the management account or an
   eligible Reachability Analyzer delegated administrator account. Complete the
   Organizations integration described below before cross-account analyses.
3. Grant that central identity the Reachability Analyzer permissions below and
   access to the aggregator. If the aggregator is in another account, supply
   `config_profile_name` or `config_session` for its reader identity instead.
4. For live topology checks, optionally map member account IDs to profiles with
   EC2 read access using `account_profiles`, or provide `account_sessions`.
5. Set `config_aggregator` to the aggregator's name, `config_region` to its Region,
   and choose the resource account with `account_id` or `.in_account(...)`.

### Which credentials each operation uses

| Operation | Credentials | Region |
| --- | --- | --- |
| Create, start, poll, and delete a reachability analysis | Central `profile_name` or `session` | Selected resource Region |
| Read aggregated AWS Config inventory | `config_profile_name` or `config_session`; defaults to central credentials | Fixed `config_region` |
| Read live EC2 topology | Selected account's `account_profiles` or `account_sessions` entry | Selected resource Region |
| Validate the live account with STS `GetCallerIdentity` | The same credentials selected for the live EC2 read | Selected resource Region |

Account scoping never switches the central analysis identity. It qualifies
resource IDs as account-specific ARNs and scopes aggregator lookups. Named member
profiles are loaded only when a live topology check needs them. Config-only
checks and centralized reachability analyses do not require member profiles.

Without a mapping, a live check can reuse the central session only when
`GetCallerIdentity` confirms that its account matches the selected account.
A mismatched identity raises `AccountMismatchError` before EC2 topology calls.
Successful identity checks are reused per session and Region.

## Named profiles and role assumption

The [profile setup](usage.md#assume-a-role-through-a-standard-boto3-profile)
shows standard `role_arn` / `source_profile` profiles for member-account reads.
Configure the central `org-network-admin` profile and optional `org-config-reader`
using your normal SSO or credential provider. Replace the illustrative account
IDs, role names and regions with your organization's values, and complete any
required login before running pytest.

```python
rule = RuleBuilder(
    profile_name="org-network-admin",
    config_profile_name="org-config-reader",  # Omit to reuse the central profile.
    config_aggregator="organization-network",
    config_region="eu-west-2",
    region_name="eu-west-2",
    account_profiles={
        "111111111111": "production-network-read",
        "222222222222": "shared-network-read",
    },
)
production = rule.in_account("111111111111")
```

Member role profiles use [boto3's AssumeRole credential provider][boto-credentials],
which caches and refreshes temporary credentials. The package keeps those boto3
sessions; it does not copy STS response keys into static sessions. The source
identity must be permitted to assume each target role, and the target role's
trust policy must admit the source identity. Existing workload-role or federated
sessions can be supplied directly instead of named profiles.

## Reachability Analyzer permissions

AWS's managed
[AmazonVPCReachabilityAnalyzerFullAccessPolicy][ra-policy] is a convenient starting
point. Its commercial-partition ARN is:

```text
arn:aws:iam::aws:policy/AmazonVPCReachabilityAnalyzerFullAccessPolicy
```

For an existing central IAM role, an administrator can attach it from the project
root. Replace `YOUR_ANALYSIS_ROLE` first:

```bash
aws iam attach-role-policy \
  --role-name YOUR_ANALYSIS_ROLE \
  --policy-arn arn:aws:iam::aws:policy/AmazonVPCReachabilityAnalyzerFullAccessPolicy
```

For IAM Identity Center, add the corresponding policies to the permission set
that supplies the relevant credentials. The managed policy is broad; its current
default version, v4, permits analysis lifecycle operations, network-resource
reads, and supporting Tiros calls. AWS explains why granting only the five
directly invoked lifecycle APIs is insufficient in [Required API permissions][ra-permissions].

### Organizations integration

An administrator must first enable [trusted access][ra-trust] with AWS
Organizations and complete its role deployment. AWS creates
`AWSServiceRoleForReachabilityAnalyzer` and the required cross-account roles
through that setup; the package does not create them. The
[service-linked-role documentation][ra-role] describes this integration.

Run cross-account analyses from the management account or an eligible delegated
administrator account, using resource ARNs. The builder generates these ARNs for
account-scoped selectors. In addition to the managed policy, AWS's
[required-permissions guide][ra-permissions] lists these runtime reads:
`organizations:DescribeOrganization`, `organizations:ListAWSServiceAccessForOrganization`,
`organizations:ListDelegatedServicesForAccount`,
`organizations:ListDelegatedAdministrators`, and `organizations:ListAccounts`.
Grant organization setup permissions to the administrator performing setup.

Config aggregation and Organizations integration do not remove Reachability
Analyzer's same-Region restriction. Select accounts independently from Regions;
run an analysis in each Region, and use topology assertions for cross-Region
relationships such as VPC peering. A successful topology check does not prove
cross-Region packet reachability.

## Config aggregator permissions

Attach the included [Config inventory read policy](../iam/config-read-policy.json)
to the aggregator reader identity. When `config_profile_name` / `config_session`
is omitted, this is the central analysis identity:

```bash
aws iam put-role-policy \
  --role-name YOUR_AGGREGATOR_READER_ROLE \
  --policy-name AwsNetworkAssertsConfigRead \
  --policy-document file://iam/config-read-policy.json
```

The policy grants `config:GetAggregateResourceConfig` and
`config:ListAggregateDiscoveredResources`. Replace
`arn:*:config:*:*:config-aggregator/*` with the actual aggregator ARN to narrow
access. Its suffix contains the aggregator **ID**, not its display name. The
[Config authorization reference][config-iam] documents these action mappings and
resource scopes. These grants do not enable recording or create an aggregator.

An aggregator reads replicated inventory from authorized accounts and Regions.
It does not provide source-account EC2 credentials or make live EC2 reads from
the aggregator account on behalf of its members.

## Member roles for live topology reads

Grant the selected member role the EC2 reads needed by its tests:
`ec2:DescribeNetworkInterfaces`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables`,
`ec2:DescribeVpcPeeringConnections`, `ec2:DescribeTransitGatewayAttachments`,
`ec2:DescribeTransitGatewayRouteTables`, `ec2:GetTransitGatewayRouteTablePropagations`,
`ec2:DescribeTransitGateways`, `ec2:GetTransitGatewayRouteTableAssociations`,
`ec2:SearchTransitGatewayRoutes`, `ec2:GetTransitGatewayPrefixListReferences`,
and `ec2:GetManagedPrefixListEntries`. The managed [Reachability Analyzer
policy][ra-policy] covers most of these reads, but its current v4 omits
`GetTransitGatewayRouteTableAssociations` and `GetTransitGatewayPrefixListReferences`.
If using that policy, add the [TGW topology supplement](../iam/tgw-topology-supplement.example.json)
for association and route checks. The central identity's permissions do not grant these actions
to a member role.

Scoped propagation verifies the TGW owner with `ec2:DescribeTransitGateways`
before reading the selected table; grant this read to existing propagation-only
member roles as well.

Scope TGW propagation and attachment assertions to the TGW owner account, even
when the attached VPC belongs to another account. In shared VPCs, enumeration
preserves the `OwnerId` of each ENI so participant resources retain their own
Config scope and Reachability Analyzer ARN.

## Custom endpoints and STS

The package's `endpoint_url` and `endpoint_urls` settings apply to the clients
it creates, including the STS `GetCallerIdentity` client used before live reads.
For an emulator, provide an STS endpoint through the shared `endpoint_url` or an
`endpoint_urls["sts"]` / `endpoint_urls["REGION:sts"]` override, and ensure its
identity response matches the account selected by the test.

Boto3 creates an additional internal STS client when a named profile assumes a
role. The package's endpoint overrides do not configure that credential-provider
client. Set `AWS_ENDPOINT_URL_STS` or configure an STS endpoint in a shared-config
`services` section for the selected role profile when that call must also use a
custom endpoint. [AWS's endpoint guide][sdk-endpoints] documents these settings
and explains that endpoint settings are not inherited from `source_profile`.

[ra-policy]: https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonVPCReachabilityAnalyzerFullAccessPolicy.html
[ra-permissions]: https://docs.aws.amazon.com/vpc/latest/reachability/security_iam_required-API-permissions.html
[ra-trust]: https://docs.aws.amazon.com/vpc/latest/reachability/enable-trusted-access.html
[ra-role]: https://docs.aws.amazon.com/vpc/latest/reachability/using-service-linked-roles.html
[config-iam]: https://docs.aws.amazon.com/service-authorization/latest/reference/list_config.html
[config-aggregation]: https://docs.aws.amazon.com/config/latest/developerguide/aggregate-data.html
[boto-credentials]: https://docs.aws.amazon.com/boto3/latest/guide/credentials.html#assume-role-provider
[sdk-endpoints]: https://docs.aws.amazon.com/sdkref/latest/guide/feature-ss-endpoints.html

## Lambda probe permissions

The explicit `subnet(...).probe_tcp()`, `probe_tls()`, `probe_http()`, `probe_dns()`
and `probe_session()` APIs deploy a temporary Lambda only with `allow_write=True`.
ENI/instance-derived sessions and the [expectation API](expectations.md) keep the
same per-deployment write gate.
Its complete lifecycle runs in the selected account and network region, using
that account's existing profile/session and STS identity verification. Give
these permissions to that identity, which may differ from the central RA and
Config identities. An execution role is created only with the explicit
`auto_create_execution_role=True` option described below.

The [caller policy template](../iam/probe-caller-policy.example.json) grants
`lambda:CreateFunction`, `lambda:GetFunctionConfiguration`,
`lambda:InvokeFunction`, and `lambda:DeleteFunction` for names beginning
`aws-network-asserts-`. It grants `iam:PassRole` for one existing execution role,
conditioned on `iam:PassedToService=lambda.amazonaws.com`, plus the EC2 VPC
validation reads listed by AWS. Replace `REGION`, `ACCOUNT_ID`, the role path/name
and, outside the commercial partition, `arn:aws` before attaching this template.
Existing SCPs, boundaries and organization controls still apply.

Protocol probes and sessions additionally read `ec2:DescribeSubnets` before
deployment to record source VPC/AZ/ownership, including with supplied groups.
The caller template already includes this permission. Derived
`eni(id).probe_session(...)` checks also need `ec2:DescribeNetworkInterfaces`;
`instance(id).probe_session(...)` additionally needs `ec2:DescribeInstances`.
Both caller templates include these reads. They verify current owner,
attachment, subnet/AZ and security groups before deployment and again before
each terminal observation. No SSM command or process execution in the instance
is performed. Config-enabled checks also need the usual workload/subnet records.

IPv6 and dual-stack sessions use the same service permissions. Their selected
subnet must already have IPv4 and associated IPv6 CIDRs; the caller's subnet
read validates those prerequisites. Lambda creation sets
`Ipv6AllowedForDualStack=True`, without altering VPCs, CIDRs, routes or groups.
Supply the existing IPv6 egress/routing policy needed for the target. TLS/HTTP/DNS
use the same execution-role ENI policy, with no extra AWS service permissions. HTTP GET/HEAD
sends application traffic to the exact supplied endpoint; choose endpoints whose
behaviour is appropriate for a test. No credentials or application authentication
are supplied by these probes.

The execution role must trust Lambda:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
```

The [execution policy](../iam/probe-execution-policy.json) grants the six EC2
permissions [AWS documents for VPC ENIs][lambda-vpc]: create, describe and delete
interfaces, describe subnets, and assign/unassign private IP addresses. AWS
requires `Resource: "*"` for the listed VPC execution-role permissions in this
setup. The probe's handler makes no EC2 calls. TCP probes send a handshake; HTTP probes
send the explicit GET/HEAD request described in the
[advanced guide](advanced-checks.md).
This role should be dedicated to probes rather than granting workload secrets
or application access. Administrators can further restrict deployment using
Lambda's `lambda:SubnetIds` and `lambda:SecurityGroupIds` condition keys.

The execution policy omits CloudWatch Logs permissions. If an existing role
permits logging, Lambda may create log groups that remain after function
deletion; the library does not remove those logs. Keep the execution role
available while AWS asynchronously releases its VPC ENIs. The library deletes
its function and, when explicitly requested, its temporary execution role and
security group.
It never deletes shared network interfaces.

See the [live probe guide](live-probes.md) for the per-call permission gate,
readiness and invocation limits, cleanup warnings and result semantics. A
successful probe establishes its requested protocol predicate from the Lambda's
own network context; a failed probe is not an isolation assertion.

[lambda-vpc]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html

### Automatic execution roles

Use `auto_create_execution_role=True` instead of `execution_role_arn` to give each
probe its own temporary role. `allow_write=True` is still required. Attach the
[auto-role caller policy template](../iam/probe-auto-role-caller-policy.example.json)
to the selected account's caller instead of the existing-role caller template.
Replace its `ACCOUNT_ID`, `REGION`, and partition as appropriate.

It adds `iam:CreateRole`, `iam:PutRolePolicy`, `iam:DeleteRolePolicy`, and
`iam:DeleteRole` on `arn:aws:iam::ACCOUNT_ID:role/aws-network-asserts-*`, with
`iam:PassRole` limited to the same prefix and the Lambda service. Its EC2 reads
include
`ec2:DescribeNetworkInterfaces` for workload discovery and safe Lambda ENI
cleanup, plus `ec2:DescribeInstances` for instance-derived sessions. IAM APIs use
the same verified account credentials as the function; central analysis and
Config identities are unchanged. These caller permissions allow role/policy
management under that prefix, so grant them only to the test identity that
should perform those writes. Existing SCPs and permission boundaries can still
prevent creation or policy attachment; their errors propagate.

The created role's trust and inline policy match the documents above. It has no
CloudWatch Logs permissions and no managed policies. No long-lived role is
modified. Cleanup deletes the function first, waits for all matching Lambda
ENIs, then removes the inline policy and role. It retains the role and emits
`CleanupWarning` when safe cleanup cannot finish, including ENIs still in use
by another function. Inspect `temporary_role` evidence for the name/ARN, cleanup
status, error and remaining ENI IDs. Default role cleanup polling is 1200 seconds;
see [the probe guide](live-probes.md#automatically-create-an-execution-role) for
propagation, timeout, and lost-response behavior.

AWS requires the execution role to remain available during ENI removal. Do not
manually delete a retained role until the function and dependent ENIs have been
investigated. [AWS's VPC guidance][lambda-vpc] explains this dependency.

### Automatic security groups

Use `auto_create_security_group=True` instead of `security_group_ids`. The
literal `allow_write=True` requirement is unchanged. The option works with either
an existing execution role or `auto_create_execution_role=True`.

Add the [automatic security-group policy supplement](../iam/probe-auto-security-group-policy.example.json)
to the selected account's existing-role or automatic-role caller policy.
Replace `REGION`, `ACCOUNT_ID`, `VPC_ID`, and the ARN partition as appropriate.
The VPC ARN uses an account wildcard to support a subnet shared by a different
VPC owner; it can be replaced with that owner's ID when known.

The supplement grants `ec2:CreateSecurityGroup` for that VPC and groups carrying
the requested probe tag, `ec2:CreateTags` only during security-group creation,
and `ec2:DeleteSecurityGroup` only for groups tagged
`aws-network-asserts:probe=aws-network-asserts-*`. It also grants
`ec2:DescribeSubnets` and `ec2:DescribeSecurityGroups`. EC2 tags require a separate
`CreateTags` grant even though they are passed through `CreateSecurityGroup`.
These are caller permissions; the Lambda execution role still only needs its
original six ENI permissions. See [EC2 authorization][ec2-authorization] and
[tag-on-create authorization][ec2-tagging].

All security-group operations use the verified selected-account credentials and
selected network region. The live subnet determines the VPC; Config credentials
remain central. The library adds no ingress rules and preserves the new group's
AWS default outbound rules, which allow all outbound traffic. It neither copies
nor edits existing groups. A newly generated source group may need to be allowed
by an existing destination policy for the connection to succeed; the library
never changes that destination policy.

Cleanup deletes the function, then retries security-group deletion while AWS
reports dependencies. With an automatic role, the inline policy and role are
removed after successful group deletion. If function deletion is unconfirmed,
or group cleanup fails/times out, resources are retained with `CleanupWarning`
and diagnostic names/IDs. `security_group_cleanup_timeout` defaults to 1200
seconds; read the [group lifecycle guide](live-probes.md#automatically-create-a-security-group)
for propagation, partial failures, and the separate cleanup evidence fields.

[ec2-authorization]: https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html
[ec2-tagging]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/supported-iam-actions-tagging.html

## SSM commands, inspection reads and recovery

SSM sessions need their own literal `allow_write=True`; command execution is
independent of Lambda deployment permission. The selected account identity uses
`ec2:DescribeInstances`, `ec2:DescribeNetworkInterfaces`,
`ssm:DescribeInstanceInformation`, `ssm:SendCommand`, `ssm:GetCommandInvocation`
and, when needed, `ssm:CancelCommand`. The existing managed node and its profile
are prerequisites, not resources created by a test. See the
[SSM caller policy](../iam/ssm-probe-caller-policy.example.json) and
[SSM guide](ssm-probes.md). RunShellScript permission grants host code execution;
use a dedicated identity scoped to the intended instance.

Inspection checks use `ec2:DescribeTransitGatewayVpcAttachments`, TGW/VPC/subnet
and route reads, and `network-firewall:DescribeFirewall` in their respective
verified owner accounts. See the [inspection read policy](../iam/inspection-topology-policy.example.json).

Recovery is dry-run by default and uses the recorded account/region. In addition
to cleanup permissions, it reads native identities and dependencies. Before role
deletion it reads the role's policies/profiles and lists Lambda functions,
including published versions, across every enabled region. Denied or incomplete
visibility retains the role. The [recovery policy](../iam/probe-recovery-policy.example.json)
and [guide](recovery.md) describe these extra reads and the explicit write gate.
