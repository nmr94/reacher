"""Inspection topology uses current native responses without claiming packet delivery."""

from copy import deepcopy

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from aws_network_asserts import NetworkAssertionError, RuleBuilder

ACCOUNT = "111111111111"
REGION = "eu-west-2"
VPC = "vpc-inspection"
TGW = "tgw-hub"
ATTACHMENT = "tgw-attach-inspection"
FIREWALL = f"arn:aws:network-firewall:{REGION}:{ACCOUNT}:firewall/inspection"
SUBNETS = {f"{REGION}a": "subnet-a", f"{REGION}b": "subnet-b"}


@pytest.fixture
def cloud():
    session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION
    )
    rule = RuleBuilder(session=session, account_id=ACCOUNT, config_mode="off")
    with (
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("ec2", REGION)) as ec2,
        Stubber(rule.clients.client("network-firewall", REGION)) as firewall,
    ):
        yield rule, sts, ec2, firewall
        for stub in (sts, ec2, firewall):
            stub.assert_no_pending_responses()


def identity(sts):
    sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})


def gateway(ec2, **changes):
    ec2.add_response(
        "describe_transit_gateways",
        {
            "TransitGateways": [
                {"TransitGatewayId": TGW, "OwnerId": ACCOUNT, "State": "available", **changes}
            ]
        },
        {"TransitGatewayIds": [TGW]},
    )


def attachment(**changes):
    return {
        "TransitGatewayAttachmentId": ATTACHMENT,
        "TransitGatewayId": TGW,
        "VpcId": VPC,
        "VpcOwnerId": ACCOUNT,
        "State": "available",
        "SubnetIds": list(SUBNETS.values()),
        "Options": {"ApplianceModeSupport": "enable"},
        **changes,
    }


def attachments(ec2, rows, **response):
    ec2.add_response(
        "describe_transit_gateway_vpc_attachments",
        {"TransitGatewayVpcAttachments": rows, **response},
        {
            "Filters": [
                {"Name": "transit-gateway-id", "Values": [TGW]},
                {"Name": "vpc-id", "Values": [VPC]},
            ]
        },
    )


@pytest.mark.parametrize("owner", [ACCOUNT, "222222222222"])
def test_appliance_mode_uses_tgw_owner_and_allows_a_different_vpc_owner(cloud, owner):
    rule, sts, ec2, _ = cloud
    identity(sts)
    gateway(ec2)
    attachments(ec2, [attachment(VpcOwnerId=owner)])
    result = rule.tgw(TGW).has_appliance_mode(VPC)
    assert result
    assert result.evidence["claim"] == "appliance_mode"
    assert result.evidence["account_id"] == ACCOUNT


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [attachment(Options={"ApplianceModeSupport": "disable"})],
        [attachment(State="pending", Options={})],
    ],
)
def test_absent_disabled_or_unready_appliance_mode_is_a_false_predicate(cloud, rows):
    rule, sts, ec2, _ = cloud
    identity(sts)
    gateway(ec2)
    attachments(ec2, rows)
    assert not rule.tgw(TGW).has_appliance_mode(VPC)


@pytest.mark.parametrize(
    "rows",
    [
        [attachment(TransitGatewayAttachmentId="tgw-attach-")],
        [attachment(VpcOwnerId="unknown")],
        [attachment(TransitGatewayId="tgw-other")],
        [attachment(Options={})],
        [attachment(State="unknown")],
        [attachment(), attachment()],
        [attachment(), attachment(TransitGatewayAttachmentId="tgw-attach-other")],
    ],
)
def test_ambiguous_or_missing_appliance_metadata_is_not_a_false_result(cloud, rows):
    rule, sts, ec2, _ = cloud
    identity(sts)
    gateway(ec2)
    attachments(ec2, rows)
    with pytest.raises(NetworkAssertionError):
        rule.tgw(TGW).has_appliance_mode(VPC)


def test_appliance_mode_consumes_all_attachment_pages(cloud):
    rule, sts, ec2, _ = cloud
    identity(sts)
    gateway(ec2)
    attachments(ec2, [], NextToken="second")
    ec2.add_response(
        "describe_transit_gateway_vpc_attachments",
        {"TransitGatewayVpcAttachments": [attachment()]},
        {
            "Filters": [
                {"Name": "transit-gateway-id", "Values": [TGW]},
                {"Name": "vpc-id", "Values": [VPC]},
            ],
            "NextToken": "second",
        },
    )
    assert rule.tgw(TGW).has_appliance_mode(VPC)


def source(ec2, *, wrong_zone=False, vpc_owner=ACCOUNT, subnet_owner=ACCOUNT):
    ec2.add_response(
        "describe_vpcs",
        {"Vpcs": [{"VpcId": VPC, "OwnerId": vpc_owner, "State": "available"}]},
        {"VpcIds": [VPC]},
    )
    ec2.add_response(
        "describe_subnets",
        {
            "Subnets": [
                {
                    "SubnetId": subnet,
                    "VpcId": VPC,
                    "OwnerId": subnet_owner,
                    "State": "available",
                    "AvailabilityZone": f"{REGION}c" if wrong_zone else zone,
                }
                for zone, subnet in SUBNETS.items()
            ]
        },
        {"SubnetIds": sorted(SUBNETS.values())},
    )


def firewall_response():
    return {
        "Firewall": {
            "FirewallArn": FIREWALL,
            "FirewallId": "12345678-1234-1234-1234-123456789012",
            "FirewallPolicyArn": (
                f"arn:aws:network-firewall:{REGION}:{ACCOUNT}:firewall-policy/inspection"
            ),
            "VpcId": VPC,
            "SubnetMappings": [{"SubnetId": subnet} for subnet in SUBNETS.values()],
        },
        "FirewallStatus": {
            "Status": "READY",
            "ConfigurationSyncStateSummary": "IN_SYNC",
            "SyncStates": {
                zone: {
                    "Attachment": {
                        "SubnetId": subnet,
                        "EndpointId": f"vpce-{zone[-1]}",
                        "Status": "READY",
                    },
                    "Config": {},
                }
                for zone, subnet in SUBNETS.items()
            },
        },
    }


def test_firewall_endpoints_require_exact_live_az_placement(cloud):
    rule, sts, ec2, firewall = cloud
    identity(sts)
    source(ec2)
    firewall.add_response("describe_firewall", firewall_response(), {"FirewallArn": FIREWALL})
    result = rule.vpc(VPC).has_firewall_endpoints(FIREWALL, subnets_by_az=SUBNETS)
    assert result
    assert result.evidence["claim"] == "firewall_endpoint_placement"
    assert len(result.evidence["subnets"]) == 2


@pytest.mark.parametrize(
    "case",
    [
        "wrong_az",
        "wrong_vpc",
        "missing_endpoint",
        "provisioning",
        "config_pending",
        "object_pending",
        "endpoint_pending",
    ],
)
def test_healthy_partial_or_other_az_layout_does_not_satisfy_declared_coverage(cloud, case):
    rule, sts, ec2, firewall = cloud
    identity(sts)
    source(ec2, wrong_zone=case == "wrong_az")
    response = firewall_response()
    status = response["FirewallStatus"]
    if case == "wrong_vpc":
        response["Firewall"]["VpcId"] = "vpc-other"
    elif case == "missing_endpoint":
        del status["SyncStates"][f"{REGION}b"]
    elif case == "provisioning":
        status["Status"] = "PROVISIONING"
    elif case == "config_pending":
        status["ConfigurationSyncStateSummary"] = "PENDING"
    elif case == "object_pending":
        status["SyncStates"][f"{REGION}a"]["Config"] = {"rules": {"SyncStatus": "PENDING"}}
    elif case == "endpoint_pending":
        status["SyncStates"][f"{REGION}a"]["Attachment"]["Status"] = "CREATING"
    firewall.add_response("describe_firewall", response, {"FirewallArn": FIREWALL})
    assert not rule.vpc(VPC).has_firewall_endpoints(FIREWALL, subnets_by_az=SUBNETS)


@pytest.mark.parametrize(
    "case",
    [
        "wrong_identity",
        "unknown_summary",
        "missing_sync_states",
        "missing_attachment",
        "missing_endpoint_id",
        "duplicate_endpoint",
        "contradictory_mapping",
        "unknown_status",
    ],
)
def test_malformed_firewall_state_is_an_error_not_ready_coverage(cloud, case):
    rule, sts, ec2, firewall = cloud
    identity(sts)
    source(ec2)
    response = firewall_response()
    status = response["FirewallStatus"]
    first = status["SyncStates"][f"{REGION}a"]
    if case == "wrong_identity":
        response["Firewall"]["FirewallArn"] = FIREWALL + "-other"
    elif case == "unknown_summary":
        status["ConfigurationSyncStateSummary"] = "UNKNOWN"
    elif case == "missing_sync_states":
        del status["SyncStates"]
    elif case == "missing_attachment":
        del first["Attachment"]
    elif case == "missing_endpoint_id":
        del first["Attachment"]["EndpointId"]
    elif case == "duplicate_endpoint":
        status["SyncStates"][f"{REGION}b"]["Attachment"]["EndpointId"] = "vpce-a"
    elif case == "contradictory_mapping":
        first["Attachment"]["SubnetId"] = "subnet-other"
    elif case == "unknown_status":
        status["Status"] = "UNKNOWN"
    firewall.add_response("describe_firewall", response, {"FirewallArn": FIREWALL})
    with pytest.raises(NetworkAssertionError):
        rule.vpc(VPC).has_firewall_endpoints(FIREWALL, subnets_by_az=SUBNETS)


@pytest.mark.parametrize("subnets", [{}, {f"{REGION}a": "subnet-a", f"{REGION}b": "subnet-a"}])
def test_empty_duplicate_endpoint_declarations_are_rejected_before_sdk(cloud, subnets):
    rule, _, _, _ = cloud
    with pytest.raises(ValueError):
        rule.vpc(VPC).has_firewall_endpoints(FIREWALL, subnets_by_az=subnets)


def test_firewall_read_permission_errors_propagate(cloud):
    rule, sts, ec2, firewall = cloud
    identity(sts)
    source(ec2)
    firewall.add_client_error("describe_firewall", "AccessDeniedException")
    with pytest.raises(ClientError, match="AccessDeniedException"):
        rule.vpc(VPC).has_firewall_endpoints(FIREWALL, subnets_by_az=SUBNETS)


def test_firewall_subnet_ownership_cannot_be_inferred_from_caller_identity(cloud):
    rule, sts, ec2, _ = cloud
    identity(sts)
    source(ec2, subnet_owner="222222222222")
    with pytest.raises(NetworkAssertionError, match="owned|owner|account"):
        rule.vpc(VPC).has_firewall_endpoints(FIREWALL, subnets_by_az=SUBNETS)


def test_firewall_scope_is_validated_before_reads(cloud):
    rule, _, _, _ = cloud
    with pytest.raises(ValueError, match="selected account and region"):
        rule.vpc(VPC).has_firewall_endpoints(
            FIREWALL.replace(ACCOUNT, "222222222222"), subnets_by_az=SUBNETS
        )


def test_extra_ready_endpoints_are_not_exact_declared_coverage(cloud):
    rule, sts, ec2, firewall = cloud
    identity(sts)
    source(ec2)
    response = firewall_response()
    response["Firewall"]["SubnetMappings"].append({"SubnetId": "subnet-c"})
    response["FirewallStatus"]["SyncStates"][f"{REGION}c"] = {
        "Attachment": {"SubnetId": "subnet-c", "EndpointId": "vpce-c", "Status": "READY"}
    }
    firewall.add_response("describe_firewall", response, {"FirewallArn": FIREWALL})
    assert not rule.vpc(VPC).has_firewall_endpoints(FIREWALL, subnets_by_az=SUBNETS)


@pytest.mark.parametrize("return_state", ["active", "blackhole"])
def test_paired_vpc_routes_require_both_directions_through_endpoints(cloud, return_state):
    rule, sts, ec2, _ = cloud
    identity(sts)
    # Gateway endpoints appear in GatewayId in DescribeRouteTables.
    for table_id, cidr, target, state in [
        ("rtb-forward", "10.50.0.0/16", "vpce-a", "active"),
        ("rtb-return", "10.40.0.0/16", "vpce-b", return_state),
    ]:
        ec2.add_response(
            "describe_route_tables",
            {
                "RouteTables": [
                    {
                        "RouteTableId": table_id,
                        "OwnerId": ACCOUNT,
                        "Routes": [
                            {
                                "DestinationCidrBlock": cidr,
                                "GatewayId": target,
                                "State": state,
                                "Origin": "CreateRoute",
                            }
                        ],
                    }
                ]
            },
            {"RouteTableIds": [table_id]},
        )
    result = rule.route_table("rtb-forward").has_bidirectional_routes(
        "10.50.0.0/16",
        source="10.40.0.0/16",
        return_table=rule.route_table("rtb-return"),
        via="vpce-a",
        return_via="vpce-b",
    )
    assert bool(result) == (return_state == "active")
    assert result.evidence["claim"] == "paired_vpc_routes"
    assert result.evidence["forward"]
    assert bool(result.evidence["return"]) == (return_state == "active")


def test_invalid_paired_route_scope_is_rejected_before_reads(cloud):
    rule, _, _, _ = cloud
    with pytest.raises(ValueError, match="region"):
        rule.subnet("subnet-a").has_bidirectional_routes(
            "10.50.0.0/16",
            source="10.40.0.0/16",
            return_table=rule.in_region("us-east-1").subnet("subnet-b"),
        )
    with pytest.raises(ValueError, match="address family"):
        rule.route_table("rtb-forward").has_bidirectional_routes(
            "10.50.0.0/16",
            source="2001:db8::/64",
            return_table=rule.route_table("rtb-return"),
        )


def test_inspection_declarations_are_not_mutated(cloud):
    rule, sts, ec2, firewall = cloud
    identity(sts)
    source(ec2)
    firewall.add_response("describe_firewall", firewall_response(), {"FirewallArn": FIREWALL})
    expected = deepcopy(SUBNETS)
    assert rule.vpc(VPC).has_firewall_endpoints(FIREWALL, subnets_by_az=expected)
    assert expected == SUBNETS


@pytest.mark.parametrize("kind", ["subnet", "route_table", "tgw_table"])
def test_scoped_route_destination_is_rejected_before_any_aws_read(cloud, kind):
    rule, _, _, _ = cloud
    selector = (
        rule.tgw(TGW).route_table("tgw-rtb-source")
        if kind == "tgw_table"
        else getattr(rule, kind)("subnet-source" if kind == "subnet" else "rtb-source")
    )
    with pytest.raises(ValueError, match="scope"):
        selector.has_route_to("fe80::1%wrong-interface")


@pytest.mark.parametrize("kind", ["subnet", "route_table", "tgw_table"])
@pytest.mark.parametrize("scoped", ["source", "destination"])
def test_both_route_pair_ranges_are_validated_before_any_aws_read(cloud, kind, scoped):
    rule, _, _, _ = cloud
    if kind == "tgw_table":
        source = rule.tgw(TGW).route_table("tgw-rtb-source")
        reverse = rule.tgw(TGW).route_table("tgw-rtb-return")
    else:
        prefix = "subnet-" if kind == "subnet" else "rtb-"
        source = getattr(rule, kind)(prefix + "source")
        reverse = getattr(rule, kind)(prefix + "return")
    ranges = {"source": "fe80::1/128", "destination": "fe80::2/128"}
    ranges[scoped] = "fe80::1%wrong-interface/128"
    with pytest.raises(ValueError, match="scope"):
        source.has_bidirectional_routes(
            ranges["destination"], source=ranges["source"], return_table=reverse
        )


def test_paired_routes_reject_an_owned_table_with_a_different_identity(cloud):
    rule, sts, ec2, _ = cloud
    identity(sts)
    ec2.add_response(
        "describe_route_tables",
        {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-unrelated",
                    "OwnerId": ACCOUNT,
                    "Routes": [
                        {
                            "DestinationCidrBlock": "10.50.0.0/16",
                            "GatewayId": "vpce-a",
                            "State": "active",
                        }
                    ],
                }
            ]
        },
        {"RouteTableIds": ["rtb-forward"]},
    )
    with pytest.raises(NetworkAssertionError, match="selected table"):
        rule.route_table("rtb-forward").has_bidirectional_routes(
            "10.50.0.0/16",
            source="10.40.0.0/16",
            return_table=rule.route_table("rtb-return"),
            via="vpce-a",
            return_via="vpce-a",
        )


def test_return_route_error_keeps_partial_forward_evidence(cloud):
    rule, sts, ec2, _ = cloud
    identity(sts)
    ec2.add_response(
        "describe_route_tables",
        {
            "RouteTables": [
                {
                    "RouteTableId": "rtb-forward",
                    "OwnerId": ACCOUNT,
                    "Routes": [
                        {
                            "DestinationCidrBlock": "10.50.0.0/16",
                            "GatewayId": "vpce-a",
                            "State": "active",
                        }
                    ],
                }
            ]
        },
        {"RouteTableIds": ["rtb-forward"]},
    )
    ec2.add_client_error(
        "describe_route_tables",
        "UnauthorizedOperation",
        expected_params={"RouteTableIds": ["rtb-return"]},
    )
    with pytest.raises(ClientError, match="UnauthorizedOperation") as caught:
        rule.route_table("rtb-forward").has_bidirectional_routes(
            "10.50.0.0/16",
            source="10.40.0.0/16",
            return_table=rule.route_table("rtb-return"),
            via="vpce-a",
            return_via="vpce-a",
        )
    assert caught.value.paired_route_evidence["forward"]
    assert not caught.value.paired_route_evidence["return_evaluated"]
