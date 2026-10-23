"""Public API checks against real botocore service models, without AWS calls."""

import json
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from aws_network_asserts import (
    ConfigResourceNotFoundError,
    NetworkAssertionError,
    RuleBuilder,
    UnsupportedCheckError,
)

REGION = "eu-west-2"
REMOTE_REGION = "eu-west-1"
CONFIG_REGION = "eu-central-1"
AGGREGATOR = "organization-network"
ACCOUNT = "123456789012"
REMOTE_ACCOUNT = "210987654321"
ENI = "eni-0123456789abcdef0"
SUBNET = "subnet-0123456789abcdef0"
VPC = "vpc-0123456789abcdef0"
PEER = "vpc-0123456789abcdef1"
TABLE = "rtb-0123456789abcdef0"
TGW = "tgw-0123456789abcdef0"
TGW_TABLE = "tgw-rtb-0123456789abcdef0"


def make_rule(**kwargs):
    session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION
    )
    options = {"config_mode": "off"}
    if kwargs.get("config_mode", "off") != "off":
        options.update(
            config_aggregator=AGGREGATOR,
            config_region=CONFIG_REGION,
            account_id=ACCOUNT,
        )
    options.update(kwargs)
    return RuleBuilder(
        session=session,
        endpoint_url="http://localhost:4566",
        **options,
    )


def verified_ec2(rule):
    """Exercise the account check before attaching a topology API Stubber."""
    with Stubber(rule.clients.client("sts", rule.region_name)) as sts:
        sts.add_response(
            "get_caller_identity",
            {
                "Account": rule.account_id,
                "Arn": f"arn:aws:iam::{rule.account_id}:user/test",
                "UserId": "test-user",
            },
            {},
        )
        client = rule.ec2
        sts.assert_no_pending_responses()
    return client


def route_table(**updates):
    table = {
        "RouteTableId": TABLE,
        "VpcId": VPC,
        "OwnerId": ACCOUNT,
        "Associations": [
            {
                "RouteTableAssociationId": "rtbassoc-current",
                "RouteTableId": TABLE,
                "SubnetId": SUBNET,
                "Main": False,
                "AssociationState": {"State": "associated"},
            }
        ],
        "Routes": [
            {
                "DestinationCidrBlock": "10.47.0.0/16",
                "TransitGatewayId": TGW,
                "Origin": "CreateRoute",
                "State": "active",
            }
        ],
    }
    table.update(updates)
    return table


def config_item(resource_type, resource_id, configuration, **updates):
    result = {
        "resourceType": resource_type,
        "resourceId": resource_id,
        "awsRegion": REGION,
        "accountId": ACCOUNT,
        "configurationItemStatus": "OK",
        "configurationItemCaptureTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
        "configuration": json.dumps(configuration),
    }
    result.update(updates)
    return result


def config_params(resource_type, resource_id):
    return {
        "ConfigurationAggregatorName": AGGREGATOR,
        "ResourceIdentifier": {
            "SourceAccountId": ACCOUNT,
            "SourceRegion": REGION,
            "ResourceType": resource_type,
            "ResourceId": resource_id,
        },
    }


def eni_response(**updates):
    result = {
        "NetworkInterfaceId": ENI,
        "SubnetId": SUBNET,
        "VpcId": VPC,
        "OwnerId": ACCOUNT,
    }
    result.update(updates)
    return {"NetworkInterfaces": [result]}


def peering(
    *,
    orientation="requester",
    state="active",
    remote_region=REMOTE_REGION,
    remote_account=REMOTE_ACCOUNT,
):
    local = {"VpcId": VPC, "Region": REGION, "OwnerId": ACCOUNT}
    remote = {"VpcId": PEER, "Region": remote_region, "OwnerId": remote_account}
    return {
        "VpcPeeringConnectionId": "pcx-0123456789abcdef0",
        "RequesterVpcInfo": local if orientation == "requester" else remote,
        "AccepterVpcInfo": remote if orientation == "requester" else local,
        "Status": {"Code": state},
    }


def peering_params(orientation):
    return {"Filters": [{"Name": f"{orientation}-vpc-info.vpc-id", "Values": [VPC]}]}


def tgw_table(**updates):
    result = {
        "TransitGatewayRouteTableId": TGW_TABLE,
        "TransitGatewayId": TGW,
        "State": "available",
    }
    result.update(updates)
    return {"TransitGatewayRouteTables": [result]}


def propagation_params():
    return {
        "TransitGatewayRouteTableId": TGW_TABLE,
        "Filters": [
            {"Name": "resource-id", "Values": [VPC]},
            {"Name": "resource-type", "Values": ["vpc"]},
        ],
    }


def propagation(state):
    return {
        "TransitGatewayAttachmentId": "tgw-attach-0123456789abcdef0",
        "ResourceType": "vpc",
        "ResourceId": VPC,
        "State": state,
    }


def test_subnet_uses_explicit_association_and_paginates():
    rule = make_rule()
    params = {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]}
    with Stubber(rule.ec2) as stub:
        stub.add_response("describe_route_tables", {"RouteTables": [], "NextToken": "next"}, params)
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": [route_table()]},
            {**params, "NextToken": "next"},
        )
        result = rule.subnet(SUBNET).has_route_to("10.47.1.1/32", via=TGW)
        assert result
        assert result.evidence["association"] == "explicit"
        assert result.evidence["route_table_id"] == TABLE
        stub.assert_no_pending_responses()


def test_main_table_uses_live_subnet_vpc_not_stale_config_vpc():
    rule = make_rule(config_mode="prefer")
    with (
        Stubber(rule.config_clients.client("config", CONFIG_REGION)) as config,
        Stubber(verified_ec2(rule)) as ec2,
    ):
        config.add_response(
            "get_aggregate_resource_config",
            {"ConfigurationItem": config_item("AWS::EC2::Subnet", SUBNET, {"vpcId": "vpc-old"})},
            config_params("AWS::EC2::Subnet", SUBNET),
        )
        ec2.add_response(
            "describe_route_tables",
            {"RouteTables": []},
            {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]},
        )
        ec2.add_response(
            "describe_subnets",
            {
                "Subnets": [
                    {"SubnetId": SUBNET, "VpcId": VPC, "OwnerId": ACCOUNT, "State": "available"}
                ]
            },
            {"SubnetIds": [SUBNET]},
        )
        ec2.add_response(
            "describe_route_tables",
            {
                "RouteTables": [
                    route_table(
                        Associations=[
                            {
                                "RouteTableAssociationId": "rtbassoc-main",
                                "RouteTableId": TABLE,
                                "Main": True,
                                "AssociationState": {"State": "associated"},
                            }
                        ]
                    )
                ]
            },
            {
                "Filters": [
                    {"Name": "vpc-id", "Values": [VPC]},
                    {"Name": "association.main", "Values": ["true"]},
                ]
            },
        )
        result = rule.subnet(SUBNET).has_route_to("10.47.1.1")
        assert result
        assert result.evidence["association"] == "main"
        assert result.evidence["config"]["configuration"]["vpcId"] == "vpc-old"
        config.assert_no_pending_responses()
        ec2.assert_no_pending_responses()


def test_multiple_effective_route_tables_is_an_error_not_an_arbitrary_choice():
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": [route_table(), route_table(RouteTableId="rtb-2")]},
            {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]},
        )
        with pytest.raises(NetworkAssertionError, match="Expected one"):
            rule.subnet(SUBNET).has_route_to("10.47.1.1")


@pytest.mark.parametrize(
    "change",
    [
        "missing_associations",
        "empty_associations",
        "wrong_subnet",
        "wrong_table",
        "missing_main",
        "main_with_subnet",
        "missing_id",
        "duplicate_id",
        "missing_state",
        "unknown_state",
        "associating",
        "disassociating",
        "disassociated",
        "failed",
        "missing_vpc",
        "both_targets",
    ],
)
def test_explicit_subnet_route_selection_requires_complete_active_native_association(change):
    rule = make_rule(account_id=ACCOUNT)
    table = route_table()
    association = table["Associations"][0]
    if change == "missing_associations":
        del table["Associations"]
    elif change == "empty_associations":
        table["Associations"] = []
    elif change == "wrong_subnet":
        association["SubnetId"] = "subnet-unrelated"
    elif change == "wrong_table":
        association["RouteTableId"] = "rtb-unrelated"
    elif change == "missing_main":
        del association["Main"]
    elif change == "main_with_subnet":
        association["Main"] = True
    elif change == "missing_id":
        del association["RouteTableAssociationId"]
    elif change == "duplicate_id":
        table["Associations"].append(dict(association))
    elif change == "missing_state":
        del association["AssociationState"]
    elif change in {"unknown_state", "associating", "disassociating", "disassociated", "failed"}:
        association["AssociationState"]["State"] = "future" if change == "unknown_state" else change
    elif change == "missing_vpc":
        del table["VpcId"]
    elif change == "both_targets":
        association["GatewayId"] = "igw-edge"
    with Stubber(verified_ec2(rule)) as stub:
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": [table]},
            {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]},
        )
        with pytest.raises(NetworkAssertionError):
            rule.subnet(SUBNET).has_route_to("10.47.1.1")
        # Contradictory explicit data must not initiate a main-table fallback.
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "change", ["wrong_id", "missing_vpc", "invalid_vpc", "pending", "missing_state"]
)
def test_main_fallback_validates_live_subnet_identity_vpc_and_state_before_table_lookup(change):
    rule = make_rule(account_id=ACCOUNT)
    subnet = {"SubnetId": SUBNET, "VpcId": VPC, "OwnerId": ACCOUNT, "State": "available"}
    if change == "wrong_id":
        subnet["SubnetId"] = "subnet-unrelated"
    elif change == "missing_vpc":
        del subnet["VpcId"]
    elif change == "invalid_vpc":
        subnet["VpcId"] = "not-a-vpc"
    elif change == "pending":
        subnet["State"] = "pending"
    elif change == "missing_state":
        del subnet["State"]
    with Stubber(verified_ec2(rule)) as stub:
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": []},
            {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]},
        )
        stub.add_response("describe_subnets", {"Subnets": [subnet]}, {"SubnetIds": [SUBNET]})
        with pytest.raises(NetworkAssertionError):
            rule.subnet(SUBNET).has_route_to("10.47.1.1")
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "change", ["wrong_vpc", "not_main", "unknown_state", "inactive", "duplicate_main"]
)
def test_main_fallback_requires_the_same_vpc_and_one_active_main_association(change):
    rule = make_rule(account_id=ACCOUNT)
    table = route_table(
        Associations=[
            {
                "RouteTableAssociationId": "rtbassoc-main",
                "RouteTableId": TABLE,
                "Main": True,
                "AssociationState": {"State": "associated"},
            }
        ]
    )
    association = table["Associations"][0]
    if change == "wrong_vpc":
        table["VpcId"] = "vpc-unrelated"
    elif change == "not_main":
        association.update(Main=False, SubnetId="subnet-unrelated")
    elif change == "unknown_state":
        association["AssociationState"]["State"] = "future"
    elif change == "inactive":
        association["AssociationState"]["State"] = "disassociating"
    elif change == "duplicate_main":
        table["Associations"].append({**association, "RouteTableAssociationId": "rtbassoc-other"})
    with Stubber(verified_ec2(rule)) as stub:
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": []},
            {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]},
        )
        stub.add_response(
            "describe_subnets",
            {
                "Subnets": [
                    {"SubnetId": SUBNET, "VpcId": VPC, "OwnerId": ACCOUNT, "State": "available"}
                ]
            },
            {"SubnetIds": [SUBNET]},
        )
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": [table]},
            {
                "Filters": [
                    {"Name": "vpc-id", "Values": [VPC]},
                    {"Name": "association.main", "Values": ["true"]},
                ]
            },
        )
        with pytest.raises(NetworkAssertionError):
            rule.subnet(SUBNET).has_route_to("10.47.1.1")
        stub.assert_no_pending_responses()


def test_main_fallback_consumes_all_live_subnet_and_main_table_pages():
    rule = make_rule(account_id=ACCOUNT)
    table = route_table(
        Associations=[
            {
                "RouteTableAssociationId": "rtbassoc-main",
                "RouteTableId": TABLE,
                "Main": True,
                "AssociationState": {"State": "associated"},
            }
        ]
    )
    main_params = {
        "Filters": [
            {"Name": "vpc-id", "Values": [VPC]},
            {"Name": "association.main", "Values": ["true"]},
        ]
    }
    with Stubber(verified_ec2(rule)) as stub:
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": []},
            {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]},
        )
        stub.add_response(
            "describe_subnets", {"Subnets": [], "NextToken": "second"}, {"SubnetIds": [SUBNET]}
        )
        stub.add_response(
            "describe_subnets",
            {
                "Subnets": [
                    {"SubnetId": SUBNET, "VpcId": VPC, "OwnerId": ACCOUNT, "State": "available"}
                ]
            },
            {"SubnetIds": [SUBNET], "NextToken": "second"},
        )
        stub.add_response(
            "describe_route_tables", {"RouteTables": [], "NextToken": "last"}, main_params
        )
        stub.add_response(
            "describe_route_tables", {"RouteTables": [table]}, {**main_params, "NextToken": "last"}
        )
        result = rule.subnet(SUBNET).has_route_to("10.47.1.1")
        assert result
        assert result.evidence["vpc_id"] == VPC
        assert (
            result.evidence["route_table_association"]["RouteTableAssociationId"] == "rtbassoc-main"
        )
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("orientation", ["requester", "accepter"])
def test_active_peering_matches_either_orientation_and_remote_identity(orientation):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        if orientation == "accepter":
            stub.add_response(
                "describe_vpc_peering_connections",
                {"VpcPeeringConnections": []},
                peering_params("requester"),
            )
        stub.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": [peering(orientation=orientation)]},
            peering_params(orientation),
        )
        assert rule.vpc(VPC).has_peering_with(
            rule.in_region(REMOTE_REGION).vpc(PEER), account_id=REMOTE_ACCOUNT
        )
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "changes",
    [
        {"remote_region": "us-east-1"},
        {"remote_account": ACCOUNT},
        {"state": "pending-acceptance"},
    ],
)
def test_peering_wrong_remote_scope_or_inactive_state_cannot_pass(changes):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": [peering(**changes)]},
            peering_params("requester"),
        )
        stub.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": []},
            peering_params("accepter"),
        )
        result = rule.vpc(VPC).has_peering_with(
            PEER, region=REMOTE_REGION, account_id=REMOTE_ACCOUNT
        )
        assert not result
        assert "no active peering" in repr(result)
        stub.assert_no_pending_responses()


def test_peering_search_follows_all_pages():
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": [], "NextToken": "next"},
            peering_params("requester"),
        )
        stub.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": [peering()]},
            {**peering_params("requester"), "NextToken": "next"},
        )
        assert rule.vpc(VPC).has_peering_with(PEER)
        stub.assert_no_pending_responses()


def test_peering_rejects_conflicting_region_argument_without_api_calls():
    rule = make_rule()
    with Stubber(rule.ec2), pytest.raises(ValueError, match="region disagrees"):
        rule.vpc(VPC).has_peering_with(rule.in_region(REMOTE_REGION).vpc(PEER), region=REGION)


@pytest.mark.parametrize("orientation", ["requester", "accepter"])
def test_scoped_peering_uses_destination_selector_account_and_region(orientation):
    rule = make_rule(account_id=ACCOUNT)
    destination = rule.in_account(REMOTE_ACCOUNT).in_region(REMOTE_REGION).vpc(PEER)
    with (
        Stubber(verified_ec2(rule)) as ec2,
        Stubber(rule.clients.client("sts", REMOTE_REGION)),
    ):
        if orientation == "accepter":
            ec2.add_response(
                "describe_vpc_peering_connections",
                {"VpcPeeringConnections": []},
                peering_params("requester"),
            )
        ec2.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": [peering(orientation=orientation)]},
            peering_params(orientation),
        )
        result = rule.vpc(VPC).has_peering_with(destination)
        assert result
        assert result.evidence["account_id"] == ACCOUNT
        assert destination.account_id == REMOTE_ACCOUNT
        assert rule.account_id == ACCOUNT
        ec2.assert_no_pending_responses()


def test_peering_rejects_conflicting_account_argument_before_api_calls():
    rule = make_rule(config_mode="required")
    destination = rule.in_account(REMOTE_ACCOUNT).vpc(PEER)
    with (
        Stubber(rule.config_clients.client("config", CONFIG_REGION)),
        Stubber(rule.analysis_ec2),
        Stubber(rule.clients.client("sts", REGION)),
        pytest.raises(ValueError, match="account_id disagrees"),
    ):
        rule.vpc(VPC).has_peering_with(destination, account_id=ACCOUNT)


def test_peering_destination_account_from_selector_must_match_remote_owner():
    rule = make_rule(account_id=ACCOUNT)
    destination = rule.in_account(REMOTE_ACCOUNT).in_region(REMOTE_REGION).vpc(PEER)
    with Stubber(verified_ec2(rule)) as ec2:
        ec2.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": [peering(remote_account=ACCOUNT)]},
            peering_params("requester"),
        )
        ec2.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": []},
            peering_params("accepter"),
        )
        assert not rule.vpc(VPC).has_peering_with(destination)
        ec2.assert_no_pending_responses()


@pytest.mark.parametrize("orientation", ["requester", "accepter"])
def test_scoped_peering_cannot_match_a_different_local_owner(orientation):
    rule = make_rule(account_id=ACCOUNT)
    response = peering(orientation=orientation)
    local_side = "RequesterVpcInfo" if orientation == "requester" else "AccepterVpcInfo"
    response[local_side]["OwnerId"] = REMOTE_ACCOUNT
    with Stubber(verified_ec2(rule)) as ec2:
        for side in ("requester", "accepter"):
            ec2.add_response(
                "describe_vpc_peering_connections",
                {"VpcPeeringConnections": [response] if side == orientation else []},
                peering_params(side),
            )
        assert not rule.vpc(VPC).has_peering_with(
            PEER, region=REMOTE_REGION, account_id=REMOTE_ACCOUNT
        )
        ec2.assert_no_pending_responses()


def test_scoped_peering_missing_local_owner_is_an_evaluation_error():
    rule = make_rule(account_id=ACCOUNT)
    response = peering()
    del response["RequesterVpcInfo"]["OwnerId"]
    with Stubber(verified_ec2(rule)) as ec2:
        ec2.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": [response]},
            peering_params("requester"),
        )
        with pytest.raises(NetworkAssertionError, match="OwnerId"):
            rule.vpc(VPC).has_peering_with(PEER)
        ec2.assert_no_pending_responses()


@pytest.mark.parametrize("changes", [{"TransitGatewayId": "tgw-other"}, {"State": "pending"}])
def test_tgw_propagation_rejects_wrong_gateway_or_unavailable_table(changes):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_transit_gateway_route_tables",
            tgw_table(**changes),
            {"TransitGatewayRouteTableIds": [TGW_TABLE]},
        )
        result = rule.tgw(TGW).propagates(TGW_TABLE).from_vpc(VPC)
        assert not result
        assert "not an available table" in result.message
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("method", ["from_vpc", "to_vpc"])
def test_enabled_tgw_propagation_pagination_and_alias(method):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_transit_gateway_route_tables",
            tgw_table(),
            {"TransitGatewayRouteTableIds": [TGW_TABLE]},
        )
        stub.add_response(
            "get_transit_gateway_route_table_propagations",
            {
                "TransitGatewayRouteTablePropagations": [propagation("enabling")],
                "NextToken": "next",
            },
            propagation_params(),
        )
        stub.add_response(
            "get_transit_gateway_route_table_propagations",
            {"TransitGatewayRouteTablePropagations": [propagation("enabled")]},
            {**propagation_params(), "NextToken": "next"},
        )
        result = getattr(rule.tgw(TGW).propagates(TGW_TABLE), method)(VPC)
        assert result
        assert f"from {VPC} into {TGW_TABLE}" in result.message
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("state", ["enabling", "disabling", "disabled"])
def test_tgw_propagation_requires_enabled_state(state):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_transit_gateway_route_tables",
            tgw_table(),
            {"TransitGatewayRouteTableIds": [TGW_TABLE]},
        )
        stub.add_response(
            "get_transit_gateway_route_table_propagations",
            {"TransitGatewayRouteTablePropagations": [propagation(state)]},
            propagation_params(),
        )
        assert not rule.tgw(TGW).propagates(TGW_TABLE).from_vpc(VPC)


def test_tgw_rejects_vpc_route_table_id():
    with pytest.raises(ValueError, match="tgw-rtb"):
        make_rule().tgw(TGW).propagates(TABLE)


@pytest.mark.parametrize(
    "method,expected,passed",
    [
        ("in_subnet", SUBNET, True),
        ("in_subnet", "subnet-other", False),
        ("in_vpc", VPC, True),
        ("in_vpc", PEER, False),
    ],
)
def test_eni_membership_uses_live_fields_and_useful_results(method, expected, passed):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_network_interfaces", eni_response(), {"NetworkInterfaceIds": [ENI]}
        )
        result = getattr(rule.eni(ENI), method)(expected)
        assert bool(result) is passed
        assert ("PASS:" if passed else "FAIL:") in repr(result)
        assert ENI in result.message
        assert REGION in result.message
        if passed:
            result.assert_ok()
        else:
            with pytest.raises(AssertionError, match="expected"):
                result.assert_ok()


def test_missing_eni_membership_field_raises_instead_of_claiming_nonmembership():
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_network_interfaces",
            {"NetworkInterfaces": [{"NetworkInterfaceId": ENI}]},
            {"NetworkInterfaceIds": [ENI]},
        )
        with pytest.raises(NetworkAssertionError, match="missing VpcId"):
            rule.eni(ENI).in_vpc(VPC)


def test_empty_subnet_eni_list_is_explicitly_empty():
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_network_interfaces",
            {"NetworkInterfaces": []},
            {"Filters": [{"Name": "subnet-id", "Values": [SUBNET]}]},
        )
        assert rule.subnet(SUBNET).enis() == []


def test_subnet_eni_enumeration_paginates_without_mutating_builder():
    rule = make_rule()
    params = {"Filters": [{"Name": "subnet-id", "Values": [SUBNET]}]}
    second = "eni-0123456789abcdef1"
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_network_interfaces", {**eni_response(), "NextToken": "next"}, params
        )
        stub.add_response(
            "describe_network_interfaces",
            eni_response(NetworkInterfaceId=second),
            {**params, "NextToken": "next"},
        )
        selected = rule.subnet(SUBNET).enis()
        assert [eni.resource_id for eni in selected] == [ENI, second]
        assert all(eni.region == REGION for eni in selected)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("status", [None, "ResourceDeleted", "ResourceNotRecorded"])
def test_prefer_config_falls_back_only_for_unavailable_record_and_keeps_live_evidence(status):
    rule = make_rule(config_mode="prefer")
    with (
        Stubber(rule.config_clients.client("config", CONFIG_REGION)) as config,
        Stubber(verified_ec2(rule)) as ec2,
    ):
        if status is None:
            config.add_client_error(
                "get_aggregate_resource_config",
                service_error_code="ResourceNotDiscoveredException",
                expected_params=config_params("AWS::EC2::NetworkInterface", ENI),
            )
        else:
            config.add_response(
                "get_aggregate_resource_config",
                {
                    "ConfigurationItem": config_item(
                        "AWS::EC2::NetworkInterface",
                        ENI,
                        {"vpcId": "vpc-old"},
                        configurationItemStatus=status,
                    )
                },
                config_params("AWS::EC2::NetworkInterface", ENI),
            )
        ec2.add_response(
            "describe_network_interfaces", eni_response(), {"NetworkInterfaceIds": [ENI]}
        )
        result = rule.eni(ENI).in_vpc(VPC)
        assert result
        assert "config_unavailable" in result.evidence
        assert result.evidence["network_interface"]["VpcId"] == VPC
        config.assert_no_pending_responses()
        ec2.assert_no_pending_responses()


def test_required_config_does_not_fall_back_to_live_api():
    rule = make_rule(config_mode="required")
    with (
        Stubber(rule.config_clients.client("config", CONFIG_REGION)) as config,
        Stubber(rule.analysis_ec2),
        Stubber(rule.clients.client("sts", REGION)),
    ):
        config.add_client_error(
            "get_aggregate_resource_config",
            service_error_code="ResourceNotDiscoveredException",
            expected_params=config_params("AWS::EC2::NetworkInterface", ENI),
        )
        with pytest.raises(ConfigResourceNotFoundError):
            rule.eni(ENI).in_vpc(VPC)
        config.assert_no_pending_responses()


@pytest.mark.parametrize("mode", ["prefer", "required"])
def test_config_permission_errors_always_propagate(mode):
    rule = make_rule(config_mode=mode)
    with (
        Stubber(rule.config_clients.client("config", CONFIG_REGION)) as config,
        Stubber(rule.analysis_ec2),
        Stubber(rule.clients.client("sts", REGION)),
    ):
        config.add_client_error(
            "get_aggregate_resource_config",
            service_error_code="AccessDeniedException",
            expected_params=config_params("AWS::EC2::NetworkInterface", ENI),
        )
        with pytest.raises(ClientError, match="AccessDenied"):
            rule.eni(ENI).in_vpc(VPC)
        config.assert_no_pending_responses()


def test_config_off_makes_no_config_api_calls_and_explicit_config_methods_fail():
    rule = make_rule()
    with Stubber(rule.clients.client("config", REGION)), Stubber(rule.ec2) as ec2:
        ec2.add_response(
            "describe_network_interfaces", eni_response(), {"NetworkInterfaceIds": [ENI]}
        )
        assert rule.eni(ENI).in_vpc(VPC)
        with pytest.raises(UnsupportedCheckError, match="config_mode"):
            rule.eni(ENI).config_snapshot()
        with pytest.raises(UnsupportedCheckError, match="config_mode"):
            rule.resource_ids("AWS::EC2::NetworkInterface")


def test_selectors_are_immutable_and_region_views_share_client_cache_only():
    rule = make_rule()
    original = rule.eni(ENI)
    remote = rule.in_region(REMOTE_REGION)
    second = remote.eni("eni-2")
    assert original.resource_id == ENI
    assert original.region == rule.region_name == REGION
    assert second.region == REMOTE_REGION
    assert remote.clients is rule.clients
    assert remote.ec2 is rule.in_region(REMOTE_REGION).ec2
    assert remote.ec2 is not rule.ec2
    with pytest.raises(FrozenInstanceError):
        original.resource_id = "eni-mutated"
    with pytest.raises(TypeError, match="not an assertion"):
        bool(original)
    with pytest.raises(TypeError, match="Complete"):
        bool(rule.tgw(TGW).propagates(TGW_TABLE))


@pytest.mark.parametrize("method", ["can_reach", "cannot_reach"])
def test_cross_region_reachability_selectors_raise_before_any_config_or_ec2_calls(method):
    rule = make_rule(config_mode="required")
    with (
        Stubber(rule.config_clients.client("config", CONFIG_REGION)),
        Stubber(rule.analysis_ec2),
        Stubber(rule.clients.client("sts", REGION)),
    ):
        with pytest.raises(UnsupportedCheckError, match="one region"):
            getattr(rule.eni(ENI), method)(rule.in_region(REMOTE_REGION).eni("eni-other"))


@pytest.mark.parametrize("method", ["can_reach", "cannot_reach"])
def test_cross_region_reachability_arn_is_rejected_not_treated_as_isolation(method):
    rule = make_rule()
    arn = f"arn:aws:ec2:{REMOTE_REGION}:{REMOTE_ACCOUNT}:network-interface/eni-other"
    with Stubber(rule.ec2), pytest.raises(UnsupportedCheckError, match="both endpoints"):
        getattr(rule.eni(ENI), method)(arn)


def test_subnet_selector_is_not_a_reachability_endpoint():
    rule = make_rule()
    with Stubber(rule.ec2), pytest.raises(UnsupportedCheckError, match="ENI"):
        rule.eni(ENI).can_reach(rule.subnet(SUBNET))


@pytest.mark.parametrize("field", ["VpcId", "Region", "OwnerId"])
def test_missing_peering_remote_identity_is_an_error_not_no_peering(field):
    rule = make_rule()
    response = peering()
    del response["AccepterVpcInfo"][field]
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": [response]},
            peering_params("requester"),
        )
        with pytest.raises(NetworkAssertionError, match=field):
            rule.vpc(VPC).has_peering_with(PEER, region=REMOTE_REGION, account_id=REMOTE_ACCOUNT)


@pytest.mark.parametrize("status", [None, {}, {"Code": "unexpected"}])
def test_missing_or_unknown_peering_status_is_an_error_not_no_peering(status):
    rule = make_rule()
    response = peering()
    if status is None:
        del response["Status"]
    else:
        response["Status"] = status
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_vpc_peering_connections",
            {"VpcPeeringConnections": [response]},
            peering_params("requester"),
        )
        with pytest.raises(NetworkAssertionError):
            rule.vpc(VPC).has_peering_with(PEER)


@pytest.mark.parametrize("field", ["TransitGatewayId", "State"])
def test_missing_tgw_table_identity_or_state_is_an_error(field):
    rule = make_rule()
    response = tgw_table()
    del response["TransitGatewayRouteTables"][0][field]
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_transit_gateway_route_tables",
            response,
            {"TransitGatewayRouteTableIds": [TGW_TABLE]},
        )
        with pytest.raises(NetworkAssertionError, match=field):
            rule.tgw(TGW).propagates(TGW_TABLE).from_vpc(VPC)


def test_missing_propagation_state_is_an_error_not_disabled_propagation():
    rule = make_rule()
    entry = propagation("enabled")
    del entry["State"]
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_transit_gateway_route_tables",
            tgw_table(),
            {"TransitGatewayRouteTableIds": [TGW_TABLE]},
        )
        stub.add_response(
            "get_transit_gateway_route_table_propagations",
            {"TransitGatewayRouteTablePropagations": [entry]},
            propagation_params(),
        )
        with pytest.raises(NetworkAssertionError, match="State"):
            rule.tgw(TGW).propagates(TGW_TABLE).from_vpc(VPC)


def test_missing_attachment_state_is_an_error_not_absent_attachment():
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_transit_gateway_attachments",
            {
                "TransitGatewayAttachments": [
                    {
                        "TransitGatewayId": TGW,
                        "ResourceType": "vpc",
                        "ResourceId": VPC,
                    }
                ]
            },
            {
                "Filters": [
                    {"Name": "transit-gateway-id", "Values": [TGW]},
                    {"Name": "resource-id", "Values": [VPC]},
                    {"Name": "resource-type", "Values": ["vpc"]},
                ]
            },
        )
        with pytest.raises(NetworkAssertionError, match="State"):
            rule.tgw(TGW).has_attachment(VPC)


@pytest.mark.parametrize("name", ["timeout", "poll_interval"])
@pytest.mark.parametrize("value", [True, False, float("nan"), float("inf"), 0, -1, "2"])
def test_invalid_analysis_timing_is_rejected_at_builder_construction(name, value):
    with pytest.raises(ValueError, match=f"{name} must be a positive finite"):
        make_rule(**{name: value})


@pytest.mark.parametrize("key,value", [("Name", None), (None, "value"), ("", "value"), ("Name", 3)])
def test_config_tag_requires_string_key_and_value_before_calls(key, value):
    rule = make_rule(config_mode="required")
    with (
        Stubber(rule.config_clients.client("config", CONFIG_REGION)),
        pytest.raises(ValueError, match="Tag key"),
    ):
        rule.vpc(VPC).has_config_tag(key, value)


def test_absent_config_tag_does_not_match_empty_value():
    rule = make_rule(config_mode="required")
    with Stubber(rule.config_clients.client("config", CONFIG_REGION)) as stub:
        stub.add_response(
            "get_aggregate_resource_config",
            {"ConfigurationItem": config_item("AWS::EC2::VPC", VPC, {}, tags={})},
            config_params("AWS::EC2::VPC", VPC),
        )
        assert not rule.vpc(VPC).has_config_tag("Name", "")


@pytest.mark.parametrize("kind", ["table", "propagation", "attachment"])
def test_unknown_tgw_state_raises_instead_of_passing_a_negative_assertion(kind):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        if kind == "attachment":
            stub.add_response(
                "describe_transit_gateway_attachments",
                {
                    "TransitGatewayAttachments": [
                        {
                            "TransitGatewayId": TGW,
                            "ResourceType": "vpc",
                            "ResourceId": VPC,
                            "State": "unknown-new",
                        }
                    ]
                },
                {
                    "Filters": [
                        {"Name": "transit-gateway-id", "Values": [TGW]},
                        {"Name": "resource-id", "Values": [VPC]},
                        {"Name": "resource-type", "Values": ["vpc"]},
                    ]
                },
            )
            with pytest.raises(NetworkAssertionError, match="unknown State"):
                rule.tgw(TGW).has_attachment(VPC)
        else:
            stub.add_response(
                "describe_transit_gateway_route_tables",
                tgw_table(State="unknown-new" if kind == "table" else "available"),
                {"TransitGatewayRouteTableIds": [TGW_TABLE]},
            )
            if kind == "propagation":
                stub.add_response(
                    "get_transit_gateway_route_table_propagations",
                    {"TransitGatewayRouteTablePropagations": [propagation("unknown-new")]},
                    propagation_params(),
                )
            with pytest.raises(NetworkAssertionError, match="unknown State"):
                rule.tgw(TGW).propagates(TGW_TABLE).from_vpc(VPC)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("items", [{}, None, ["not an object"]])
def test_malformed_list_shapes_never_become_empty_resource_selection(monkeypatch, items):
    rule = make_rule()
    paginator = Mock()
    paginator.paginate.return_value = [{"NetworkInterfaces": items}]
    monkeypatch.setattr(rule.ec2, "get_paginator", lambda _: paginator)
    with pytest.raises(NetworkAssertionError, match="list of objects"):
        rule.subnet(SUBNET).enis()


@pytest.mark.parametrize("accounts", [["１１１１１１１１１１１１"], ["bad"], [111111111111]])
def test_additional_accounts_use_shared_account_validation_at_construction(accounts):
    with pytest.raises(ValueError, match="account ID"):
        make_rule(additional_accounts=accounts)


def test_propagation_never_accepts_a_different_table_returned_by_discovery():
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_transit_gateway_route_tables",
            tgw_table(TransitGatewayRouteTableId="tgw-rtb-other"),
            {"TransitGatewayRouteTableIds": [TGW_TABLE]},
        )
        with pytest.raises(NetworkAssertionError, match="identity"):
            rule.tgw(TGW).propagates(TGW_TABLE).from_vpc(VPC)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("keep", ["False", "True", 0, 1, None])
def test_builder_rejects_nonboolean_analysis_retention(keep):
    with pytest.raises(ValueError, match="keep_analysis must be a boolean"):
        make_rule(keep_analysis=keep)
