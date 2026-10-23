"""Resource visibility must not be mistaken for ownership in shared networks."""

import boto3
import pytest
from botocore.stub import Stubber

from aws_network_asserts import NetworkAssertionError, RuleBuilder

REGION = "eu-west-2"
OWNER = "111111111111"
PARTICIPANT = "222222222222"
ENI = "eni-0123456789abcdef0"
PARTICIPANT_ENI = "eni-0fedcba9876543210"
SUBNET = "subnet-0123456789abcdef0"
VPC = "vpc-0123456789abcdef0"
TABLE = "rtb-0123456789abcdef0"
TGW = "tgw-0123456789abcdef0"


def make_rule(*, scoped=True):
    session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION
    )
    rule = RuleBuilder(
        session=session,
        config_mode="off",
        account_id=OWNER if scoped else None,
        endpoint_url="https://aws.test.invalid",
    )
    if scoped:
        with Stubber(rule.clients.client("sts", REGION)) as sts:
            sts.add_response(
                "get_caller_identity",
                {
                    "Account": OWNER,
                    "Arn": f"arn:aws:iam::{OWNER}:user/test",
                    "UserId": "test-user",
                },
                {},
            )
            _ = rule.ec2
            sts.assert_no_pending_responses()
    return rule


def interface(resource_id=ENI, **fields):
    return {"NetworkInterfaceId": resource_id, "SubnetId": SUBNET, "VpcId": VPC, **fields}


def route_table(**fields):
    return {
        "RouteTableId": TABLE,
        "VpcId": VPC,
        "Routes": [
            {
                "DestinationCidrBlock": "10.47.0.0/16",
                "TransitGatewayId": TGW,
                "State": "active",
            }
        ],
        **fields,
    }


def attachment(**fields):
    return {
        "TransitGatewayId": TGW,
        "TransitGatewayAttachmentId": "tgw-attach-0123456789abcdef0",
        "ResourceId": VPC,
        "ResourceType": "vpc",
        "State": "available",
        **fields,
    }


ATTACHMENT_PARAMS = {
    "Filters": [
        {"Name": "transit-gateway-id", "Values": [TGW]},
        {"Name": "resource-id", "Values": [VPC]},
        {"Name": "resource-type", "Values": ["vpc"]},
    ]
}


def test_shared_subnet_enumeration_preserves_participant_eni_ownership():
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_network_interfaces",
            {
                "NetworkInterfaces": [
                    interface(OwnerId=OWNER),
                    interface(PARTICIPANT_ENI, OwnerId=PARTICIPANT),
                ]
            },
            {"Filters": [{"Name": "subnet-id", "Values": [SUBNET]}]},
        )
        own, foreign = rule.subnet(SUBNET).enis()
        assert (own.resource_id, own.account_id) == (ENI, OWNER)
        assert (foreign.resource_id, foreign.account_id) == (PARTICIPANT_ENI, PARTICIPANT)
        assert foreign.builder.inventory.account_id == PARTICIPANT
        assert own.region == foreign.region == REGION
        assert own.builder.clients is foreign.builder.clients is rule.clients
        assert foreign.builder.config_clients is rule.config_clients
        assert rule.account_id == OWNER
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("owner_fields", [{}, {"OwnerId": "invalid"}])
def test_scoped_enumeration_requires_valid_eni_owner(owner_fields):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_network_interfaces",
            {"NetworkInterfaces": [interface(**owner_fields)]},
            {"Filters": [{"Name": "subnet-id", "Values": [SUBNET]}]},
        )
        with pytest.raises(NetworkAssertionError, match="OwnerId"):
            rule.subnet(SUBNET).enis()
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("kind", ["eni", "route_table", "subnet"])
@pytest.mark.parametrize("owner_fields", [{}, {"OwnerId": "invalid"}, {"OwnerId": PARTICIPANT}])
def test_scoped_live_checks_reject_missing_invalid_or_foreign_owners(kind, owner_fields):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        if kind == "eni":
            stub.add_response(
                "describe_network_interfaces",
                {"NetworkInterfaces": [interface(**owner_fields)]},
                {"NetworkInterfaceIds": [ENI]},
            )
            selector = rule.eni(ENI)
        else:
            params = (
                {"RouteTableIds": [TABLE]}
                if kind == "route_table"
                else {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]}
            )
            stub.add_response(
                "describe_route_tables", {"RouteTables": [route_table(**owner_fields)]}, params
            )
            selector = rule.route_table(TABLE) if kind == "route_table" else rule.subnet(SUBNET)
        with pytest.raises(NetworkAssertionError, match="OwnerId"):
            if kind == "eni":
                selector.in_vpc(VPC)
            else:
                selector.has_route_to("10.47.1.1/32", via=TGW)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("owner_fields", [{}, {"OwnerId": "invalid"}, {"OwnerId": PARTICIPANT}])
def test_main_route_fallback_rejects_foreign_or_missing_subnet_owner(owner_fields):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": []},
            {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]},
        )
        stub.add_response(
            "describe_subnets",
            {"Subnets": [{"SubnetId": SUBNET, "VpcId": VPC, **owner_fields}]},
            {"SubnetIds": [SUBNET]},
        )
        with pytest.raises(NetworkAssertionError, match="OwnerId"):
            rule.subnet(SUBNET).has_route_to("10.47.1.1/32", via=TGW)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("owner_fields", [{}, {"OwnerId": "invalid"}, {"OwnerId": PARTICIPANT}])
def test_main_table_owner_is_checked_before_missing_association_metadata(owner_fields):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": []},
            {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]},
        )
        stub.add_response(
            "describe_subnets",
            {
                "Subnets": [
                    {"SubnetId": SUBNET, "VpcId": VPC, "OwnerId": OWNER, "State": "available"}
                ]
            },
            {"SubnetIds": [SUBNET]},
        )
        # Missing Associations must not hide a missing/foreign table owner.
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": [route_table(**owner_fields)]},
            {
                "Filters": [
                    {"Name": "vpc-id", "Values": [VPC]},
                    {"Name": "association.main", "Values": ["true"]},
                ]
            },
        )
        with pytest.raises(NetworkAssertionError, match="OwnerId"):
            rule.subnet(SUBNET).has_route_to("10.47.1.1/32", via=TGW)
        stub.assert_no_pending_responses()


def test_tgw_attachment_checks_tgw_owner_independently_from_vpc_owner():
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_transit_gateway_attachments",
            {
                "TransitGatewayAttachments": [
                    attachment(TransitGatewayOwnerId=OWNER, ResourceOwnerId=PARTICIPANT)
                ]
            },
            ATTACHMENT_PARAMS,
        )
        assert rule.tgw(TGW).has_attachment(VPC)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "tgw_owner", [{}, {"TransitGatewayOwnerId": "invalid"}, {"TransitGatewayOwnerId": PARTICIPANT}]
)
def test_vpc_ownership_does_not_satisfy_tgw_ownership(tgw_owner):
    rule = make_rule()
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_transit_gateway_attachments",
            {"TransitGatewayAttachments": [attachment(ResourceOwnerId=OWNER, **tgw_owner)]},
            ATTACHMENT_PARAMS,
        )
        with pytest.raises(NetworkAssertionError, match="TransitGatewayOwnerId"):
            rule.tgw(TGW).has_attachment(VPC)
        stub.assert_no_pending_responses()


def test_standalone_unscoped_checks_do_not_require_owner_metadata():
    rule = make_rule(scoped=False)
    with Stubber(rule.ec2) as stub:
        stub.add_response(
            "describe_network_interfaces",
            {"NetworkInterfaces": [interface()]},
            {"NetworkInterfaceIds": [ENI]},
        )
        stub.add_response(
            "describe_network_interfaces",
            {"NetworkInterfaces": [interface()]},
            {"Filters": [{"Name": "subnet-id", "Values": [SUBNET]}]},
        )
        stub.add_response(
            "describe_route_tables",
            {"RouteTables": [route_table()]},
            {"RouteTableIds": [TABLE]},
        )
        stub.add_response(
            "describe_transit_gateway_attachments",
            {"TransitGatewayAttachments": [attachment()]},
            ATTACHMENT_PARAMS,
        )
        assert rule.eni(ENI).in_vpc(VPC)
        assert rule.subnet(SUBNET).enis()[0].account_id is None
        assert rule.route_table(TABLE).has_route_to("10.47.1.1/32", via=TGW)
        assert rule.tgw(TGW).has_attachment(VPC)
        stub.assert_no_pending_responses()
