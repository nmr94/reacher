"""Effective TGW route coverage and ownership against botocore SDK models."""

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from test_builder import ACCOUNT, TGW, TGW_TABLE, make_rule, verified_ec2

from aws_network_asserts import NetworkAssertionError, UnsupportedCheckError
from aws_network_asserts.tgw_routes import check_tgw_routes

ATTACHMENT = "tgw-attach-12345678"
OTHER = "tgw-attach-87654321"


def route(
    cidr="10.0.0.0/8", *, state="active", target=ATTACHMENT, kind="static", resource_type="vpc"
):
    item = {"DestinationCidrBlock": cidr, "State": state, "Type": kind}
    if target is not None:
        item["TransitGatewayAttachments"] = [
            {"TransitGatewayAttachmentId": target, "ResourceType": resource_type}
        ]
    return item


@pytest.fixture
def cloud():
    rule = make_rule(account_id=ACCOUNT)
    with Stubber(verified_ec2(rule)) as stub:
        yield rule, stub
        stub.assert_no_pending_responses()


def searches(stub, destination, routes, descendants=()):
    for name, rows in (("supernet", routes), ("subnet", descendants)):
        stub.add_response(
            "search_transit_gateway_routes",
            {"Routes": list(rows), "AdditionalRoutesAvailable": False},
            {
                "TransitGatewayRouteTableId": TGW_TABLE,
                "Filters": [{"Name": f"route-search.{name}-of-match", "Values": [destination]}],
                "MaxResults": 1000,
            },
        )

    stub.add_response(
        "get_transit_gateway_prefix_list_references",
        {"TransitGatewayPrefixListReferences": []},
        {"TransitGatewayRouteTableId": TGW_TABLE},
    )


def live(stub, *, owner=ACCOUNT, table=TGW_TABLE):
    stub.add_response(
        "describe_transit_gateways",
        {"TransitGateways": [{"TransitGatewayId": TGW, "OwnerId": owner, "State": "available"}]},
        {"TransitGatewayIds": [TGW]},
    )
    stub.add_response(
        "describe_transit_gateway_route_tables",
        {
            "TransitGatewayRouteTables": [
                {"TransitGatewayRouteTableId": table, "TransitGatewayId": TGW, "State": "available"}
            ]
        },
        {"TransitGatewayRouteTableIds": [table]},
    )


@pytest.mark.parametrize("prefix,target", [("10.0.0.0/8", "10.47.0.0/16"), ("::/0", "::/0")])
def test_supernet_coverage_and_ipv6_intervals(cloud, prefix, target):
    rule, stub = cloud
    searches(stub, target, [route(prefix)])
    result = check_tgw_routes(rule.ec2, TGW_TABLE, target, via=ATTACHMENT)
    assert result
    assert len(result.evidence["coverage"]) == 1


@pytest.mark.parametrize(
    "via", ["tgw-attach-", "tgw-attach-a ", "tgw-attach-a\x00", "tgw-attach-a/b"]
)
def test_malformed_tgw_target_expectation_fails_before_search(via):
    with pytest.raises(ValueError, match="via"):
        check_tgw_routes(None, TGW_TABLE, "10.47.0.0/16", via=via)


def test_scoped_ipv6_target_is_rejected_before_tgw_search():
    with pytest.raises(ValueError, match="scope"):
        check_tgw_routes(None, TGW_TABLE, "fe80::1%wrong-interface")


def test_scoped_native_tgw_route_is_an_evaluation_error(cloud):
    rule, stub = cloud
    searches(stub, "fe80::1/128", [route("fe80::%wrong-interface/64")])
    with pytest.raises(NetworkAssertionError, match="scope"):
        check_tgw_routes(rule.ec2, TGW_TABLE, "fe80::1")


def test_scoped_native_tgw_prefix_list_is_an_evaluation_error(cloud):
    rule, stub = cloud
    item = route()
    del item["DestinationCidrBlock"]
    item["PrefixListId"] = "pl-12345678"
    searches(stub, "fe80::1/128", [item])
    stub.add_response(
        "get_managed_prefix_list_entries",
        {"Entries": [{"Cidr": "fe80::%wrong-interface/64"}]},
        {"PrefixListId": "pl-12345678"},
    )
    with pytest.raises(NetworkAssertionError, match="scope"):
        check_tgw_routes(rule.ec2, TGW_TABLE, "fe80::1")


@pytest.mark.parametrize("target", ["tgw-attach-", "tgw-attach-a ", "tgw-attach-a\x00"])
def test_malformed_selected_tgw_target_is_not_a_route_mismatch(cloud, target):
    rule, stub = cloud
    searches(stub, "10.47.0.0/16", [route(target=target)])
    with pytest.raises(NetworkAssertionError, match="invalid attachment"):
        check_tgw_routes(rule.ec2, TGW_TABLE, "10.47.0.0/16", via=ATTACHMENT)


def test_longest_prefix_blackhole_inside_supernet(cloud):
    rule, stub = cloud
    searches(
        stub, "10.0.0.0/8", [route()], [route("10.123.45.67/32", state="blackhole", target=None)]
    )
    result = check_tgw_routes(rule.ec2, TGW_TABLE, "10.0.0.0/8")
    assert not result
    assert result.evidence["counterexample"]["first"] == "10.123.45.67"


def test_partial_cidr_cannot_pass(cloud):
    rule, stub = cloud
    searches(stub, "10.1.0.0/24", [], [route("10.1.0.0/25")])
    result = check_tgw_routes(rule.ec2, TGW_TABLE, "10.1.0.0/24")
    assert not result
    assert result.evidence["counterexample"]["first"] == "10.1.0.128"


def test_static_blackhole_wins_over_propagation(cloud):
    rule, stub = cloud
    searches(stub, "10.0.0.0/8", [route(kind="propagated"), route(state="blackhole", target=None)])
    assert not check_tgw_routes(rule.ec2, TGW_TABLE, "10.0.0.0/8")


def test_vpc_propagation_precedes_vpn(cloud):
    rule, stub = cloud
    searches(
        stub,
        "10.0.0.0/8",
        [route(kind="propagated"), route(kind="propagated", resource_type="vpn", target=OTHER)],
    )
    assert check_tgw_routes(rule.ec2, TGW_TABLE, "10.0.0.0/8", via=ATTACHMENT)


def test_same_priority_ambiguous_bgp_routes_raise(cloud):
    rule, stub = cloud
    searches(
        stub,
        "10.0.0.0/8",
        [
            route(kind="propagated", resource_type="vpn"),
            route(kind="propagated", resource_type="vpn", target=OTHER),
        ],
    )
    with pytest.raises(UnsupportedCheckError, match="BGP"):
        check_tgw_routes(rule.ec2, TGW_TABLE, "10.0.0.0/8")


def test_ecmp_members_must_all_match_via(cloud):
    rule, stub = cloud
    item = route(kind="propagated")
    item["TransitGatewayAttachments"].append(
        {"TransitGatewayAttachmentId": OTHER, "ResourceType": "vpc"}
    )
    searches(stub, "10.0.0.0/8", [item])
    assert not check_tgw_routes(rule.ec2, TGW_TABLE, "10.0.0.0/8", via=ATTACHMENT)


@pytest.mark.parametrize(
    "patch",
    [
        {"State": "pending"},
        {"State": "mystery"},
        {"TransitGatewayAttachments": []},
        {"Type": "unknown"},
    ],
)
def test_unknown_or_incomplete_route_never_passes(cloud, patch):
    rule, stub = cloud
    searches(stub, "10.0.0.0/8", [{**route(), **patch}])
    with pytest.raises(NetworkAssertionError):
        check_tgw_routes(rule.ec2, TGW_TABLE, "10.0.0.0/8")


def test_search_pagination_and_deduplication(cloud):
    rule, stub = cloud
    request = {
        "TransitGatewayRouteTableId": TGW_TABLE,
        "Filters": [{"Name": "route-search.supernet-of-match", "Values": ["10.0.0.0/8"]}],
        "MaxResults": 1000,
    }
    stub.add_response(
        "search_transit_gateway_routes",
        {"Routes": [route()], "AdditionalRoutesAvailable": True, "NextToken": "page2"},
        request,
    )
    stub.add_response(
        "search_transit_gateway_routes",
        {"Routes": [route()], "AdditionalRoutesAvailable": False},
        {**request, "NextToken": "page2"},
    )
    stub.add_response(
        "search_transit_gateway_routes",
        {"Routes": [], "AdditionalRoutesAvailable": False},
        {
            **request,
            "Filters": [{"Name": "route-search.subnet-of-match", "Values": ["10.0.0.0/8"]}],
        },
    )
    stub.add_response(
        "get_transit_gateway_prefix_list_references",
        {"TransitGatewayPrefixListReferences": []},
        {"TransitGatewayRouteTableId": TGW_TABLE},
    )
    result = check_tgw_routes(rule.ec2, TGW_TABLE, "10.0.0.0/8")
    assert result
    assert len(result.evidence["routes"]) == 1


def test_truncated_search_without_token_is_unknown(cloud):
    rule, stub = cloud
    stub.add_response(
        "search_transit_gateway_routes", {"Routes": [route()], "AdditionalRoutesAvailable": True}
    )
    with pytest.raises(UnsupportedCheckError, match="truncated"):
        check_tgw_routes(rule.ec2, TGW_TABLE, "10.0.0.0/8")


def test_prefix_list_expands_all_pages(cloud):
    rule, stub = cloud
    item = route()
    item.pop("DestinationCidrBlock")
    item["PrefixListId"] = "pl-12345678"
    searches(stub, "10.1.0.0/24", [item])
    stub.add_response(
        "get_managed_prefix_list_entries",
        {"Entries": [{"Cidr": "10.1.0.0/25"}], "NextToken": "next"},
        {"PrefixListId": "pl-12345678"},
    )
    stub.add_response(
        "get_managed_prefix_list_entries",
        {"Entries": [{"Cidr": "10.1.0.128/25"}]},
        {"PrefixListId": "pl-12345678", "NextToken": "next"},
    )
    assert check_tgw_routes(rule.ec2, TGW_TABLE, "10.1.0.0/24", via=ATTACHMENT)


def test_public_route_checks_owner_and_table(cloud):
    rule, stub = cloud
    live(stub)
    searches(stub, "10.47.0.0/16", [route()])
    result = rule.tgw(TGW).route_table(TGW_TABLE).has_route_to("10.47.0.0/16", via=ATTACHMENT)
    assert result
    assert result.evidence["account_id"] == ACCOUNT
    assert result.evidence["transit_gateway_route_table"]["TransitGatewayId"] == TGW


def test_wrong_tgw_owner_stops_before_route_reads(cloud):
    rule, stub = cloud
    stub.add_response(
        "describe_transit_gateways",
        {
            "TransitGateways": [
                {"TransitGatewayId": TGW, "OwnerId": "999999999999", "State": "available"}
            ]
        },
    )
    with pytest.raises(NetworkAssertionError, match="OwnerId"):
        rule.tgw(TGW).route_table(TGW_TABLE).has_route_to("10.0.0.0/8")


@pytest.mark.parametrize(
    "associated,passed", [("associated", True), ("associating", False), (None, False)]
)
def test_attachment_association_with_shared_vpc_owner(cloud, associated, passed):
    rule, stub = cloud
    live(stub)
    attachment = {
        "TransitGatewayAttachmentId": ATTACHMENT,
        "TransitGatewayId": TGW,
        "TransitGatewayOwnerId": ACCOUNT,
        "ResourceOwnerId": "999999999999",
        "ResourceId": "vpc-1",
        "ResourceType": "vpc",
        "State": "available",
    }
    stub.add_response(
        "describe_transit_gateway_attachments",
        {"TransitGatewayAttachments": [attachment]},
        {"TransitGatewayAttachmentIds": [ATTACHMENT]},
    )
    request = {
        "TransitGatewayRouteTableId": TGW_TABLE,
        "Filters": [{"Name": "transit-gateway-attachment-id", "Values": [ATTACHMENT]}],
    }
    stub.add_response(
        "get_transit_gateway_route_table_associations",
        {"Associations": [], "NextToken": "next"},
        request,
    )
    rows = (
        []
        if associated is None
        else [
            {
                key: attachment[key]
                for key in ("TransitGatewayAttachmentId", "ResourceId", "ResourceType")
            }
            | {"State": associated}
        ]
    )
    stub.add_response(
        "get_transit_gateway_route_table_associations",
        {"Associations": rows},
        {**request, "NextToken": "next"},
    )
    result = rule.tgw(TGW).route_table(TGW_TABLE).has_association(ATTACHMENT)
    assert bool(result) is passed


def test_both_route_directions_are_evaluated(cloud):
    rule, stub = cloud
    table = rule.tgw(TGW).route_table(TGW_TABLE)
    live(stub)
    searches(stub, "10.47.0.0/16", [])
    live(stub)
    searches(stub, "10.1.0.0/16", [route()])
    result = table.has_bidirectional_routes(
        "10.47.0.0/16", source="10.1.0.0/16", return_table=table
    )
    assert not result
    assert result.to_dict()["evidence"]["return"]["passed"]


def test_aws_permission_errors_propagate(cloud):
    rule, stub = cloud
    stub.add_client_error(
        "search_transit_gateway_routes", service_error_code="UnauthorizedOperation"
    )
    with pytest.raises(ClientError):
        check_tgw_routes(rule.ec2, TGW_TABLE, "10.0.0.0/8")


@pytest.mark.parametrize("blackhole", [False, True])
def test_prefix_reference_is_not_assumed_visible_in_cidr_search(cloud, blackhole):
    rule, stub = cloud
    for name in ("supernet", "subnet"):
        stub.add_response(
            "search_transit_gateway_routes",
            {"Routes": [], "AdditionalRoutesAvailable": False},
            {
                "TransitGatewayRouteTableId": TGW_TABLE,
                "MaxResults": 1000,
                "Filters": [{"Name": f"route-search.{name}-of-match", "Values": ["10.0.0.0/8"]}],
            },
        )
    request = {"TransitGatewayRouteTableId": TGW_TABLE}
    stub.add_response(
        "get_transit_gateway_prefix_list_references",
        {"TransitGatewayPrefixListReferences": [], "NextToken": "next"},
        request,
    )
    reference = {
        "TransitGatewayRouteTableId": TGW_TABLE,
        "PrefixListId": "pl-12345678",
        "PrefixListOwnerId": "999999999999",
        "State": "available",
        "Blackhole": blackhole,
    }
    if not blackhole:
        reference["TransitGatewayAttachment"] = {
            "TransitGatewayAttachmentId": ATTACHMENT,
            "ResourceType": "vpc",
        }
    stub.add_response(
        "get_transit_gateway_prefix_list_references",
        {"TransitGatewayPrefixListReferences": [reference]},
        {**request, "NextToken": "next"},
    )
    stub.add_response(
        "get_managed_prefix_list_entries",
        {"Entries": [{"Cidr": "10.0.0.0/8"}]},
        {"PrefixListId": "pl-12345678"},
    )
    result = check_tgw_routes(rule.ec2, TGW_TABLE, "10.0.0.0/8", via=ATTACHMENT)
    assert bool(result) is not blackhole


def test_paired_tgw_directions_require_same_address_family():
    rule = make_rule(account_id=ACCOUNT)
    table = rule.tgw(TGW).route_table(TGW_TABLE)
    with pytest.raises(ValueError, match="same address family"):
        table.has_bidirectional_routes("2001:db8::/32", source="10.0.0.0/8", return_table=table)


def test_scoped_propagation_must_verify_actual_tgw_owner(cloud):
    rule, stub = cloud
    stub.add_response(
        "describe_transit_gateways",
        {
            "TransitGateways": [
                {"TransitGatewayId": TGW, "OwnerId": "999999999999", "State": "available"}
            ]
        },
        {"TransitGatewayIds": [TGW]},
    )
    with pytest.raises(NetworkAssertionError, match="OwnerId"):
        rule.tgw(TGW).propagates(TGW_TABLE).from_vpc("vpc-1")


def test_scoped_propagation_uses_verified_owner_and_table_identity(cloud):
    rule, stub = cloud
    live(stub)
    stub.add_response(
        "get_transit_gateway_route_table_propagations",
        {
            "TransitGatewayRouteTablePropagations": [
                {
                    "ResourceId": "vpc-1",
                    "ResourceType": "vpc",
                    "State": "enabled",
                    "TransitGatewayAttachmentId": ATTACHMENT,
                }
            ]
        },
        {
            "TransitGatewayRouteTableId": TGW_TABLE,
            "Filters": [
                {"Name": "resource-id", "Values": ["vpc-1"]},
                {"Name": "resource-type", "Values": ["vpc"]},
            ],
        },
    )
    assert rule.tgw(TGW).propagates(TGW_TABLE).from_vpc("vpc-1")
