"""Regressions for route selection that could falsely claim reachability."""

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from aws_network_asserts.errors import NetworkAssertionError, UnsupportedCheckError
from aws_network_asserts.routes import check_routes


def route(cidr, target="igw-12345678", *, state="active", origin="CreateRoute"):
    field = "DestinationIpv6CidrBlock" if ":" in cidr else "DestinationCidrBlock"
    return {field: cidr, "GatewayId": target, "State": state, "Origin": origin}


def table(*routes):
    return {"RouteTableId": "rtb-12345678", "Routes": list(routes)}


@pytest.fixture
def ec2():
    return boto3.client(
        "ec2",
        region_name="eu-west-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def test_specific_blackhole_beats_active_default():
    result = check_routes(
        None,
        table(route("0.0.0.0/0"), route("10.1.0.0/16", state="blackhole")),
        "10.1.1.1/32",
    )
    assert not result
    assert "blackhole" in result.message
    assert result.evidence["counterexample"]["first"] == "10.1.1.1"


@pytest.mark.parametrize("via", [" nat-a", "nat-a ", "nat-\ta", "nat-\x00a", "nat-\x1ba"])
def test_malformed_target_expectations_are_errors_not_route_mismatches(via):
    with pytest.raises(ValueError, match="via"):
        check_routes(None, table(route("0.0.0.0/0", "nat-a")), "10.1.1.1", via=via)


@pytest.mark.parametrize("target", [" nat-a", "nat-a ", "nat-\ta", "nat-\x00a", "nat-\x1ba"])
def test_malformed_selected_target_cannot_produce_a_conclusive_route_result(target):
    with pytest.raises(NetworkAssertionError, match="Invalid route target"):
        check_routes(None, table(route("0.0.0.0/0", target)), "10.1.1.1", via="nat-a")


@pytest.mark.parametrize(
    "kind,identifier",
    [
        ("natgateway", "nat-egress"),
        ("transit-gateway", "tgw-hub"),
        ("internet-gateway", "igw-egress"),
    ],
)
def test_ec2_arn_target_cannot_be_reported_as_a_conclusive_route_mismatch(kind, identifier):
    arn = f"arn:aws:ec2:eu-west-2:111111111111:{kind}/{identifier}"
    with pytest.raises(UnsupportedCheckError, match="native EC2 target ID"):
        check_routes(None, table(route("0.0.0.0/0", identifier)), "10.1.1.1", via=arn)


@pytest.mark.parametrize("via", ["arn:aws:ec2", "arn:aws:networkmanager::wrong:core-network/id"])
def test_malformed_route_arn_is_rejected(via):
    with pytest.raises(ValueError):
        check_routes(None, table(route("0.0.0.0/0")), "10.1.1.1", via=via)


def test_native_arn_route_target_still_uses_exact_matching():
    arn = "arn:aws:networkmanager::111111111111:core-network/core-network-12345678"
    entry = {"DestinationCidrBlock": "0.0.0.0/0", "CoreNetworkArn": arn, "State": "active"}
    assert check_routes(None, table(entry), "10.1.1.1", via=arn)


@pytest.mark.parametrize(
    "supernet, destination",
    [("10.0.0.0/8", "10.47.0.0/16"), ("2001:db8::/32", "2001:db8:47::/48")],
)
def test_supernet_covers_requested_network_without_an_exact_route(supernet, destination):
    result = check_routes(None, table(route(supernet, "tgw-hub")), destination, via="tgw-hub")
    assert result
    assert result.evidence["coverage"][0]["prefix"] == supernet


def test_cidr_requires_every_address_not_just_first():
    result = check_routes(None, table(route("10.1.0.0/25")), "10.1.0.0/24")
    assert not result
    assert result.evidence["counterexample"]["first"] == "10.1.0.128"


def test_multiple_routes_can_jointly_cover_a_cidr():
    result = check_routes(None, table(route("10.1.0.0/25"), route("10.1.0.128/25")), "10.1.0.0/24")
    assert result
    assert len(result.evidence["coverage"]) == 2


def test_small_blackhole_inside_large_network_fails_complete_coverage():
    result = check_routes(
        None,
        table(route("10.0.0.0/8"), route("10.123.45.67/32", state="blackhole")),
        "10.0.0.0/8",
    )
    assert not result
    assert result.evidence["counterexample"]["first"] == "10.123.45.67"


def test_via_applies_to_all_effective_routes():
    result = check_routes(
        None,
        table(route("10.1.0.0/24", "tgw-first"), route("10.1.0.128/25", "tgw-second")),
        "10.1.0.0/24",
        via="tgw-first",
    )
    assert not result
    assert "expected tgw-first" in result.message
    assert result.evidence["counterexample"]["first"] == "10.1.0.128"


def test_via_matches_instance_or_network_interface_alias():
    selected = route("10.0.0.0/8")
    selected.pop("GatewayId")
    selected.update(InstanceId="i-nat", NetworkInterfaceId="eni-nat")
    assert check_routes(None, table(selected), "10.1.1.1", via="i-nat")
    assert check_routes(None, table(selected), "10.1.1.1", via="eni-nat")


def test_ipv6_is_not_covered_by_ipv4_default():
    assert not check_routes(None, table(route("0.0.0.0/0")), "2001:db8::1")


def test_ipv6_default_uses_finite_intervals_even_for_entire_address_space():
    result = check_routes(None, table(route("::/0")), "::/0")
    assert result
    assert len(result.evidence["coverage"]) == 1
    assert result.evidence["coverage"][0]["last"] == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"


def test_static_route_beats_same_prefix_propagated_route():
    result = check_routes(
        None,
        table(
            route("10.0.0.0/8", "vgw-propagated", origin="EnableVgwRoutePropagation"),
            route("10.0.0.0/8", "igw-static", state="blackhole"),
        ),
        "10.2.3.4",
    )
    assert not result
    assert "blackhole" in result.message


def test_unknown_origin_is_ok_without_a_priority_tie():
    selected = route("10.0.0.0/8", "eni-server", origin="Advertisement")
    assert check_routes(None, table(selected), "10.1.1.1")


def test_unknown_origin_tie_raises_instead_of_guessing():
    with pytest.raises(UnsupportedCheckError, match="origin"):
        check_routes(
            None,
            table(
                route("10.0.0.0/8", "eni-server", origin="Advertisement"),
                route("10.0.0.0/8", "igw-static"),
            ),
            "10.1.1.1",
        )


@pytest.mark.parametrize("state", [None, "pending", ""])
def test_missing_or_unknown_state_is_error(state):
    with pytest.raises(NetworkAssertionError, match="state"):
        check_routes(None, table(route("10.0.0.0/8", state=state)), "10.1.1.1")


def test_active_route_without_known_target_is_error():
    with pytest.raises(NetworkAssertionError, match="no recognized target"):
        check_routes(
            None,
            table({"DestinationCidrBlock": "10.0.0.0/8", "State": "active"}),
            "10.1.1.1",
        )


def test_blackhole_can_have_no_target():
    result = check_routes(
        None,
        table({"DestinationCidrBlock": "10.0.0.0/8", "State": "blackhole"}),
        "10.1.1.1",
    )
    assert not result


@pytest.mark.parametrize(
    "bad_table",
    [
        {},
        {"Routes": None},
        table({"State": "active"}),
        table({"DestinationCidrBlock": "bad-ip", "State": "active"}),
        table({"DestinationCidrBlock": "::/0", "State": "active"}),
        table({"DestinationIpv6CidrBlock": "10.0.0.0/8", "State": "active"}),
        table({"DestinationCidrBlock": "10.0.0.0/8", "DestinationPrefixListId": "pl-1"}),
    ],
)
def test_incomplete_route_data_never_passes_or_proves_isolation(bad_table):
    with pytest.raises(NetworkAssertionError):
        check_routes(None, bad_table, "10.1.1.1")


@pytest.mark.parametrize("destination", ["", "invalid", "10.1.1.1/33", None, 123])
def test_invalid_destination_is_rejected(destination):
    with pytest.raises(ValueError):
        check_routes(None, table(), destination)


def test_empty_table_is_a_conclusive_missing_route():
    assert not check_routes(None, table(), "10.1.1.1")


def prefix_route(prefix_id, *, target="vpce-12345678", state="active"):
    return {
        "DestinationPrefixListId": prefix_id,
        "GatewayId": target,
        "State": state,
        "Origin": "CreateRoute",
    }


def test_prefix_list_paginated_more_specific_blackhole_beats_default(ec2):
    with Stubber(ec2) as stub:
        stub.add_response(
            "get_managed_prefix_list_entries",
            {"Entries": [{"Cidr": "192.0.2.0/24"}], "NextToken": "next"},
            {"PrefixListId": "pl-12345678"},
        )
        stub.add_response(
            "get_managed_prefix_list_entries",
            {"Entries": [{"Cidr": "10.0.0.0/8"}]},
            {"PrefixListId": "pl-12345678", "NextToken": "next"},
        )
        result = check_routes(
            ec2,
            table(route("0.0.0.0/0"), prefix_route("pl-12345678", state="blackhole")),
            "10.1.1.1",
        )
        assert not result
        assert "blackhole" in result.message
        stub.assert_no_pending_responses()


def test_prefix_list_wins_same_prefix_propagated_route(ec2):
    with Stubber(ec2) as stub:
        stub.add_response(
            "get_managed_prefix_list_entries",
            {"Entries": [{"Cidr": "10.0.0.0/8"}]},
            {"PrefixListId": "pl-12345678"},
        )
        result = check_routes(
            ec2,
            table(
                route("10.0.0.0/8", "vgw-propagated", origin="EnableVgwRoutePropagation"),
                prefix_route("pl-12345678", state="blackhole"),
            ),
            "10.1.1.1",
        )
        assert not result


def test_static_cidr_wins_same_prefix_prefix_list(ec2):
    with Stubber(ec2) as stub:
        stub.add_response(
            "get_managed_prefix_list_entries",
            {"Entries": [{"Cidr": "10.0.0.0/8"}]},
            {"PrefixListId": "pl-12345678"},
        )
        result = check_routes(
            ec2,
            table(route("10.0.0.0/8"), prefix_route("pl-12345678", state="blackhole")),
            "10.1.1.1",
            via="igw-12345678",
        )
        assert result


def test_tied_prefix_lists_with_different_targets_are_not_guessed(ec2):
    with Stubber(ec2) as stub:
        for prefix_id in ("pl-11111111", "pl-22222222"):
            stub.add_response(
                "get_managed_prefix_list_entries",
                {"Entries": [{"Cidr": "10.0.0.0/8"}]},
                {"PrefixListId": prefix_id},
            )
        with pytest.raises(UnsupportedCheckError, match="Ambiguous"):
            check_routes(
                ec2,
                table(
                    prefix_route("pl-11111111", target="vpce-first"),
                    prefix_route("pl-22222222", target="vpce-second"),
                ),
                "10.1.1.1",
            )


def test_prefix_list_permission_error_is_not_a_negative_result(ec2):
    with Stubber(ec2) as stub:
        stub.add_client_error(
            "get_managed_prefix_list_entries",
            service_error_code="UnauthorizedOperation",
            expected_params={"PrefixListId": "pl-12345678"},
        )
        with pytest.raises(ClientError):
            check_routes(ec2, table(prefix_route("pl-12345678")), "10.1.1.1")


@pytest.mark.parametrize("via", [None, "igw-12345678", "tgw-second"])
def test_conflicting_route_targets_cannot_pass_even_when_one_matches(via):
    selected = route("10.0.0.0/8")
    selected["TransitGatewayId"] = "tgw-second"
    with pytest.raises(UnsupportedCheckError, match="Ambiguous route targets"):
        check_routes(None, table(selected), "10.1.1.1", via=via)


@pytest.mark.parametrize("destination", ["fe80::1%wrong-interface", "fe80::%wrong-interface/64"])
def test_scoped_ipv6_destination_cannot_pass_unscoped_default_route(destination):
    with pytest.raises(ValueError, match="scope"):
        check_routes(None, table(route("::/0")), destination)


def test_scoped_native_route_cidr_is_an_evaluation_error():
    with pytest.raises(NetworkAssertionError, match="scope"):
        check_routes(None, table(route("fe80::%wrong-interface/64")), "fe80::1")


def test_scoped_prefix_list_cidr_is_an_evaluation_error(ec2):
    with Stubber(ec2) as stub:
        stub.add_response(
            "get_managed_prefix_list_entries",
            {"Entries": [{"Cidr": "fe80::%wrong-interface/64"}]},
            {"PrefixListId": "pl-12345678"},
        )
        with pytest.raises(NetworkAssertionError, match="scope"):
            check_routes(ec2, table(prefix_route("pl-12345678")), "fe80::1")
        stub.assert_no_pending_responses()
