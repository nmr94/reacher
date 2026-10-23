"""Inspection matchers preflight scope and preserve literal topology claims."""

from unittest.mock import Mock

import boto3
import pytest

from aws_network_asserts import (
    CheckResult,
    RuleBuilder,
    UnsupportedCheckError,
    expect,
    have_appliance_mode,
    have_bidirectional_routes,
    have_firewall_endpoints,
    have_route_to,
)
from aws_network_asserts.builder import RouteTableRule, TransitGatewayRule, VpcRule

ACCOUNT = "111111111111"
REGION = "eu-west-2"
FIREWALL = f"arn:aws:network-firewall:{REGION}:{ACCOUNT}:firewall/inspection"


@pytest.fixture
def rule():
    session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION
    )
    return RuleBuilder(session=session, account_id=ACCOUNT, config_mode="off")


def test_appliance_matcher_has_no_analysis_cost_and_evaluates_fresh(rule, monkeypatch):
    check = Mock(return_value=CheckResult(True, "available enabled attachment"))
    monkeypatch.setattr(TransitGatewayRule, "has_appliance_mode", check)
    source = rule.tgw("tgw-hub")
    matcher = have_appliance_mode("vpc-inspection")
    assert expect(source).plan(matcher)["max_ra_analyses"] == 0
    check.assert_not_called()
    expect(source).to(matcher, max_ra_analyses=0)
    check.assert_called_once_with("vpc-inspection")


def test_firewall_matcher_snapshots_layout_and_preserves_aws_errors(rule, monkeypatch):
    layout = {f"{REGION}a": "subnet-a"}
    matcher = have_firewall_endpoints(FIREWALL, subnets_by_az=layout)
    layout[f"{REGION}a"] = "subnet-changed"
    check = Mock(return_value=CheckResult(True, "ready exact layout"))
    monkeypatch.setattr(VpcRule, "has_firewall_endpoints", check)
    expect(rule.vpc("vpc-inspection")).to(matcher)
    check.assert_called_once_with(FIREWALL, subnets_by_az={f"{REGION}a": "subnet-a"})
    error = RuntimeError("AWS unavailable")
    check.side_effect = error
    with pytest.raises(RuntimeError) as caught:
        expect(rule.vpc("vpc-inspection")).to(matcher)
    assert caught.value is error


def test_firewall_negation_cannot_turn_incomplete_coverage_into_no_inspection(rule, monkeypatch):
    check = Mock()
    monkeypatch.setattr(VpcRule, "has_firewall_endpoints", check)
    with pytest.raises(UnsupportedCheckError, match="incomplete endpoint"):
        expect(rule.vpc("vpc-inspection")).not_to(
            have_firewall_endpoints(FIREWALL, subnets_by_az={f"{REGION}a": "subnet-a"})
        )
    check.assert_not_called()


def test_firewall_plan_checks_scope_before_any_lookup(rule):
    with pytest.raises(ValueError, match="selected account and region"):
        expect(rule.vpc("vpc-inspection")).plan(
            have_firewall_endpoints(
                FIREWALL.replace(ACCOUNT, "222222222222"),
                subnets_by_az={f"{REGION}a": "subnet-a"},
            )
        )


def test_paired_route_matcher_passes_both_explicit_directions(rule, monkeypatch):
    check = Mock(return_value=CheckResult(True, "both effective routes matched"))
    monkeypatch.setattr(RouteTableRule, "has_bidirectional_routes", check)
    return_table = rule.route_table("rtb-return")
    matcher = have_bidirectional_routes(
        "10.50.0.0/16",
        source="10.40.0.0/16",
        return_table=return_table,
        via="vpce-a",
        return_via="vpce-a",
    )
    source = rule.route_table("rtb-forward")
    assert expect(source).plan(matcher)["case_count"] == 1
    expect(source).to(matcher)
    check.assert_called_once_with(
        "10.50.0.0/16",
        source="10.40.0.0/16",
        return_table=return_table,
        via="vpce-a",
        return_via="vpce-a",
    )
    check.reset_mock()
    with pytest.raises(UnsupportedCheckError, match="Incomplete paired"):
        expect(source).not_to(matcher)
    check.assert_not_called()


def test_paired_route_plan_rejects_cross_region_or_tgw_scope(rule):
    with pytest.raises(ValueError, match="one region"):
        expect(rule.subnet("subnet-forward")).plan(
            have_bidirectional_routes(
                "10.50.0.0/16",
                source="10.40.0.0/16",
                return_table=rule.in_region("us-east-1").subnet("subnet-return"),
            )
        )
    with pytest.raises(ValueError, match="same scoped TGW"):
        expect(rule.tgw("tgw-forward").route_table("tgw-rtb-forward")).plan(
            have_bidirectional_routes(
                "10.50.0.0/16",
                source="10.40.0.0/16",
                return_table=rule.tgw("tgw-unrelated").route_table("tgw-rtb-return"),
            )
        )


@pytest.mark.parametrize("layout", [{}, {f"{REGION}a": "subnet-a", f"{REGION}b": "subnet-a"}])
def test_empty_or_duplicate_firewall_declarations_are_not_matchers(layout):
    with pytest.raises(ValueError):
        have_firewall_endpoints(FIREWALL, subnets_by_az=layout)


def test_scoped_route_matcher_is_rejected_during_construction():
    with pytest.raises(ValueError, match="scope"):
        have_route_to("fe80::1%wrong-interface")


@pytest.mark.parametrize("scoped", ["source", "destination"])
def test_scoped_route_pair_matcher_is_rejected_during_construction(rule, scoped):
    ranges = {"source": "fe80::1/128", "destination": "fe80::2/128"}
    ranges[scoped] = "fe80::1%wrong-interface/128"
    with pytest.raises(ValueError, match="scope"):
        have_bidirectional_routes(
            ranges["destination"],
            source=ranges["source"],
            return_table=rule.route_table("rtb-return"),
        )
