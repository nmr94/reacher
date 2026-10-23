"""Environment-configured examples. See README for invocation and charges."""

import os

import pytest

from aws_network_asserts import (
    be_peered_with,
    be_recorded,
    expect,
    have_route_to,
    propagate_to,
    reach,
)
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


def test_eni_can_reach_service(rule, aws_value):
    expect(rule.eni(aws_value("SOURCE_ENI")).named("source")).to(
        reach(aws_value("DESTINATION_IP")).over_tcp(int(os.getenv("DESTINATION_PORT", "443")))
    )


def test_eni_cannot_reach_blocked_service(rule, aws_value):
    expect(rule.eni(aws_value("SOURCE_ENI")).named("source")).not_to(
        reach(aws_value("BLOCKED_IP")).over_tcp(int(os.getenv("BLOCKED_PORT", "22")))
    )


def test_subnet_has_route(rule, aws_value):
    route = have_route_to(aws_value("DESTINATION_CIDR"))
    if target := os.getenv("ROUTE_TARGET"):
        route = route.via(target)
    expect(rule.subnet(aws_value("SOURCE_SUBNET"))).to(route)


def test_vpcs_are_peered(rule, aws_value):
    expect(rule.vpc(aws_value("SOURCE_VPC"))).to(be_peered_with(aws_value("PEER_VPC")))


def test_vpc_propagates_into_tgw_table(rule, aws_value):
    expect(rule.tgw(aws_value("TRANSIT_GATEWAY"))).to(
        propagate_to(aws_value("TGW_ROUTE_TABLE")).from_vpc(aws_value("SOURCE_VPC"))
    )


def test_source_is_recorded(rule, aws_value):
    if rule.config_mode == "off":
        pytest.skip("Config is disabled for this run")
    expect(rule.eni(aws_value("SOURCE_ENI"))).to(be_recorded())
