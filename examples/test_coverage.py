"""Declare discovery and the complete finite RA grid before running it."""

import json
import os

import pytest

from aws_network_asserts import (
    contain_exactly_resources,
    every,
    expect,
    have_route_to,
    reach_each,
)
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


def test_every_application_can_reach_every_database(rule, aws_value):
    if rule.account_id is None:
        pytest.skip("Set NETWORK_ACCOUNT_ID to scope discovered and expected ENIs")
    expected = [rule.eni(value.strip()) for value in aws_value("EXPECTED_SOURCE_ENIS").split(",")]
    destinations = [rule.eni(value.strip()) for value in aws_value("DESTINATION_ENIS").split(",")]
    ports = [int(value.strip()) for value in aws_value("REACHABILITY_PORTS").split(",")]
    cap = int(os.getenv("MAX_REACHABILITY_ANALYSES", "100"))
    actual = rule.subnet(aws_value("SOURCE_SUBNET")).enis()
    expect(actual).to(contain_exactly_resources(*expected))
    requirement = reach_each(destinations).over_tcp(*ports)
    print(json.dumps(expect(every(actual)).plan(requirement), indent=2))
    expect(every(actual)).to(requirement, max_ra_analyses=cap)


def test_the_route_remains_available_for_three_samples(rule, aws_value):
    route = have_route_to(aws_value("DESTINATION_CIDR")).via(aws_value("ROUTE_TARGET"))
    expect(rule.subnet(aws_value("SOURCE_SUBNET"))).to(route.consistently(checks=3, interval=1))
