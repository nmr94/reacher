"""Cross-region topology tests; these do not claim an end-to-end RA analysis.

Set REGION_A, REGION_B, VPC_A, VPC_B, SUBNET_A, SUBNET_B, CIDR_A, CIDR_B,
and PEERING_ID. Same-region packet checks additionally use SOURCE_ENI_A/B and
DESTINATION_ENI_A/B. Uses NETWORK_ACCOUNT_ID by default; ACCOUNT_A/B can select
different owners. Nothing is provisioned by these tests.
"""

import os

import pytest

from aws_network_asserts import be_peered_with, expect, have_route_to, reach
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


def scoped(rule, aws_value, side):
    regional = rule.in_region(aws_value(f"REGION_{side}"))
    account_id = os.getenv(f"ACCOUNT_{side}")
    return regional.in_account(account_id) if account_id else regional


def test_cross_region_peering(rule, aws_value):
    a = scoped(rule, aws_value, "A")
    b = scoped(rule, aws_value, "B")
    expect(a.vpc(aws_value("VPC_A"))).to(be_peered_with(b.vpc(aws_value("VPC_B"))))


@pytest.mark.parametrize("source,destination", [("A", "B"), ("B", "A")])
def test_routes_in_both_regions(rule, aws_value, source, destination):
    regional = scoped(rule, aws_value, source)
    expect(regional.subnet(aws_value(f"SUBNET_{source}"))).to(
        have_route_to(aws_value(f"CIDR_{destination}")).via(aws_value("PEERING_ID"))
    )


@pytest.mark.parametrize("side", ["A", "B"])
def test_regional_reachability(rule, aws_value, side):
    regional = scoped(rule, aws_value, side)
    expect(regional.eni(aws_value(f"SOURCE_ENI_{side}"))).to(
        reach(regional.eni(aws_value(f"DESTINATION_ENI_{side}"))).over_tcp(443)
    )
