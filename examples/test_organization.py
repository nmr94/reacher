"""Organization examples using one aggregator and member profiles or MiniStack sessions.

Set ACCOUNT_A/B, SOURCE_ENI_A/B, and optionally REGION_A/B for Config checks.
The cross-account RA check uses SOURCE_ENI_A and DESTINATION_ENI_B in the single
ORGANIZATION_TEST_REGION (defaults to --aws-region). Peering uses VPC_A/B and
REGION_A/B and needs credentials for ACCOUNT_A. With --ministack the shared
fixture supplies account sessions instead of profiles. RA creates temporary
analysis objects; these tests do not provision network resources.
"""

import os

import pytest

from aws_network_asserts import be_peered_with, be_recorded, expect, reach
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


@pytest.mark.parametrize("side", ["A", "B"])
def test_member_inventory_uses_central_aggregator(org_rule, aws_value, side):
    if org_rule.config_mode == "off":
        pytest.skip("Config is disabled for this run")
    account = org_rule.in_account(aws_value(f"ACCOUNT_{side}"))
    region = os.getenv(f"REGION_{side}") or org_rule.region_name
    expect(account.in_region(region).eni(aws_value(f"SOURCE_ENI_{side}"))).to(be_recorded())


def test_cross_account_reachability_uses_central_analysis(org_rule, aws_value):
    region = os.getenv("ORGANIZATION_TEST_REGION") or org_rule.region_name
    regional = org_rule.in_region(region)
    source = regional.in_account(aws_value("ACCOUNT_A")).eni(aws_value("SOURCE_ENI_A"))
    target = regional.in_account(aws_value("ACCOUNT_B")).eni(aws_value("DESTINATION_ENI_B"))
    expect(source.named("application")).to(
        reach(target.named("destination")).over_tcp(int(os.getenv("DESTINATION_PORT", "443")))
    )


def test_cross_account_peering_uses_source_member_credentials(org_rule, aws_value):
    a = org_rule.in_account(aws_value("ACCOUNT_A")).in_region(aws_value("REGION_A"))
    b = org_rule.in_account(aws_value("ACCOUNT_B")).in_region(aws_value("REGION_B"))
    expect(a.vpc(aws_value("VPC_A"))).to(be_peered_with(b.vpc(aws_value("VPC_B"))))
