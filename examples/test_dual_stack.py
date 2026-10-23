"""Observed IPv4 and IPv6 health checks from an existing dual-stack subnet."""

import pytest

from aws_network_asserts import expect, get
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


def test_both_address_families_serve_the_health_endpoint(pytestconfig, request, aws_value):
    if not pytestconfig.getoption("--allow-probe-writes"):
        pytest.skip("Use --allow-probe-writes to permit temporary Lambda resources")
    subnet = aws_value("SOURCE_SUBNET")
    url = aws_value("PROBE_DUAL_STACK_URL")
    cidrs = [value.strip() for value in aws_value("PROBE_DUAL_STACK_ALLOWED_CIDRS").split(",")]
    auto_role = pytestconfig.getoption("--auto-create-execution-role")
    auto_group = pytestconfig.getoption("--auto-create-security-group")
    role = None if auto_role else aws_value("PROBE_EXECUTION_ROLE_ARN")
    groups = None if auto_group else aws_value("PROBE_SECURITY_GROUP_IDS").split(",")
    rule = request.getfixturevalue("rule")
    with (
        rule.subnet(subnet)
        .named("dual-stack source")
        .probe_session(
            allow_write=True,
            address_family="dual",
            execution_role_arn=role,
            auto_create_execution_role=auto_role,
            security_group_ids=[value.strip() for value in groups] if groups is not None else None,
            auto_create_security_group=auto_group,
        ) as probe
    ):
        expect(probe).to(
            get(url, address_family="dual", allowed_destination_cidrs=cidrs)
            .returning_status(200)
            .for_every_address()
        )
