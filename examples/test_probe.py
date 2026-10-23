"""An observed TCP check; requires both --run-aws and --allow-probe-writes."""

import os

import pytest

from aws_network_asserts import connect_to, expect
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


def test_tcp_from_vpc(pytestconfig, request, aws_value):
    if not pytestconfig.getoption("--allow-probe-writes"):
        pytest.skip("Use --allow-probe-writes to permit temporary Lambda resources")
    subnet = aws_value("SOURCE_SUBNET")
    host = aws_value("DESTINATION_HOST")
    auto_role = pytestconfig.getoption("--auto-create-execution-role")
    auto_group = pytestconfig.getoption("--auto-create-security-group")
    role = None if auto_role else aws_value("PROBE_EXECUTION_ROLE_ARN")
    groups = (
        None
        if auto_group
        else [group.strip() for group in aws_value("PROBE_SECURITY_GROUP_IDS").split(",")]
    )
    rule = request.getfixturevalue("rule")
    with rule.subnet(subnet).probe_session(
        execution_role_arn=role,
        auto_create_execution_role=auto_role,
        security_group_ids=groups,
        auto_create_security_group=auto_group,
        allow_write=True,  # Explicit permission at the call site, never a builder default.
    ) as probe:
        expect(probe).to(connect_to(host).over_tcp(int(os.getenv("DESTINATION_PORT", "443"))))
