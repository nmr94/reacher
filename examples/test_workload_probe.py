"""Copy a live workload's verified network context into a temporary Lambda."""

import os

import pytest

from aws_network_asserts import expect, get
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


@pytest.mark.parametrize("kind", ["eni", "instance"])
def test_the_workload_network_can_get_a_healthy_response(pytestconfig, request, aws_value, kind):
    if not pytestconfig.getoption("--allow-probe-writes"):
        pytest.skip("Use --allow-probe-writes to permit temporary Lambda resources")
    if pytestconfig.getoption("--auto-create-security-group"):
        raise pytest.UsageError(
            "Workload probes derive their groups; omit --auto-create-security-group"
        )
    source_id = aws_value("SOURCE_ENI" if kind == "eni" else "SOURCE_INSTANCE")
    url = aws_value("PROBE_HEALTH_URL")
    auto_role = pytestconfig.getoption("--auto-create-execution-role")
    role = None if auto_role else aws_value("PROBE_EXECUTION_ROLE_ARN")
    rule = request.getfixturevalue("rule")
    source = getattr(rule, kind)(source_id).named("application workload")
    interface = os.getenv("PROBE_NETWORK_INTERFACE_ID") if kind == "instance" else None
    selection = {"network_interface_id": interface} if interface else {}
    with source.probe_session(
        allow_write=True,
        execution_role_arn=role,
        auto_create_execution_role=auto_role,
        **selection,
    ) as probe:
        expect(probe).to(get(url).returning_status(200))
