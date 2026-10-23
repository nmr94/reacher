"""Run fixed protocol operations on an existing managed Linux instance."""

import pytest

from aws_network_asserts import expect, get
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


def test_the_managed_host_can_get_a_healthy_response(pytestconfig, request, aws_value):
    if not pytestconfig.getoption("--allow-ssm-commands"):
        pytest.skip("Use --allow-ssm-commands to authorize code execution on the instance")
    instance = aws_value("SOURCE_INSTANCE")
    url = aws_value("PROBE_HEALTH_URL")
    rule = request.getfixturevalue("rule")
    with (
        rule.instance(instance)
        .named("managed application host")
        .ssm_probe_session(
            allow_write=True,
        ) as probe
    ):
        expect(probe).to(get(url).returning_status(200))
