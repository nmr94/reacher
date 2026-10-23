"""Opt-in application traffic; set explicit targets and enable both write flags."""

import pytest

from aws_network_asserts import establish_tls, expect, get, resolve
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


def test_protocols_from_one_deployment(pytestconfig, request, aws_value):
    if not pytestconfig.getoption("--allow-probe-writes"):
        pytest.skip("Use --allow-probe-writes to permit temporary Lambda resources")
    subnet = aws_value("SOURCE_SUBNET")
    host = aws_value("PROBE_TLS_HOST")
    url = aws_value("PROBE_HEALTH_URL")
    allowed_cidrs = aws_value("PROBE_DNS_ALLOWED_CIDRS").split(",")
    auto_role = pytestconfig.getoption("--auto-create-execution-role")
    auto_group = pytestconfig.getoption("--auto-create-security-group")
    role = None if auto_role else aws_value("PROBE_EXECUTION_ROLE_ARN")
    groups = None if auto_group else aws_value("PROBE_SECURITY_GROUP_IDS").split(",")
    rule = request.getfixturevalue("rule")
    with rule.subnet(subnet).probe_session(
        allow_write=True,  # Explicitly permits deployment and its cleanup in this test.
        execution_role_arn=role,
        auto_create_execution_role=auto_role,
        security_group_ids=[value.strip() for value in groups] if groups is not None else None,
        auto_create_security_group=auto_group,
    ) as probe:
        cidrs = [value.strip() for value in allowed_cidrs]
        expect(probe).to(resolve(host).within_cidrs(*cidrs))
        expect(probe).to(establish_tls(host, allowed_destination_cidrs=cidrs).for_every_address())
        expect(probe).to(
            get(url, allowed_destination_cidrs=cidrs, attempts=3, successes_required=2)
            .returning_status(200)
            .for_every_address()
        )
