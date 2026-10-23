"""Keep one durable manifest outside pytest's temporary directories."""

from pathlib import Path

import pytest

from aws_network_asserts import expect, get
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


def test_the_service_with_recoverable_cleanup(pytestconfig, request, aws_value):
    if not pytestconfig.getoption("--allow-probe-writes"):
        pytest.skip("Use --allow-probe-writes to permit temporary Lambda resources")
    manifest = Path(aws_value("PROBE_CLEANUP_MANIFEST"))
    if manifest.exists() or manifest.is_symlink() or not manifest.parent.is_dir():
        raise pytest.UsageError("Use a fresh PROBE_CLEANUP_MANIFEST path in an existing directory")
    subnet = aws_value("SOURCE_SUBNET")
    url = aws_value("PROBE_HEALTH_URL")
    auto_role = pytestconfig.getoption("--auto-create-execution-role")
    auto_group = pytestconfig.getoption("--auto-create-security-group")
    role = None if auto_role else aws_value("PROBE_EXECUTION_ROLE_ARN")
    groups = None if auto_group else aws_value("PROBE_SECURITY_GROUP_IDS").split(",")
    rule = request.getfixturevalue("rule")
    with rule.subnet(subnet).probe_session(
        allow_write=True,
        cleanup_manifest=manifest,
        execution_role_arn=role,
        auto_create_execution_role=auto_role,
        security_group_ids=[value.strip() for value in groups] if groups is not None else None,
        auto_create_security_group=auto_group,
    ) as probe:
        expect(probe).to(get(url).returning_status(200))
