"""Optional pytest fixtures for the repository's AWS and MiniStack examples.

Load explicitly with ``python -m pytest -p contrib.pytest_examples examples/``.
Nothing in the library itself depends on this runner.
"""

import json
import os

import pytest

from aws_network_asserts import RuleBuilder
from aws_network_asserts.accounts import validate_account_id
from contrib.ministack_boto3 import MiniStack

_AWS_ENABLED = False


def aws_enabled():
    """Whether this pytest run explicitly enabled AWS example execution."""
    return _AWS_ENABLED


def pytest_configure(config):
    global _AWS_ENABLED
    _AWS_ENABLED = bool(config.getoption("--run-aws"))


def pytest_unconfigure(config):
    global _AWS_ENABLED
    _AWS_ENABLED = False


def pytest_addoption(parser):
    group = parser.getgroup("aws-network-asserts examples")
    group.addoption(
        "--run-aws", action="store_true", help="Run examples against configured AWS APIs"
    )
    group.addoption(
        "--ministack",
        action="store_true",
        help="Use contrib/ministack_boto3.py for local account sessions and endpoint selection",
    )
    group.addoption(
        "--aws-region",
        default=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "eu-west-2",
    )
    group.addoption("--aws-endpoint-url", default=None)
    group.addoption("--aws-profile", default=None, help="Central analysis/Config profile")
    group.addoption("--config-mode", choices=("prefer", "required", "off"), default="required")
    group.addoption("--keep-analysis", action="store_true")
    group.addoption(
        "--allow-probe-writes",
        action="store_true",
        help="Also allow examples to create, invoke and delete temporary VPC Lambda probes",
    )
    group.addoption(
        "--allow-ssm-commands",
        action="store_true",
        help="Also allow examples to execute fixed probe commands on configured SSM instances",
    )
    group.addoption(
        "--auto-create-execution-role",
        action="store_true",
        help="Explicitly create and clean up a temporary IAM role for the Lambda example",
    )
    group.addoption(
        "--auto-create-security-group",
        action="store_true",
        help="Explicitly create and clean up a security group for the Lambda example",
    )


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-aws"):
        return
    skip = pytest.mark.skip(
        reason="Use -p contrib.pytest_examples --run-aws to run AWS network examples"
    )
    for item in items:
        if "aws" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def org_rule(pytestconfig):
    if not pytestconfig.getoption("--run-aws"):
        pytest.skip("Use -p contrib.pytest_examples --run-aws to run AWS network examples")
    region = pytestconfig.getoption("--aws-region")
    endpoint = pytestconfig.getoption("--aws-endpoint-url")
    account = os.getenv("NETWORK_ACCOUNT_ID") or os.getenv("CONFIG_SOURCE_ACCOUNT")
    if pytestconfig.getoption("--ministack"):
        if pytestconfig.getoption("--aws-profile"):
            raise pytest.UsageError("Choose --ministack or --aws-profile, not both")
        stack = MiniStack(endpoint_url=endpoint, region=region)
        validate_account_id(stack.default_account)
        account = account or stack.default_account
        members = {account, os.getenv("ACCOUNT_A"), os.getenv("ACCOUNT_B")} - {None}
        credentials = {
            "session": stack.session(),
            "account_sessions": {
                member: stack.session(validate_account_id(member)) for member in sorted(members)
            },
        }
        if config_account := os.getenv("MINISTACK_CONFIG_ACCOUNT_ID"):
            credentials["config_session"] = stack.session(validate_account_id(config_account))
        endpoint = stack.endpoint_url
    else:
        try:
            profiles = json.loads(os.getenv("NETWORK_ACCOUNT_PROFILES", "{}"))
        except json.JSONDecodeError as error:
            raise pytest.UsageError("NETWORK_ACCOUNT_PROFILES must be a JSON object") from error
        if not isinstance(profiles, dict):
            raise pytest.UsageError(
                "NETWORK_ACCOUNT_PROFILES must map account IDs to profile names"
            )
        credentials = {
            "profile_name": pytestconfig.getoption("--aws-profile"),
            "config_profile_name": os.getenv("CONFIG_PROFILE"),
            "account_profiles": profiles,
        }
    return RuleBuilder(
        **credentials,
        region_name=region,
        endpoint_url=endpoint,
        config_mode=pytestconfig.getoption("--config-mode"),
        keep_analysis=pytestconfig.getoption("--keep-analysis"),
        config_aggregator=os.getenv("CONFIG_AGGREGATOR"),
        config_region=os.getenv("CONFIG_AGGREGATOR_REGION"),
        account_id=account,
    )


@pytest.fixture(scope="session")
def rule(org_rule):
    """Use NETWORK_ACCOUNT_ID as the default owner for the basic network examples."""
    return org_rule


@pytest.fixture
def aws_value():
    def required(name):
        value = os.getenv(name)
        if not value:
            pytest.skip(f"Set {name} to run this example")
        return value

    return required
