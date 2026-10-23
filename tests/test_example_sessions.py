"""Example fixtures use MiniStack tenants without contacting an endpoint."""

import inspect
import os
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from botocore.stub import Stubber

from aws_network_asserts import AccountMismatchError
from contrib import pytest_examples as examples

CENTRAL = "999999999999"
MEMBER = "111111111111"
OTHER = "222222222222"
CONFIG = "333333333333"
ENDPOINT = "http://localhost:4599"


@pytest.fixture
def options(monkeypatch, tmp_path):
    for name in list(os.environ):
        if name.startswith(("AWS_", "MINISTACK_", "NETWORK_", "CONFIG_")) or name in {
            "ACCOUNT_A",
            "ACCOUNT_B",
        }:
            monkeypatch.delenv(name)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    return {
        "--run-aws": True,
        "--ministack": True,
        "--aws-region": "eu-west-2",
        "--aws-endpoint-url": None,
        "--aws-profile": None,
        "--config-mode": "off",
        "--keep-analysis": False,
    }


def make_rule(options):
    # Exercise the actual fixture body; leave pytest's injection to example runs.
    return inspect.unwrap(examples.org_rule)(SimpleNamespace(getoption=options.__getitem__))


def signed_account(client):
    credentials = client._request_signer._credentials.get_frozen_credentials()
    assert credentials.secret_key == "test"
    assert credentials.token is None
    return credentials.access_key


@pytest.mark.parametrize(
    "service", ["ec2", "sts", "config", "lambda", "iam", "ssm", "network-firewall"]
)
def test_default_shim_sessions_and_every_service_use_the_local_endpoint(
    options, service, monkeypatch
):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ambient-key-must-not-be-used")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ambient-secret-must-not-be-used")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "ambient-token-must-not-be-used")
    # A per-service SDK override must not escape the explicitly selected MiniStack endpoint.
    service_environment = service.replace("-", "_").upper()
    monkeypatch.setenv(f"AWS_ENDPOINT_URL_{service_environment}", "https://unused.invalid")
    rule = make_rule(options)
    client = rule.clients.client(service, rule.region_name)
    assert rule.account_id == "000000000000"
    assert rule.config_clients is rule.clients
    assert signed_account(client) == rule.account_id
    assert client.meta.endpoint_url == "http://localhost:4566"
    assert client.meta.region_name == "eu-west-2"


@pytest.mark.parametrize(
    "cli,mini,sdk,expected",
    [
        (ENDPOINT, "http://localhost:4600", "http://localhost:4601", ENDPOINT),
        (None, "http://localhost:4600", "http://localhost:4601", "http://localhost:4600"),
        (None, None, "http://localhost:4601", "http://localhost:4601"),
    ],
)
def test_shim_endpoint_precedence(options, monkeypatch, cli, mini, sdk, expected):
    options["--aws-endpoint-url"] = cli
    if mini:
        monkeypatch.setenv("MINISTACK_ENDPOINT", mini)
    monkeypatch.setenv("AWS_ENDPOINT_URL", sdk)
    assert make_rule(options).analysis_ec2.meta.endpoint_url == expected


@pytest.mark.parametrize("variable", ["NETWORK_ACCOUNT_ID", "CONFIG_SOURCE_ACCOUNT"])
def test_selected_account_gets_its_own_shim_session(options, monkeypatch, variable):
    monkeypatch.setenv("MINISTACK_ACCOUNT_ID", CENTRAL)
    monkeypatch.setenv("CONFIG_SOURCE_ACCOUNT", OTHER)
    monkeypatch.setenv(variable, MEMBER)
    rule = make_rule(options)
    assert rule.account_id == MEMBER
    assert signed_account(rule.analysis_ec2) == CENTRAL
    assert rule._accounts._sessions[MEMBER].get_credentials().access_key == MEMBER


def test_member_identity_and_region_changes_preserve_central_ra_and_config(options, monkeypatch):
    options.update({"--config-mode": "required", "--aws-endpoint-url": ENDPOINT})
    resource = "444444444444"
    for key, value in {
        "MINISTACK_ACCOUNT_ID": CENTRAL,
        "MINISTACK_CONFIG_ACCOUNT_ID": CONFIG,
        "NETWORK_ACCOUNT_ID": resource,
        "ACCOUNT_A": MEMBER,
        "ACCOUNT_B": OTHER,
        "CONFIG_AGGREGATOR": "organization-network",
        "CONFIG_AGGREGATOR_REGION": "eu-west-1",
        "NETWORK_ACCOUNT_PROFILES": "unused in MiniStack mode",
        "CONFIG_PROFILE": "unused-profile",
    }.items():
        monkeypatch.setenv(key, value)
    rule = make_rule(options)
    for account in (resource, MEMBER, OTHER):
        regional = rule.in_account(account).in_region("us-east-1")
        factory = rule._accounts._factory(account)
        with Stubber(factory.client("sts", "us-east-1")) as identity:
            identity.add_response("get_caller_identity", {"Account": account}, {})
            for service in ("ec2", "lambda", "iam", "ssm", "network-firewall"):
                client = regional._live_client(service)
                assert signed_account(client) == account
                assert client.meta.endpoint_url == ENDPOINT
                assert client.meta.region_name == "us-east-1"
            identity.assert_no_pending_responses()
        assert signed_account(regional.analysis_ec2) == CENTRAL
        assert regional.analysis_ec2.meta.region_name == "us-east-1"
        config = regional.config_clients.client("config", regional.config_region)
        assert signed_account(config) == CONFIG
        assert config.meta.region_name == "eu-west-1"
        assert config.meta.endpoint_url == ENDPOINT


def test_shim_identity_mismatch_remains_an_error(options, monkeypatch):
    monkeypatch.setenv("NETWORK_ACCOUNT_ID", MEMBER)
    rule = make_rule(options)
    factory = rule._accounts._factory(MEMBER)
    with Stubber(factory.client("sts", rule.region_name)) as identity:
        identity.add_response("get_caller_identity", {"Account": OTHER}, {})
        with pytest.raises(AccountMismatchError):
            rule._live_client("ec2")
        identity.assert_no_pending_responses()


@pytest.mark.parametrize(
    "variable,value",
    [
        ("MINISTACK_ACCOUNT_ID", "１１１１１１１１１１１１"),
        ("NETWORK_ACCOUNT_ID", "invalid"),
        ("CONFIG_SOURCE_ACCOUNT", "invalid"),
        ("ACCOUNT_A", "invalid"),
        ("ACCOUNT_B", "invalid"),
        ("MINISTACK_CONFIG_ACCOUNT_ID", "invalid"),
    ],
)
def test_invalid_account_configuration_is_rejected(options, monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError, match="account"):
        make_rule(options)


def test_ministack_does_not_disable_required_config(options):
    options["--config-mode"] = "required"
    with pytest.raises(ValueError, match="config_aggregator and config_region"):
        make_rule(options)


def test_explicit_aws_profile_cannot_be_combined_with_ministack(options, monkeypatch):
    options["--aws-profile"] = "production"
    construct = Mock(side_effect=AssertionError("Do not construct either credential context"))
    monkeypatch.setattr(examples, "MiniStack", construct)
    with pytest.raises(pytest.UsageError, match="--ministack or --aws-profile"):
        make_rule(options)
    construct.assert_not_called()


def test_aws_profile_mode_keeps_existing_configuration(options, monkeypatch):
    options.update(
        {
            "--ministack": False,
            "--aws-profile": "central",
            "--aws-endpoint-url": ENDPOINT,
            "--config-mode": "prefer",
            "--keep-analysis": True,
        }
    )
    for key, value in {
        "CONFIG_PROFILE": "config-reader",
        "NETWORK_ACCOUNT_PROFILES": '{"111111111111":"member"}',
        "NETWORK_ACCOUNT_ID": MEMBER,
        "CONFIG_AGGREGATOR": "organization-network",
        "CONFIG_AGGREGATOR_REGION": "eu-west-1",
    }.items():
        monkeypatch.setenv(key, value)
    construct = Mock()
    monkeypatch.setattr(examples, "RuleBuilder", construct)
    assert make_rule(options) is construct.return_value
    construct.assert_called_once_with(
        profile_name="central",
        config_profile_name="config-reader",
        account_profiles={MEMBER: "member"},
        region_name="eu-west-2",
        endpoint_url=ENDPOINT,
        config_mode="prefer",
        keep_analysis=True,
        config_aggregator="organization-network",
        config_region="eu-west-1",
        account_id=MEMBER,
    )


@pytest.mark.parametrize("value", ["not json", "[]"])
def test_aws_profile_mapping_still_rejects_bad_configuration(options, monkeypatch, value):
    options["--ministack"] = False
    monkeypatch.setenv("NETWORK_ACCOUNT_PROFILES", value)
    with pytest.raises(pytest.UsageError, match="NETWORK_ACCOUNT_PROFILES"):
        make_rule(options)


def test_fixture_without_execution_permission_skips_before_creating_sessions(options, monkeypatch):
    options["--run-aws"] = False
    construct = Mock(side_effect=AssertionError("Do not create a credential context"))
    monkeypatch.setattr(examples, "MiniStack", construct)
    monkeypatch.setattr(examples, "RuleBuilder", construct)
    with pytest.raises(pytest.skip.Exception, match="--run-aws"):
        make_rule(options)
    construct.assert_not_called()


def test_optional_runner_registers_separate_write_gates_and_resets_execution_state(monkeypatch):
    monkeypatch.setattr(examples, "_AWS_ENABLED", False)
    assert not examples.aws_enabled()
    with ExitStack() as cleanup:
        enabled = pytest.Config.fromdictargs(
            {}, ["-p", "contrib.pytest_examples", "--run-aws", "--allow-ssm-commands"]
        )
        cleanup.callback(enabled._ensure_unconfigure)
        assert enabled.getoption("--allow-ssm-commands")
        assert not enabled.getoption("--allow-probe-writes")
        examples.pytest_configure(enabled)
        assert examples.aws_enabled()
        disabled = pytest.Config.fromdictargs({}, ["-p", "contrib.pytest_examples"])
        cleanup.callback(disabled._ensure_unconfigure)
        examples.pytest_configure(disabled)
        assert not examples.aws_enabled()
        examples.pytest_configure(enabled)
        examples.pytest_unconfigure(enabled)
        assert not examples.aws_enabled()
