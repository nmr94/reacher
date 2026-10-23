"""Lambda request/lifecycle contracts and packet observations, entirely offline."""

import errno
import io
import json
import socket
import warnings
from unittest.mock import Mock
from uuid import UUID
from zipfile import ZipFile

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import ANY, Stubber

from aws_network_asserts import (
    AccountMismatchError,
    CleanupWarning,
    ProbeError,
    ProbeTimeoutError,
    RuleBuilder,
    WriteNotAllowedError,
    _probe_handler,
    probe,
)

ACCOUNT = "111111111111"
REGION = "eu-west-2"
SUBNET = "subnet-0123456789abcdef0"
GROUP = "sg-0123456789abcdef0"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/network/ProbeExecution"
NAME = f"aws-network-asserts-{'0' * 32}"
OPTIONS = {"allow_write": True, "execution_role_arn": ROLE, "security_group_ids": [GROUP]}


def session():
    return boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION)


@pytest.fixture
def rule():
    return RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)


@pytest.fixture
def cloud(rule, monkeypatch):
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    client = rule.clients.client("lambda", REGION)
    with Stubber(rule.clients.client("sts", REGION)) as sts, Stubber(client) as stub:
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        yield rule, stub
        sts.assert_no_pending_responses()
        stub.assert_no_pending_responses()


def create(stub, name=NAME, execution_role_arn=ROLE):
    stub.add_response(
        "create_function",
        {"FunctionName": name, "State": "Pending"},
        {
            "FunctionName": name,
            "Runtime": "python3.12",
            "Role": execution_role_arn,
            "Handler": "probe_handler.handler",
            "Code": {"ZipFile": ANY},
            "Timeout": 15,
            "MemorySize": 128,
            "Publish": False,
            "VpcConfig": {"SubnetIds": [SUBNET], "SecurityGroupIds": [GROUP]},
        },
    )


def state(stub, value="Active", name=NAME):
    stub.add_response("get_function_configuration", {"State": value}, {"FunctionName": name})


def invoke(stub, *, outcome="connected", payload=None, name=NAME, **response):
    stream = io.BytesIO(
        json.dumps(
            {"outcome": outcome, "resolved_ip": "10.1.2.3", "port": 443}
            if payload is None
            else payload
        ).encode()
    )
    stub.add_response(
        "invoke",
        {"StatusCode": 200, "Payload": stream, **response},
        {
            "FunctionName": name,
            "InvocationType": "RequestResponse",
            "LogType": "None",
            "Payload": json.dumps(
                {"host": "database.example", "port": 443, "connect_timeout": 3.0}
            ).encode(),
        },
    )
    return stream


def delete(stub, name=NAME):
    stub.add_response("delete_function", {}, {"FunctionName": name})


def check(rule, **options):
    return rule.subnet(SUBNET).probe_tcp("database.example", **{**OPTIONS, **options})


@pytest.mark.parametrize("allowed", [False, None, "true", 1])
def test_write_permission_is_literal_true_and_checked_before_any_aws_call(
    rule, monkeypatch, allowed
):
    client = Mock(side_effect=AssertionError("No AWS clients should be created"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(WriteNotAllowedError, match="allow_write=True"):
        check(rule, allow_write=allowed)
    client.assert_not_called()


def test_write_permission_defaults_to_denied(rule):
    with pytest.raises(WriteNotAllowedError):
        rule.subnet(SUBNET).probe_tcp(
            "10.1.2.3", execution_role_arn=ROLE, security_group_ids=[GROUP]
        )


@pytest.mark.parametrize(
    "options",
    [
        {"port": True},
        {"port": 0},
        {"port": 65536},
        {"connect_timeout": 0},
        {"connect_timeout": 11},
        {"connect_timeout": float("nan")},
        {"ready_timeout": -1},
        {"ready_timeout": float("inf")},
        {"security_group_ids": GROUP},
        {"security_group_ids": []},
        {"security_group_ids": [GROUP, GROUP]},
        {"security_group_ids": ["vpc-1"]},
        {"execution_role_arn": "arn:aws:iam::222222222222:role/Probe"},
        {"execution_role_arn": f"arn:aws-cn:iam::{ACCOUNT}:role/Probe"},
        {"execution_role_arn": f"arn:aws:iam::{ACCOUNT}:user/Probe"},
    ],
)
def test_invalid_options_fail_before_client_creation(rule, monkeypatch, options):
    client = Mock(side_effect=AssertionError("No AWS clients should be created"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(ValueError):
        check(rule, **options)
    client.assert_not_called()


@pytest.mark.parametrize(
    "host", ["", None, "https://example.com", "::1", "10.0.0.0/24", "999.1.1.1"]
)
def test_host_is_one_ipv4_address_or_dns_name(rule, host):
    with pytest.raises(ValueError, match="host"):
        rule.subnet(SUBNET).probe_tcp(host, **OPTIONS)


def test_even_config_off_requires_explicit_probe_account():
    with pytest.raises(ValueError, match="account"):
        check(RuleBuilder(session=session(), config_mode="off"))


@pytest.mark.parametrize("outcome", ["connected", "refused", "timeout", "unreachable"])
def test_observed_tcp_result_and_cleanup(cloud, outcome):
    rule, stub = cloud
    create(stub)
    state(stub)
    stream = invoke(stub, outcome=outcome)
    delete(stub)
    result = check(rule)
    assert bool(result) == (outcome == "connected")
    assert result.evidence["cleanup"] == "deleted"
    assert result.evidence["method"] == "lambda_tcp"
    assert result.evidence["function_name"] == NAME
    assert result.evidence["account_id"] == ACCOUNT
    assert outcome in result.message
    assert stream.closed


def test_pending_is_polled_without_real_sleep(cloud, monkeypatch):
    rule, stub = cloud
    sleep = Mock()
    monkeypatch.setattr(probe.time, "sleep", sleep)
    create(stub)
    state(stub, "Pending")
    state(stub)
    invoke(stub)
    delete(stub)
    assert check(rule)
    sleep.assert_called_once()


def test_readiness_timeout_still_deletes_function(cloud, monkeypatch):
    rule, stub = cloud
    monkeypatch.setattr(probe.time, "monotonic", Mock(side_effect=[0, 300]))
    create(stub)
    state(stub, "Pending")
    delete(stub)
    with pytest.raises(ProbeTimeoutError) as caught:
        check(rule)
    assert caught.value.evidence["cleanup"] == "deleted"
    assert NAME in str(caught.value)


@pytest.mark.parametrize("value", ["Failed", "Inactive", "Unknown", None])
def test_unusable_or_missing_function_state_is_error(cloud, value):
    rule, stub = cloud
    create(stub)
    stub.add_response(
        "get_function_configuration",
        {} if value is None else {"State": value},
        {"FunctionName": NAME},
    )
    delete(stub)
    with pytest.raises(ProbeError, match="Active"):
        check(rule)


@pytest.mark.parametrize(
    "payload, fields",
    [
        ({"errorMessage": "DNS failed"}, {"FunctionError": "Unhandled"}),
        ({"outcome": "unknown"}, {}),
        ({"outcome": []}, {}),
        ({"outcome": "connected", "resolved_ip": "bad", "port": 443}, {}),
        ({"outcome": "connected", "resolved_ip": 1, "port": 443}, {}),
        ({"outcome": "connected", "resolved_ip": "10.1.2.3", "port": 22}, {}),
        ([], {}),
    ],
)
def test_invalid_or_function_error_response_never_becomes_connectivity_result(
    cloud, payload, fields
):
    rule, stub = cloud
    create(stub)
    state(stub)
    stream = invoke(stub, payload=payload, **fields)
    delete(stub)
    with pytest.raises(ProbeError) as caught:
        check(rule)
    assert caught.value.evidence["cleanup"] == "deleted"
    assert stream.closed


def test_create_denied_does_not_delete_a_function_the_check_did_not_create(cloud):
    rule, stub = cloud
    stub.add_client_error("create_function", "AccessDeniedException")
    with pytest.raises(ClientError, match="AccessDeniedException"):
        check(rule)


def test_invocation_permission_error_propagates_and_still_cleans_up(cloud):
    rule, stub = cloud
    create(stub)
    state(stub)
    stub.add_client_error("invoke", "AccessDeniedException")
    delete(stub)
    with pytest.raises(ClientError, match="AccessDeniedException"):
        check(rule)


def test_cleanup_failure_warns_with_function_name_and_retains_observation(cloud):
    rule, stub = cloud
    create(stub)
    state(stub)
    invoke(stub)
    stub.add_client_error("delete_function", "AccessDeniedException")
    with pytest.warns(CleanupWarning, match=NAME):
        result = check(rule)
    assert result
    assert result.evidence["cleanup"] == "failed"


def test_cleanup_warning_as_error_does_not_mask_original_failure(cloud):
    rule, stub = cloud
    create(stub)
    state(stub, "Failed")
    stub.add_client_error("delete_function", "AccessDeniedException")
    with warnings.catch_warnings():
        warnings.simplefilter("error", CleanupWarning)
        with pytest.raises(ProbeError, match="Active"):
            check(rule)


def test_account_mismatch_prevents_lambda_client_creation(rule, monkeypatch):
    factory_client = Mock(wraps=rule.clients.session.client)
    sts = rule.clients.client("sts", REGION)
    monkeypatch.setattr(rule.clients.session, "client", factory_client)
    with Stubber(sts) as stub:
        stub.add_response("get_caller_identity", {"Account": "222222222222"}, {})
        with pytest.raises(AccountMismatchError):
            check(rule)
        stub.assert_no_pending_responses()
    factory_client.assert_not_called()


def test_probe_uses_member_session_region_and_inherited_endpoint(monkeypatch):
    central, member = session(), session()
    region = "us-east-1"
    endpoint = "https://lambda.test.invalid"
    member_lambda = member.client("lambda", region_name=region, endpoint_url=endpoint)
    member_sts = member.client("sts", region_name=region, endpoint_url="https://sts.test.invalid")
    client = Mock(
        side_effect=lambda service, **kwargs: {"sts": member_sts, "lambda": member_lambda}[service]
    )
    monkeypatch.setattr(member, "client", client)
    central_client = Mock(side_effect=AssertionError("No central AWS requests"))
    monkeypatch.setattr(central, "client", central_client)
    rule = (
        RuleBuilder(
            session=central,
            account_sessions={ACCOUNT: member},
            config_mode="off",
            endpoint_urls={"lambda": "https://generic.test.invalid", f"{region}:lambda": endpoint},
        )
        .in_account(ACCOUNT)
        .in_region(region)
    )
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    with Stubber(member_sts) as sts, Stubber(member_lambda) as stub:
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        create(stub)
        state(stub)
        invoke(stub)
        delete(stub)
        assert check(rule)
        sts.assert_no_pending_responses()
        stub.assert_no_pending_responses()
    central_client.assert_not_called()
    args = client.call_args_list[-1]
    assert args.args == ("lambda",)
    assert args.kwargs["region_name"] == region
    assert args.kwargs["endpoint_url"] == endpoint


def test_upload_contains_self_contained_handler():
    with ZipFile(io.BytesIO(probe._package())) as archive:
        assert archive.namelist() == ["probe_handler.py"]
        namespace = {}
        exec(compile(archive.read("probe_handler.py"), "probe_handler.py", "exec"), namespace)
        assert callable(namespace["handler"])


@pytest.mark.parametrize(
    "error, expected",
    [
        (None, "connected"),
        (TimeoutError(), "timeout"),
        (ConnectionRefusedError(), "refused"),
        (OSError(errno.ENETUNREACH, "route"), "unreachable"),
    ],
)
def test_uploaded_handler_observes_handshake_and_closes_socket(monkeypatch, error, expected):
    resolver = Mock(return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 443))])
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    connection = Mock()
    connection.connect.side_effect = error
    sock = Mock()
    sock.__enter__ = Mock(return_value=connection)
    sock.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(socket, "socket", Mock(return_value=sock))
    result = _probe_handler.handler({"host": "db.example", "port": 443, "connect_timeout": 3}, None)
    assert result["outcome"] == expected
    assert result["resolved_ip"] == "10.1.2.3"
    connection.connect.assert_called_once_with(("10.1.2.3", 443))
    connection.settimeout.assert_called_once_with(3)
    sock.__exit__.assert_called_once()


def test_dns_failure_is_an_execution_error(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", Mock(side_effect=socket.gaierror("DNS")))
    with pytest.raises(socket.gaierror):
        _probe_handler.handler({"host": "missing.example", "port": 443}, None)


@pytest.mark.parametrize("mode", ["required", "prefer"])
def test_config_evidence_uses_central_reader_and_fixed_region(monkeypatch, mode):
    central, reader = session(), session()
    rule = RuleBuilder(
        session=central,
        config_session=reader,
        config_aggregator="network",
        config_region="eu-west-1",
        account_id=ACCOUNT,
        config_mode=mode,
    )
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    config = rule.config_clients.client("config", "eu-west-1")
    with (
        Stubber(config) as inventory,
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("lambda", REGION)) as stub,
    ):
        inventory.add_response(
            "get_aggregate_resource_config",
            {
                "ConfigurationItem": {
                    "resourceType": "AWS::EC2::Subnet",
                    "resourceId": SUBNET,
                    "accountId": ACCOUNT,
                    "awsRegion": REGION,
                    "configurationItemStatus": "OK",
                    "configuration": '{"vpcId": "vpc-source"}',
                }
            },
            {
                "ConfigurationAggregatorName": "network",
                "ResourceIdentifier": {
                    "SourceAccountId": ACCOUNT,
                    "SourceRegion": REGION,
                    "ResourceType": "AWS::EC2::Subnet",
                    "ResourceId": SUBNET,
                },
            },
        )
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        create(stub)
        state(stub)
        invoke(stub)
        delete(stub)
        result = check(rule)
        assert result.evidence["config"]["configuration"] == {"vpcId": "vpc-source"}
        assert result.evidence["config"]["account_id"] == ACCOUNT
        assert config.meta.region_name == "eu-west-1"
        assert rule.config_clients.session is reader
        inventory.assert_no_pending_responses()
        sts.assert_no_pending_responses()
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("mode", ["required", "prefer"])
def test_inaccessible_config_never_deploys_a_probe(mode):
    rule = RuleBuilder(
        session=session(),
        config_aggregator="network",
        config_region=REGION,
        account_id=ACCOUNT,
        config_mode=mode,
    )
    with (
        Stubber(rule.config_clients.client("config", REGION)) as inventory,
        Stubber(rule.clients.client("sts", REGION)),
        Stubber(rule.clients.client("lambda", REGION)),
    ):
        inventory.add_client_error("get_aggregate_resource_config", "AccessDeniedException")
        with pytest.raises(ClientError, match="AccessDeniedException"):
            check(rule)
        inventory.assert_no_pending_responses()


def test_bad_json_closes_payload_and_deletes_function(cloud):
    rule, stub = cloud
    create(stub)
    state(stub)
    stream = io.BytesIO(b"not JSON")
    stub.add_response("invoke", {"StatusCode": 200, "Payload": stream})
    delete(stub)
    with pytest.raises(ProbeError, match="JSON"):
        check(rule)
    assert stream.closed


def test_missing_invocation_payload_is_error_and_cleans_up(cloud):
    rule, stub = cloud
    create(stub)
    state(stub)
    stub.add_response("invoke", {"StatusCode": 200})
    delete(stub)
    with pytest.raises(ProbeError, match="Payload"):
        check(rule)


def test_keyboard_interrupt_still_deletes_created_function(cloud, monkeypatch):
    rule, stub = cloud
    create(stub)
    state(stub, "Pending")
    monkeypatch.setattr(probe.time, "sleep", Mock(side_effect=KeyboardInterrupt))
    delete(stub)
    with pytest.raises(KeyboardInterrupt):
        check(rule)


def test_aws_failure_keeps_type_and_function_evidence(cloud):
    rule, stub = cloud
    create(stub)
    state(stub)
    stub.add_client_error("invoke", "ServiceException")
    delete(stub)
    with pytest.raises(ClientError) as caught:
        check(rule)
    assert caught.value.evidence["function_name"] == NAME
    assert caught.value.evidence["cleanup"] == "deleted"


def test_unexpected_socket_error_is_an_execution_error(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", Mock(return_value=[(0, 0, 0, "", ("10.1.2.3", 443))])
    )
    connection = Mock()
    connection.connect.side_effect = OSError(errno.EINVAL, "unexpected")
    sock = Mock()
    sock.__enter__ = Mock(return_value=connection)
    sock.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(socket, "socket", Mock(return_value=sock))
    with pytest.raises(OSError, match="unexpected"):
        _probe_handler.handler({"host": "db.example", "port": 443, "connect_timeout": 3}, None)
    sock.__exit__.assert_called_once()


def test_calls_create_independent_functions_without_reusing_observations(cloud, monkeypatch):
    rule, stub = cloud
    identifiers = [UUID(int=1), UUID(int=2)]
    monkeypatch.setattr(probe, "uuid4", Mock(side_effect=identifiers))
    results = []
    for identifier, outcome in zip(identifiers, ["connected", "refused"], strict=True):
        name = f"aws-network-asserts-{identifier.hex}"
        create(stub, name=name)
        state(stub, name=name)
        invoke(stub, name=name, outcome=outcome)
        delete(stub, name=name)
        results.append(check(rule))
    assert results[0]
    assert not results[1]
    assert results[0].evidence["function_name"] != results[1].evidence["function_name"]


def test_cleanup_failure_can_fail_a_test_using_warnings_as_errors(cloud):
    rule, stub = cloud
    create(stub)
    state(stub)
    invoke(stub)
    stub.add_client_error("delete_function", "AccessDeniedException")
    with warnings.catch_warnings():
        warnings.simplefilter("error", CleanupWarning)
        with pytest.raises(CleanupWarning, match=NAME):
            check(rule)


@pytest.mark.parametrize("response", [{}, {"FunctionName": "unrelated-function"}])
def test_unconfirmed_function_identity_is_never_invoked_or_deleted(cloud, response):
    rule, stub = cloud
    stub.add_response("create_function", response)
    with (
        pytest.warns(CleanupWarning, match="creation unconfirmed"),
        pytest.raises(ProbeError, match="function identity") as caught,
    ):
        check(rule)
    assert caught.value.evidence["cleanup"] == "creation_unconfirmed"
    assert caught.value.evidence["function_name"] == NAME


def test_already_absent_owned_function_counts_as_deleted(cloud):
    rule, stub = cloud
    create(stub)
    state(stub)
    invoke(stub)
    stub.add_client_error("delete_function", "ResourceNotFoundException")
    result = check(rule)
    assert result.evidence["cleanup"] == "deleted"


def cleanup_resources():
    client = Mock()
    client.meta.region_name = REGION
    client.create_function.side_effect = lambda **request: {"FunctionName": request["FunctionName"]}
    client.get_function_configuration.return_value = {"State": "Active"}
    role = Mock(created=True, evidence={"role_name": NAME, "cleanup": "pending"})
    role.create.return_value = ROLE
    group = Mock(created=True, evidence={"group_id": GROUP, "cleanup": "pending"})
    group.create.return_value = GROUP
    group.cleanup.side_effect = lambda: group.evidence.update(cleanup="deleted")
    settings = probe.LambdaProbe("service.example", 443, None, None, 3, 300)
    return settings, client, role, group


@pytest.mark.parametrize("resource", ["function", "security_group", "role"])
def test_cleanup_interrupt_reports_retained_resources_and_preserves_cancellation(resource):
    settings, client, role, group = cleanup_resources()
    interrupt = KeyboardInterrupt("cleanup interrupted")
    operation = {
        "function": client.delete_function,
        "security_group": group.cleanup,
        "role": role.cleanup,
    }[resource]
    operation.side_effect = interrupt
    with (
        pytest.warns(CleanupWarning, match="cleanup interrupted"),
        pytest.raises(KeyboardInterrupt) as caught,
    ):
        with settings.deployed(client, SUBNET, poll_interval=0, role=role, security_group=group):
            pass
    assert caught.value is interrupt
    assert interrupt.evidence["cleanup"] == ("failed" if resource == "function" else "deleted")
    if resource == "function":
        group.cleanup.assert_not_called()
        assert group.evidence["cleanup"] == "retained"
    if resource != "role":
        role.cleanup.assert_not_called()
    assert role.evidence["cleanup"] == "retained"


def test_cleanup_cancellation_and_warning_as_error_cannot_replace_original_failure():
    settings, client, role, group = cleanup_resources()
    client.delete_function.side_effect = KeyboardInterrupt("cleanup interrupted")
    original = RuntimeError("original check failed")
    with warnings.catch_warnings():
        warnings.simplefilter("error", CleanupWarning)
        with pytest.raises(RuntimeError) as caught:
            with settings.deployed(
                client, SUBNET, poll_interval=0, role=role, security_group=group
            ):
                raise original
    assert caught.value is original
    assert original.evidence["cleanup"] == "failed"
    assert role.evidence["cleanup"] == "retained"
    assert group.evidence["cleanup"] == "retained"


def test_cleanup_warning_as_error_cannot_replace_cleanup_cancellation():
    settings, client, role, group = cleanup_resources()
    interrupt = KeyboardInterrupt("cleanup interrupted")
    client.delete_function.side_effect = interrupt
    with warnings.catch_warnings():
        warnings.simplefilter("error", CleanupWarning)
        with pytest.raises(KeyboardInterrupt) as caught:
            with settings.deployed(
                client, SUBNET, poll_interval=0, role=role, security_group=group
            ):
                pass
    assert caught.value is interrupt
    assert interrupt.evidence["cleanup"] == "failed"


@pytest.mark.parametrize("diagnostics", [[], "unrelated", {"reason": "original"}])
def test_exception_diagnostics_never_replace_original_invocation_error(
    cloud, monkeypatch, diagnostics
):
    rule, stub = cloud
    create(stub)
    state(stub)
    original = RuntimeError("Original invocation failure")
    original.evidence = diagnostics
    monkeypatch.setattr(stub.client, "invoke", Mock(side_effect=original))
    delete(stub)
    with pytest.raises(RuntimeError, match="Original invocation failure") as caught:
        check(rule)
    assert caught.value is original
    assert original.evidence["cleanup"] == "deleted"


def test_readonly_error_evidence_preserves_original_and_cleans_up(cloud, monkeypatch):
    class UserError(RuntimeError):
        @property
        def evidence(self):
            return "user supplied diagnostics"

    rule, stub = cloud
    create(stub)
    state(stub)
    original = UserError("Original")
    monkeypatch.setattr(stub.client, "invoke", Mock(side_effect=original))
    delete(stub)
    with pytest.raises(UserError) as caught:
        check(rule)
    assert caught.value is original


def test_literal_target_cannot_accept_observation_for_another_address(cloud):
    rule, stub = cloud
    create(stub)
    state(stub)
    stub.add_response(
        "invoke",
        {
            "StatusCode": 200,
            "Payload": io.BytesIO(
                json.dumps(
                    {"outcome": "connected", "resolved_ip": "10.1.2.4", "port": 443}
                ).encode()
            ),
        },
        {
            "FunctionName": NAME,
            "InvocationType": "RequestResponse",
            "LogType": "None",
            "Payload": json.dumps(
                {"host": "10.1.2.3", "port": 443, "connect_timeout": 3.0}
            ).encode(),
        },
    )
    delete(stub)
    with pytest.raises(ProbeError, match="different destination address"):
        rule.subnet(SUBNET).probe_tcp("10.1.2.3", **OPTIONS)
