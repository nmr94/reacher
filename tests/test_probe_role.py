"""Temporary execution-role SDK contracts, including safe rollback boundaries."""

import json
import warnings
from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import UUID

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.stub import Stubber
from test_probe import ACCOUNT, GROUP, NAME, REGION, SUBNET, create, delete, invoke, session, state

from aws_network_asserts import (
    AccountMismatchError,
    CleanupWarning,
    ProbeError,
    ProbeTimeoutError,
    RuleBuilder,
    WriteNotAllowedError,
    probe,
)

ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/{NAME}"
POLICY_NAME = "VpcNetworkInterfaces"
ENI = "eni-0123456789abcdef0"
TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSubnets",
                "ec2:DeleteNetworkInterface",
                "ec2:AssignPrivateIpAddresses",
                "ec2:UnassignPrivateIpAddresses",
            ],
            "Resource": "*",
        }
    ],
}


@pytest.fixture
def cloud(monkeypatch):
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    monkeypatch.setattr(probe.time, "sleep", Mock())
    # Both modules use Python's shared time module; no real sleeps in role polls.
    rule = RuleBuilder(session=session(), account_id=ACCOUNT, config_mode="off")
    with (
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("iam", REGION)) as iam,
        Stubber(rule.clients.client("lambda", REGION)) as lam,
        Stubber(rule.clients.client("ec2", REGION)) as ec2,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        yield rule, iam, lam, ec2
        for stub in (sts, iam, lam, ec2):
            stub.assert_no_pending_responses()


def check(rule, **options):
    return rule.subnet(SUBNET).probe_tcp(
        "database.example",
        **{
            "allow_write": True,
            "auto_create_execution_role": True,
            "security_group_ids": [GROUP],
            **options,
        },
    )


def role_create(iam, **overrides):
    role = {
        "Path": "/",
        "RoleName": NAME,
        "RoleId": "AROA0123456789ABCDEFGH",
        "Arn": ROLE_ARN,
        "CreateDate": datetime(2026, 10, 22, tzinfo=timezone.utc),
        **overrides,
    }
    iam.add_response(
        "create_role",
        {"Role": role},
        {
            "RoleName": NAME,
            "AssumeRolePolicyDocument": json.dumps(TRUST),
            "Description": "Temporary AWS network assertions Lambda execution role",
        },
    )


def put(iam):
    iam.add_response(
        "put_role_policy",
        {},
        {"RoleName": NAME, "PolicyName": POLICY_NAME, "PolicyDocument": json.dumps(POLICY)},
    )


def role_delete(iam):
    iam.add_response("delete_role_policy", {}, {"RoleName": NAME, "PolicyName": POLICY_NAME})
    iam.add_response("delete_role", {}, {"RoleName": NAME})


def eni_response(ec2, items, token=None, **response):
    request = {
        "Filters": [
            {"Name": "subnet-id", "Values": [SUBNET]},
            {"Name": "group-id", "Values": [GROUP]},
            {"Name": "interface-type", "Values": ["lambda"]},
        ]
    }
    if token:
        request["NextToken"] = token
    ec2.add_response(
        "describe_network_interfaces", {"NetworkInterfaces": items, **response}, request
    )


def eni(**overrides):
    return {
        "NetworkInterfaceId": ENI,
        "OwnerId": ACCOUNT,
        "SubnetId": SUBNET,
        "Groups": [{"GroupId": GROUP}],
        "InterfaceType": "lambda",
        **overrides,
    }


def lifecycle(iam, lam):
    role_create(iam)
    put(iam)
    create(lam, execution_role_arn=ROLE_ARN)
    state(lam)
    invoke(lam)
    delete(lam)


@pytest.mark.parametrize(
    "options",
    [
        {"execution_role_arn": ROLE_ARN},
        {"auto_create_execution_role": "true"},
        {"auto_create_execution_role": 1},
        {"auto_create_execution_role": False},
        {"role_cleanup_timeout": 0},
        {"role_cleanup_timeout": True},
        {"role_cleanup_timeout": float("nan")},
    ],
)
def test_role_options_are_validated_before_any_aws_call(monkeypatch, options):
    rule = RuleBuilder(session=session(), account_id=ACCOUNT, config_mode="off")
    client = Mock(side_effect=AssertionError("Unexpected AWS client"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(ValueError):
        check(rule, **options)
    client.assert_not_called()


def test_auto_create_still_requires_per_call_write_permission(monkeypatch):
    rule = RuleBuilder(session=session(), account_id=ACCOUNT, config_mode="off")
    client = Mock(side_effect=AssertionError("Unexpected AWS client"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(WriteNotAllowedError, match="allow_write"):
        check(rule, allow_write=False)
    client.assert_not_called()


def test_role_policy_function_and_cleanup_contract(cloud):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    eni_response(ec2, [])
    role_delete(iam)
    result = check(rule)
    assert result
    assert result.evidence["execution_role_arn"] == ROLE_ARN
    assert result.evidence["temporary_role"] == {
        "role_name": NAME,
        "role_arn": ROLE_ARN,
        "cleanup": "deleted",
        "remaining_eni_ids": [],
    }


def test_cleanup_order_is_function_then_enis_then_policy_then_role(cloud):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    eni_response(ec2, [])
    role_delete(iam)
    events = []

    def record(model, **kwargs):
        if model.name in {
            "DeleteFunction",
            "DescribeNetworkInterfaces",
            "DeleteRolePolicy",
            "DeleteRole",
        }:
            events.append(model.name)

    for stub in (iam, lam, ec2):
        stub.client.meta.events.register("before-parameter-build.*.*", record)
    assert check(rule)
    assert events == [
        "DeleteFunction",
        "DescribeNetworkInterfaces",
        "DeleteRolePolicy",
        "DeleteRole",
    ]


@pytest.mark.parametrize(
    "message",
    [
        "The role defined for the function cannot be assumed by Lambda.",
        "The provided execution role does not have permissions to call "
        "CreateNetworkInterface on EC2",
    ],
)
def test_known_role_propagation_rejections_are_retried(cloud, message):
    rule, iam, lam, ec2 = cloud
    role_create(iam)
    put(iam)
    lam.add_client_error("create_function", "InvalidParameterValueException", message)
    create(lam, execution_role_arn=ROLE_ARN)
    state(lam)
    invoke(lam)
    delete(lam)
    eni_response(ec2, [])
    role_delete(iam)
    assert check(rule)
    probe.time.sleep.assert_called_once()


def test_propagation_timeout_cleans_up_role_without_a_function(cloud, monkeypatch):
    rule, iam, lam, _ = cloud
    role_create(iam)
    put(iam)
    monkeypatch.setattr(probe.time, "monotonic", Mock(side_effect=[0, 300, 300]))
    lam.add_client_error(
        "create_function",
        "InvalidParameterValueException",
        "The role defined for the function cannot be assumed by Lambda.",
    )
    role_delete(iam)
    with pytest.raises(ProbeTimeoutError, match="propagation") as caught:
        check(rule)
    assert caught.value.evidence["temporary_role"]["cleanup"] == "deleted"


def test_create_role_denied_never_deletes_existing_role(cloud):
    rule, iam, _, _ = cloud
    iam.add_client_error("create_role", "AccessDenied")
    with pytest.raises(ClientError, match="AccessDenied"):
        check(rule)


def test_role_name_collision_never_reuses_or_deletes_that_role(cloud):
    rule, iam, _, _ = cloud
    iam.add_client_error("create_role", "EntityAlreadyExists")
    with pytest.raises(ClientError, match="EntityAlreadyExists"):
        check(rule)


def test_policy_failure_rolls_back_only_the_created_role(cloud):
    rule, iam, _, _ = cloud
    role_create(iam)
    iam.add_client_error("put_role_policy", "AccessDenied")
    iam.add_client_error("delete_role_policy", "NoSuchEntity")
    iam.add_response("delete_role", {}, {"RoleName": NAME})
    with pytest.raises(ClientError, match="AccessDenied") as caught:
        check(rule)
    assert caught.value.evidence["temporary_role"]["cleanup"] == "deleted"


@pytest.mark.parametrize(
    "changes",
    [
        {"Arn": f"arn:aws:iam::222222222222:role/{NAME}"},
        {"RoleName": f"{NAME}-other"},
    ],
)
def test_unconfirmed_role_identity_does_not_authorize_policy_or_role_deletion(cloud, changes):
    rule, iam, _, _ = cloud
    role_create(iam, **changes)
    with pytest.warns(CleanupWarning):
        with pytest.raises(ProbeError, match="role identity") as caught:
            check(rule)
    evidence = caught.value.evidence["temporary_role"]
    assert evidence["cleanup"] == "creation_unconfirmed"
    assert evidence["role_name"] == NAME
    assert evidence["role_arn"] == ROLE_ARN


@pytest.mark.parametrize(
    "metadata",
    [{"RetryAttempts": 1}, {"HTTPStatusCode": 200}, {"RetryAttempts": -1}],
)
def test_uncertain_role_creation_keeps_original_error_and_identity(cloud, metadata):
    rule, iam, _, _ = cloud
    iam.add_client_error("create_role", "AccessDenied", response_meta=metadata)
    with pytest.warns(CleanupWarning):
        with pytest.raises(ClientError, match="AccessDenied") as caught:
            check(rule)
    evidence = caught.value.evidence["temporary_role"]
    assert evidence["cleanup"] == "creation_unconfirmed"
    assert evidence["role_name"] == NAME


def test_unrelated_invalid_parameter_is_not_retried(cloud):
    rule, iam, lam, _ = cloud
    role_create(iam)
    put(iam)
    lam.add_client_error("create_function", "InvalidParameterValueException", "Invalid subnet")
    role_delete(iam)
    with pytest.raises(ClientError, match="Invalid subnet"):
        check(rule)
    probe.time.sleep.assert_not_called()


def test_function_creation_permission_denied_still_cleans_up_role(cloud):
    rule, iam, lam, _ = cloud
    role_create(iam)
    put(iam)
    lam.add_client_error("create_function", "AccessDeniedException")
    role_delete(iam)
    with pytest.raises(ClientError, match="AccessDeniedException"):
        check(rule)


def test_uncertain_function_creation_retains_role(cloud):
    rule, iam, lam, _ = cloud
    role_create(iam)
    put(iam)
    lam.add_client_error("create_function", "ServiceException", http_status_code=500)
    with pytest.warns(CleanupWarning, match="retaining"):
        with pytest.raises(ClientError) as caught:
            check(rule)
    assert caught.value.evidence["temporary_role"]["cleanup"] == "retained"


def test_lost_creation_response_retains_role(cloud, monkeypatch):
    rule, iam, lam, _ = cloud
    role_create(iam)
    put(iam)
    monkeypatch.setattr(
        lam.client,
        "create_function",
        Mock(side_effect=EndpointConnectionError(endpoint_url="test")),
    )
    with pytest.warns(CleanupWarning, match=NAME):
        with pytest.raises(EndpointConnectionError):
            check(rule)


def test_waits_for_all_paginated_matching_enis_before_removing_role(cloud):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    eni_response(ec2, [], NextToken="more")
    eni_response(ec2, [eni()], token="more")
    eni_response(ec2, [])
    role_delete(iam)
    assert check(rule)
    probe.time.sleep.assert_called_once()


def test_eni_group_filter_is_checked_for_exact_set(cloud):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    eni_response(ec2, [eni(Groups=[{"GroupId": GROUP}, {"GroupId": "sg-other"}])])
    role_delete(iam)
    assert check(rule)
    probe.time.sleep.assert_not_called()


def test_eni_timeout_keeps_role_and_policy_and_warns(cloud, monkeypatch):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    eni_response(ec2, [eni()])
    monkeypatch.setattr(probe.time, "monotonic", Mock(side_effect=[0, 0, 0, 1200]))
    with pytest.warns(CleanupWarning, match="role_cleanup_timeout"):
        result = check(rule)
    assert result
    assert result.evidence["cleanup"] == "deleted"
    assert result.evidence["temporary_role"]["cleanup"] == "retained"
    assert result.evidence["temporary_role"]["remaining_eni_ids"] == [ENI]


def test_eni_read_permission_failure_keeps_role_and_policy(cloud):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    ec2.add_client_error("describe_network_interfaces", "UnauthorizedOperation")
    with pytest.warns(CleanupWarning, match="UnauthorizedOperation"):
        result = check(rule)
    assert result.evidence["temporary_role"]["cleanup"] == "retained"


@pytest.mark.parametrize("items", [[{}], [eni(Groups=[{}])], [eni(Groups=[])]])
def test_malformed_eni_metadata_does_not_authorize_role_deletion(cloud, items):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    eni_response(ec2, items)
    with pytest.warns(CleanupWarning, match="role="):
        result = check(rule)
    assert result.evidence["temporary_role"]["cleanup"] == "retained"


def test_function_delete_failure_retains_role_and_policy(cloud):
    rule, iam, lam, _ = cloud
    role_create(iam)
    put(iam)
    create(lam, execution_role_arn=ROLE_ARN)
    state(lam)
    invoke(lam)
    lam.add_client_error("delete_function", "AccessDeniedException")
    with pytest.warns(CleanupWarning, match="function=.*role="):
        result = check(rule)
    assert result.evidence["cleanup"] == "failed"
    assert result.evidence["temporary_role"]["cleanup"] == "retained"


def test_invocation_error_survives_role_cleanup_failure_and_warnings_as_errors(cloud):
    rule, iam, lam, ec2 = cloud
    role_create(iam)
    put(iam)
    create(lam, execution_role_arn=ROLE_ARN)
    state(lam)
    lam.add_client_error("invoke", "AccessDeniedException")
    delete(lam)
    eni_response(ec2, [])
    iam.add_client_error("delete_role_policy", "AccessDenied")
    with warnings.catch_warnings():
        warnings.simplefilter("error", CleanupWarning)
        with pytest.raises(ClientError, match="AccessDeniedException") as caught:
            check(rule)
    assert caught.value.evidence["temporary_role"]["cleanup"] == "retained"


def test_eventually_consistent_role_delete_conflict_is_retried(cloud):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    eni_response(ec2, [])
    iam.add_response("delete_role_policy", {}, {"RoleName": NAME, "PolicyName": POLICY_NAME})
    iam.add_client_error("delete_role", "DeleteConflict")
    iam.add_response("delete_role_policy", {}, {"RoleName": NAME, "PolicyName": POLICY_NAME})
    iam.add_response("delete_role", {}, {"RoleName": NAME})
    assert check(rule)
    probe.time.sleep.assert_called_once()


def test_new_role_policy_visibility_is_retried(cloud):
    rule, iam, lam, ec2 = cloud
    role_create(iam)
    iam.add_client_error("put_role_policy", "NoSuchEntity")
    put(iam)
    create(lam, execution_role_arn=ROLE_ARN)
    state(lam)
    invoke(lam)
    delete(lam)
    eni_response(ec2, [])
    role_delete(iam)
    assert check(rule)
    probe.time.sleep.assert_called_once()


def test_policy_visibility_timeout_rolls_back_role(cloud, monkeypatch):
    rule, iam, _, _ = cloud
    role_create(iam)
    iam.add_client_error("put_role_policy", "NoSuchEntity")
    monkeypatch.setattr(probe.time, "monotonic", Mock(side_effect=[0, 300, 300]))
    role_delete(iam)
    with pytest.raises(ProbeTimeoutError, match="policy propagation") as caught:
        check(rule)
    assert caught.value.evidence["temporary_role"]["cleanup"] == "deleted"


def test_role_delete_permission_failure_warns_with_diagnostics(cloud):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    eni_response(ec2, [])
    iam.add_response("delete_role_policy", {}, {"RoleName": NAME, "PolicyName": POLICY_NAME})
    iam.add_client_error("delete_role", "AccessDenied")
    with pytest.warns(CleanupWarning, match=NAME):
        result = check(rule)
    assert result
    assert result.evidence["temporary_role"]["cleanup"] == "retained"


def test_missing_eni_collection_does_not_authorize_role_deletion(cloud):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    ec2.add_response("describe_network_interfaces", {})
    with pytest.warns(CleanupWarning, match="NetworkInterfaces"):
        result = check(rule)
    assert result.evidence["temporary_role"]["cleanup"] == "retained"


def test_creation_collision_retains_role_without_deleting_unknown_function(cloud):
    rule, iam, lam, _ = cloud
    role_create(iam)
    put(iam)
    lam.add_client_error("create_function", "ResourceConflictException")
    with pytest.warns(CleanupWarning, match="retaining"):
        with pytest.raises(ClientError, match="ResourceConflictException"):
            check(rule)


def test_existing_role_never_creates_iam_or_ec2_clients(monkeypatch):
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    rule = RuleBuilder(session=session(), account_id=ACCOUNT, config_mode="off")
    original = rule._live_client
    services = []

    def live(service):
        services.append(service)
        return original(service)

    monkeypatch.setattr(rule, "_live_client", live)
    with (
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("lambda", REGION)) as lam,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        create(lam, execution_role_arn=ROLE_ARN)
        state(lam)
        invoke(lam)
        delete(lam)
        assert check(rule, auto_create_execution_role=False, execution_role_arn=ROLE_ARN)
        sts.assert_no_pending_responses()
        lam.assert_no_pending_responses()
    assert services == ["lambda"]


def test_member_session_and_endpoints_apply_to_iam_and_cleanup_ec2(monkeypatch):
    central, member = session(), session()
    region = "us-east-1"
    clients = {
        service: member.client(
            service, region_name=region, endpoint_url=f"https://{service}.test.invalid"
        )
        for service in ("sts", "lambda", "iam", "ec2")
    }
    factory = Mock(side_effect=lambda service, **kwargs: clients[service])
    monkeypatch.setattr(member, "client", factory)
    monkeypatch.setattr(central, "client", Mock(side_effect=AssertionError("Central AWS client")))
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    rule = (
        RuleBuilder(
            session=central,
            config_mode="off",
            account_sessions={ACCOUNT: member},
            endpoint_urls={f"{region}:iam": "https://iam.test.invalid"},
        )
        .in_account(ACCOUNT)
        .in_region(region)
    )
    with (
        Stubber(clients["sts"]) as sts,
        Stubber(clients["lambda"]) as lam,
        Stubber(clients["iam"]) as iam,
        Stubber(clients["ec2"]) as ec2,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        lifecycle(iam, lam)
        eni_response(ec2, [])
        role_delete(iam)
        assert check(rule)
        for stub in (sts, lam, iam, ec2):
            stub.assert_no_pending_responses()
    assert [call.args[0] for call in factory.call_args_list] == ["sts", "lambda", "iam", "ec2"]
    assert all(call.kwargs["region_name"] == region for call in factory.call_args_list)
    assert factory.call_args_list[2].kwargs["endpoint_url"] == "https://iam.test.invalid"


def test_role_created_before_interruption_is_rolled_back(cloud, monkeypatch):
    rule, iam, _, _ = cloud
    role_create(iam)
    monkeypatch.setattr(iam.client, "put_role_policy", Mock(side_effect=KeyboardInterrupt))
    role_delete(iam)
    with pytest.raises(KeyboardInterrupt):
        check(rule)


def test_invalid_role_auto_account_stops_before_any_live_clients(monkeypatch):
    rule = RuleBuilder(session=session(), account_id=ACCOUNT, config_mode="off")
    with Stubber(rule.clients.client("sts", REGION)) as sts:
        sts.add_response("get_caller_identity", {"Account": "222222222222"}, {})
        factory = Mock(side_effect=AssertionError("Unverified live client"))
        monkeypatch.setattr(rule.clients.session, "client", factory)
        with pytest.raises(AccountMismatchError):
            check(rule)
        factory.assert_not_called()
        sts.assert_no_pending_responses()


def test_policy_appearing_after_not_found_is_removed_after_delete_conflict(cloud):
    rule, iam, lam, ec2 = cloud
    lifecycle(iam, lam)
    eni_response(ec2, [])
    iam.add_client_error("delete_role_policy", "NoSuchEntity")
    iam.add_client_error("delete_role", "DeleteConflict")
    role_delete(iam)
    result = check(rule)
    assert result.evidence["temporary_role"]["cleanup"] == "deleted"
    probe.time.sleep.assert_called_once()
