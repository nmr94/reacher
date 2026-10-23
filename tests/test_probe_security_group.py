"""Temporary security-group requests, safe rollback and combined-role cleanup."""

import warnings
from unittest.mock import Mock
from uuid import UUID

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from botocore.stub import Stubber
from test_probe import (
    ACCOUNT,
    GROUP,
    NAME,
    REGION,
    ROLE,
    SUBNET,
    create,
    delete,
    invoke,
    session,
    state,
)
from test_probe_role import ROLE_ARN, put, role_create, role_delete

from aws_network_asserts import (
    AccountMismatchError,
    CleanupWarning,
    ProbeError,
    ProbeTimeoutError,
    RuleBuilder,
    WriteNotAllowedError,
    probe,
)

VPC = "vpc-0123456789abcdef0"
OPTIONS = {
    "execution_role_arn": ROLE,
    "auto_create_security_group": True,
    "allow_write": True,
}


@pytest.fixture
def cloud(monkeypatch):
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    monkeypatch.setattr(probe.time, "sleep", Mock())
    rule = RuleBuilder(session=session(), account_id=ACCOUNT, config_mode="off")
    with (
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("lambda", REGION)) as lam,
        Stubber(rule.clients.client("ec2", REGION)) as ec2,
        Stubber(rule.clients.client("iam", REGION)) as iam,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        yield rule, lam, ec2, iam
        for stub in (sts, lam, ec2, iam):
            stub.assert_no_pending_responses()


def check(rule, **options):
    return rule.subnet(SUBNET).probe_tcp("database.example", **{**OPTIONS, **options})


def subnet(ec2, **updates):
    ec2.add_response(
        "describe_subnets",
        {
            "Subnets": [
                {
                    "SubnetId": SUBNET,
                    "VpcId": VPC,
                    "OwnerId": ACCOUNT,
                    "State": "available",
                    **updates,
                }
            ]
        },
        {"SubnetIds": [SUBNET]},
    )


def group_create(ec2, **response):
    ec2.add_response(
        "create_security_group",
        {"GroupId": GROUP, **response},
        {
            "GroupName": NAME,
            "Description": "Temporary AWS network assertions Lambda probe security group",
            "VpcId": VPC,
            "TagSpecifications": [
                {
                    "ResourceType": "security-group",
                    "Tags": [{"Key": "aws-network-asserts:probe", "Value": NAME}],
                }
            ],
        },
    )


def visible(ec2, **updates):
    ec2.add_response(
        "describe_security_groups",
        {"SecurityGroups": [{"GroupId": GROUP, "VpcId": VPC, "OwnerId": ACCOUNT, **updates}]},
        {"GroupIds": [GROUP]},
    )


def group_delete(ec2, **updates):
    ec2.add_response(
        "delete_security_group", {"Return": True, "GroupId": GROUP, **updates}, {"GroupId": GROUP}
    )


def setup_group(ec2):
    subnet(ec2)
    group_create(ec2)
    visible(ec2)


def lifecycle(lam, role=ROLE):
    create(lam, execution_role_arn=role)
    state(lam)
    invoke(lam)
    delete(lam)


@pytest.mark.parametrize(
    "options",
    [
        {"auto_create_security_group": "true"},
        {"auto_create_security_group": 1},
        {"security_group_ids": [GROUP]},
        {"security_group_ids": []},
        {"auto_create_security_group": False},
        {"security_group_cleanup_timeout": 0},
        {"security_group_cleanup_timeout": True},
        {"security_group_cleanup_timeout": float("inf")},
    ],
)
def test_invalid_options_are_rejected_without_aws_calls(monkeypatch, options):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("Unexpected AWS client"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(ValueError):
        check(rule, **options)
    client.assert_not_called()


@pytest.mark.parametrize("allow", [False, None, "true", 1])
def test_write_permission_remains_literal_true_before_any_aws_calls(monkeypatch, allow):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("Unexpected AWS client"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(WriteNotAllowedError):
        check(rule, allow_write=allow)
    client.assert_not_called()


def test_omitting_write_permission_is_denied():
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with pytest.raises(WriteNotAllowedError):
        rule.subnet(SUBNET).probe_tcp(
            "10.1.2.3",
            execution_role_arn=ROLE,
            auto_create_security_group=True,
        )


def test_selected_account_still_required():
    rule = RuleBuilder(session=session(), config_mode="off")
    with pytest.raises(ValueError, match="account"):
        check(rule)


def test_creates_group_in_live_subnet_vpc_and_cleans_up(cloud):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    lifecycle(lam)
    group_delete(ec2)
    result = check(rule)
    assert result
    assert result.evidence["security_group_ids"] == [GROUP]
    assert result.evidence["temporary_security_group"] == {
        "cleanup": "deleted",
        "group_name": NAME,
        "subnet_id": SUBNET,
        "vpc_id": VPC,
        "subnet_owner_id": ACCOUNT,
        "group_id": GROUP,
    }


def test_shared_subnet_owner_can_differ_from_new_group_owner(cloud):
    rule, lam, ec2, _ = cloud
    subnet(ec2, OwnerId="222222222222")
    group_create(ec2)
    visible(ec2)
    lifecycle(lam)
    group_delete(ec2)
    result = check(rule)
    assert result.evidence["temporary_security_group"]["subnet_owner_id"] == "222222222222"
    assert result.evidence["account_id"] == ACCOUNT


def test_subnet_discovery_consumes_all_pages(cloud):
    rule, lam, ec2, _ = cloud
    ec2.add_response(
        "describe_subnets", {"Subnets": [], "NextToken": "next"}, {"SubnetIds": [SUBNET]}
    )
    ec2.add_response(
        "describe_subnets",
        {"Subnets": [{"SubnetId": SUBNET, "VpcId": VPC, "OwnerId": ACCOUNT, "State": "available"}]},
        {"SubnetIds": [SUBNET], "NextToken": "next"},
    )
    group_create(ec2)
    visible(ec2)
    lifecycle(lam)
    group_delete(ec2)
    assert check(rule)


@pytest.mark.parametrize(
    "updates",
    [
        {"SubnetId": "subnet-other"},
        {"VpcId": ""},
        {"OwnerId": "bad"},
        {"State": "pending"},
    ],
)
def test_unknown_or_contradictory_subnet_metadata_never_creates_a_group(cloud, updates):
    rule, _, ec2, _ = cloud
    subnet(ec2, **updates)
    with pytest.raises(ProbeError):
        check(rule)


@pytest.mark.parametrize("response", [{}, {"Subnets": []}])
def test_missing_subnet_is_error_before_creation(cloud, response):
    rule, _, ec2, _ = cloud
    ec2.add_response("describe_subnets", response, {"SubnetIds": [SUBNET]})
    with pytest.raises(ProbeError):
        check(rule)


def test_subnet_read_permission_failure_does_not_deploy(cloud):
    rule, _, ec2, _ = cloud
    ec2.add_client_error("describe_subnets", "UnauthorizedOperation")
    with pytest.raises(ClientError, match="UnauthorizedOperation"):
        check(rule)


def test_create_group_permission_failure_does_not_delete_any_group(cloud):
    rule, _, ec2, _ = cloud
    subnet(ec2)
    ec2.add_client_error("create_security_group", "UnauthorizedOperation")
    with pytest.raises(ClientError, match="UnauthorizedOperation"):
        check(rule)


def test_creation_name_collision_never_uses_or_deletes_existing_group(cloud):
    rule, _, ec2, _ = cloud
    subnet(ec2)
    ec2.add_client_error("create_security_group", "InvalidGroup.Duplicate")
    with pytest.raises(ClientError, match="InvalidGroup.Duplicate"):
        check(rule)


@pytest.mark.parametrize(
    "metadata",
    [{"RetryAttempts": 1}, {"HTTPStatusCode": 200}, {"RetryAttempts": -1}],
)
def test_uncertain_group_creation_keeps_original_error_without_deleting_by_name(cloud, metadata):
    rule, _, ec2, _ = cloud
    subnet(ec2)
    ec2.add_client_error("create_security_group", "UnauthorizedOperation", response_meta=metadata)
    with pytest.warns(CleanupWarning):
        with pytest.raises(ClientError, match="UnauthorizedOperation") as caught:
            check(rule)
    evidence = caught.value.evidence["temporary_security_group"]
    assert evidence["cleanup"] == "creation_unconfirmed"
    assert evidence["group_name"] == NAME
    assert "group_id" not in evidence


def test_missing_created_group_id_does_not_authorize_deletion(cloud):
    rule, _, ec2, _ = cloud
    subnet(ec2)
    ec2.add_response("create_security_group", {})
    with pytest.warns(CleanupWarning, match="creation unconfirmed"):
        with pytest.raises(ProbeError, match="GroupId") as caught:
            check(rule)
    assert caught.value.evidence["temporary_security_group"]["group_name"] == NAME
    assert caught.value.evidence["temporary_security_group"]["cleanup"] == "creation_unconfirmed"


def test_group_visibility_not_found_is_retried(cloud):
    rule, lam, ec2, _ = cloud
    subnet(ec2)
    group_create(ec2)
    ec2.add_client_error("describe_security_groups", "InvalidGroup.NotFound")
    visible(ec2)
    lifecycle(lam)
    group_delete(ec2)
    assert check(rule)
    probe.time.sleep.assert_called_once()


def test_group_visibility_pages_are_consumed(cloud):
    rule, lam, ec2, _ = cloud
    subnet(ec2)
    group_create(ec2)
    ec2.add_response(
        "describe_security_groups",
        {"SecurityGroups": [], "NextToken": "next"},
        {"GroupIds": [GROUP]},
    )
    ec2.add_response(
        "describe_security_groups",
        {"SecurityGroups": [{"GroupId": GROUP, "VpcId": VPC, "OwnerId": ACCOUNT}]},
        {"GroupIds": [GROUP], "NextToken": "next"},
    )
    lifecycle(lam)
    group_delete(ec2)
    assert check(rule)


@pytest.mark.parametrize(
    "updates",
    [
        {"OwnerId": "222222222222"},
        {"VpcId": "vpc-other"},
        {"GroupId": "sg-other"},
        {"GroupName": "existing-unrelated-group"},
    ],
)
def test_contradictory_group_identity_does_not_authorize_deletion(cloud, updates):
    rule, _, ec2, _ = cloud
    subnet(ec2)
    group_create(ec2)
    visible(ec2, **updates)
    with pytest.warns(CleanupWarning, match="creation unconfirmed"):
        with pytest.raises(ProbeError, match="identity") as caught:
            check(rule)
    evidence = caught.value.evidence["temporary_security_group"]
    assert evidence["cleanup"] == "creation_unconfirmed"
    assert evidence["reported_groups"][0].items() >= updates.items()


def test_group_visibility_timeout_rolls_back_group(cloud, monkeypatch):
    rule, _, ec2, _ = cloud
    subnet(ec2)
    group_create(ec2)
    ec2.add_client_error("describe_security_groups", "InvalidGroup.NotFound")
    group_delete(ec2)
    monkeypatch.setattr(probe.time, "monotonic", Mock(side_effect=[0, 300, 300]))
    with pytest.raises(ProbeTimeoutError, match="group propagation") as caught:
        check(rule)
    assert caught.value.evidence["temporary_security_group"]["cleanup"] == "deleted"


def test_unconfirmed_visibility_and_delete_not_found_are_not_treated_as_gone(cloud, monkeypatch):
    rule, _, ec2, _ = cloud
    subnet(ec2)
    group_create(ec2)
    ec2.add_client_error("describe_security_groups", "UnauthorizedOperation")
    ec2.add_client_error("delete_security_group", "InvalidGroup.NotFound")
    monkeypatch.setattr(probe.time, "monotonic", Mock(side_effect=[0, 0, 1200]))
    with pytest.warns(CleanupWarning, match="cleanup_timeout"):
        with pytest.raises(ClientError, match="UnauthorizedOperation") as caught:
            check(rule)
    assert caught.value.evidence["temporary_security_group"]["cleanup"] == "retained"


def test_dependency_violation_is_retried_until_group_unused(cloud):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    lifecycle(lam)
    ec2.add_client_error("delete_security_group", "DependencyViolation")
    group_delete(ec2)
    assert check(rule)
    probe.time.sleep.assert_called_once()


def test_cleanup_timeout_retains_group_and_warns(cloud, monkeypatch):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    lifecycle(lam)
    ec2.add_client_error("delete_security_group", "DependencyViolation")
    monkeypatch.setattr(probe.time, "monotonic", Mock(side_effect=[0, 0, 0, 1200]))
    with pytest.warns(CleanupWarning, match="security_group_cleanup_timeout"):
        result = check(rule)
    assert result
    assert result.evidence["cleanup"] == "deleted"
    assert result.evidence["temporary_security_group"]["cleanup"] == "retained"


def test_invocation_failure_still_cleans_up_created_group(cloud):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    create(lam)
    state(lam)
    lam.add_client_error("invoke", "AccessDeniedException")
    delete(lam)
    group_delete(ec2)
    with pytest.raises(ClientError, match="AccessDeniedException") as caught:
        check(rule)
    assert caught.value.evidence["temporary_security_group"]["cleanup"] == "deleted"


def test_function_create_rejection_rolls_back_unused_group(cloud):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    lam.add_client_error("create_function", "InvalidParameterValueException", "Invalid VPC")
    group_delete(ec2)
    with pytest.raises(ClientError, match="Invalid VPC"):
        check(rule)


def test_uncertain_function_creation_retains_group(cloud):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    lam.add_client_error("create_function", "ServiceException", http_status_code=500)
    with pytest.warns(CleanupWarning, match="retaining its security group"):
        with pytest.raises(ClientError):
            check(rule)


def test_function_deletion_failure_retains_group(cloud):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    create(lam)
    state(lam)
    invoke(lam)
    lam.add_client_error("delete_function", "AccessDeniedException")
    with pytest.warns(CleanupWarning, match="retaining its security group"):
        result = check(rule)
    assert result.evidence["temporary_security_group"]["cleanup"] == "retained"


def test_existing_error_survives_group_cleanup_failure_with_warnings_as_errors(cloud):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    create(lam)
    state(lam)
    lam.add_client_error("invoke", "AccessDeniedException")
    delete(lam)
    ec2.add_client_error("delete_security_group", "UnauthorizedOperation")
    with warnings.catch_warnings():
        warnings.simplefilter("error", CleanupWarning)
        with pytest.raises(ClientError, match="AccessDeniedException") as caught:
            check(rule)
    assert caught.value.evidence["temporary_security_group"]["cleanup"] == "retained"


def test_existing_group_inputs_trigger_no_group_creation_or_deletion(cloud):
    rule, lam, _, _ = cloud
    lifecycle(lam)
    assert check(rule, auto_create_security_group=False, security_group_ids=[GROUP])


def test_combined_options_cleanup_order_is_function_group_policy_role(cloud):
    rule, lam, ec2, iam = cloud
    setup_group(ec2)
    role_create(iam)
    put(iam)
    lifecycle(lam, role=ROLE_ARN)
    group_delete(ec2)
    role_delete(iam)
    events = []

    def record(model, **kwargs):
        if model.name.startswith("Delete"):
            events.append(model.name)

    for stub in (lam, ec2, iam):
        stub.client.meta.events.register("before-parameter-build.*.*", record)
    result = check(rule, execution_role_arn=None, auto_create_execution_role=True)
    assert result
    assert events == ["DeleteFunction", "DeleteSecurityGroup", "DeleteRolePolicy", "DeleteRole"]
    assert result.evidence["temporary_role"]["cleanup"] == "deleted"
    assert result.evidence["temporary_security_group"]["cleanup"] == "deleted"


def test_failed_group_cleanup_retains_auto_role_without_revoking_eni_permissions(cloud):
    rule, lam, ec2, iam = cloud
    setup_group(ec2)
    role_create(iam)
    put(iam)
    lifecycle(lam, role=ROLE_ARN)
    ec2.add_client_error("delete_security_group", "UnauthorizedOperation")
    with pytest.warns(CleanupWarning, match="security_group=.*role="):
        result = check(rule, execution_role_arn=None, auto_create_execution_role=True)
    assert result.evidence["temporary_role"]["cleanup"] == "retained"


def test_role_creation_failure_rolls_back_group(cloud):
    rule, _, ec2, iam = cloud
    setup_group(ec2)
    iam.add_client_error("create_role", "AccessDenied")
    group_delete(ec2)
    with pytest.raises(ClientError, match="AccessDenied"):
        check(rule, execution_role_arn=None, auto_create_execution_role=True)


def test_group_failure_before_lambda_does_not_prevent_unused_role_cleanup(cloud):
    rule, _, ec2, iam = cloud
    setup_group(ec2)
    role_create(iam)
    iam.add_client_error("put_role_policy", "AccessDenied")
    ec2.add_client_error("delete_security_group", "UnauthorizedOperation")
    role_delete(iam)
    with pytest.warns(CleanupWarning, match="security_group="):
        with pytest.raises(ClientError, match="AccessDenied") as caught:
            check(rule, execution_role_arn=None, auto_create_execution_role=True)
    assert caught.value.evidence["temporary_role"]["cleanup"] == "deleted"


def test_lost_group_creation_response_keeps_name_for_investigation(cloud, monkeypatch):
    rule, _, ec2, _ = cloud
    subnet(ec2)
    monkeypatch.setattr(
        ec2.client,
        "create_security_group",
        Mock(side_effect=EndpointConnectionError(endpoint_url="test")),
    )
    with pytest.warns(CleanupWarning, match="creation unconfirmed"):
        with pytest.raises(EndpointConnectionError) as caught:
            check(rule)
    info = caught.value.evidence["temporary_security_group"]
    assert info["group_name"] == NAME
    assert info["vpc_id"] == VPC
    assert info["cleanup"] == "creation_unconfirmed"


def test_interrupted_function_creation_retains_group(cloud, monkeypatch):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    monkeypatch.setattr(lam.client, "create_function", Mock(side_effect=KeyboardInterrupt))
    # Creation is unconfirmed: preserve the group for a potentially created Lambda.
    with pytest.warns(CleanupWarning, match="retaining"):
        with pytest.raises(KeyboardInterrupt):
            check(rule)


def test_account_mismatch_prevents_all_live_resource_clients(monkeypatch):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with Stubber(rule.clients.client("sts", REGION)) as sts:
        sts.add_response("get_caller_identity", {"Account": "222222222222"}, {})
        client = Mock(side_effect=AssertionError("Unexpected unverified service client"))
        monkeypatch.setattr(rule.clients.session, "client", client)
        with pytest.raises(AccountMismatchError):
            check(rule)
        client.assert_not_called()
        sts.assert_no_pending_responses()


def test_interruption_after_confirmed_function_creation_still_cleans_up(cloud, monkeypatch):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    create(lam)
    monkeypatch.setattr(
        lam.client, "get_function_configuration", Mock(side_effect=KeyboardInterrupt)
    )
    delete(lam)
    group_delete(ec2)
    with pytest.raises(KeyboardInterrupt):
        check(rule)


def test_group_deletion_rejects_explicit_false_response(cloud):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    lifecycle(lam)
    group_delete(ec2, Return=False)
    with pytest.warns(CleanupWarning, match="did not confirm deletion"):
        result = check(rule)
    assert result.evidence["temporary_security_group"]["cleanup"] == "retained"


def test_visible_group_already_deleted_is_tolerated(cloud):
    rule, lam, ec2, _ = cloud
    setup_group(ec2)
    lifecycle(lam)
    ec2.add_client_error("delete_security_group", "InvalidGroup.NotFound")
    result = check(rule)
    assert result.evidence["temporary_security_group"]["cleanup"] == "deleted"


def test_member_credentials_region_and_endpoint_apply_to_group_lifecycle(monkeypatch):
    central, member = session(), session()
    region = "us-east-1"
    endpoint = "https://ec2.test.invalid"
    clients = {
        service: member.client(
            service, region_name=region, endpoint_url=f"https://{service}.test.invalid"
        )
        for service in ("sts", "lambda", "ec2")
    }
    factory = Mock(side_effect=lambda service, **kwargs: clients[service])
    monkeypatch.setattr(member, "client", factory)
    monkeypatch.setattr(central, "client", Mock(side_effect=AssertionError("Central AWS request")))
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    rule = (
        RuleBuilder(
            session=central,
            config_mode="off",
            account_sessions={ACCOUNT: member},
            endpoint_urls={f"{region}:ec2": endpoint},
        )
        .in_account(ACCOUNT)
        .in_region(region)
    )
    with (
        Stubber(clients["sts"]) as sts,
        Stubber(clients["lambda"]) as lam,
        Stubber(clients["ec2"]) as ec2,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        setup_group(ec2)
        lifecycle(lam)
        group_delete(ec2)
        result = check(rule)
        assert result
        assert result.evidence["region"] == region
        for stub in (sts, lam, ec2):
            stub.assert_no_pending_responses()
    assert [call.args[0] for call in factory.call_args_list] == ["sts", "lambda", "ec2"]
    assert factory.call_args_list[-1].kwargs["endpoint_url"] == endpoint
    assert factory.call_args_list[-1].kwargs["region_name"] == region


@pytest.mark.parametrize("mode", ["required", "prefer"])
def test_config_permission_failure_precedes_any_group_or_lambda_client(monkeypatch, mode):
    rule = RuleBuilder(
        session=session(),
        config_mode=mode,
        config_aggregator="network",
        config_region=REGION,
        account_id=ACCOUNT,
    )
    client = Mock(side_effect=AssertionError("Unexpected live client"))
    monkeypatch.setattr(rule, "_live_client", client)
    with Stubber(rule.config_clients.client("config", REGION)) as config:
        config.add_client_error("get_aggregate_resource_config", "AccessDeniedException")
        with pytest.raises(ClientError, match="AccessDeniedException"):
            check(rule)
        client.assert_not_called()
        config.assert_no_pending_responses()


@pytest.mark.parametrize(
    "code,metadata",
    [
        ("AccessDeniedException", {"RetryAttempts": 1}),
        ("InvalidParameterValueException", {"RetryAttempts": 1}),
        ("RequestTimeoutException", {}),
    ],
)
def test_ambiguous_create_error_retains_both_dependencies(cloud, code, metadata):
    rule, lam, ec2, iam = cloud
    setup_group(ec2)
    role_create(iam)
    put(iam)
    lam.add_client_error(
        "create_function",
        code,
        "The role defined for the function cannot be assumed by Lambda.",
        http_status_code=400,
        response_meta=metadata,
    )
    with pytest.warns(CleanupWarning, match="retaining"):
        with pytest.raises(ClientError) as caught:
            check(rule, execution_role_arn=None, auto_create_execution_role=True)
    assert caught.value.evidence["cleanup"] == "creation_unconfirmed"
    assert caught.value.evidence["temporary_role"]["cleanup"] == "retained"
    assert caught.value.evidence["temporary_security_group"]["cleanup"] == "retained"


def test_malformed_function_creation_retains_automatic_dependencies(cloud):
    rule, lam, ec2, iam = cloud
    setup_group(ec2)
    role_create(iam)
    put(iam)
    lam.add_response("create_function", {})
    with pytest.warns(CleanupWarning, match="retaining"):
        with pytest.raises(ProbeError, match="function identity") as caught:
            check(rule, execution_role_arn=None, auto_create_execution_role=True)
    assert caught.value.evidence["temporary_role"]["cleanup"] == "retained"
    assert caught.value.evidence["temporary_security_group"]["cleanup"] == "retained"
