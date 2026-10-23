"""Write-ahead persistence and recovery use native request models, never AWS."""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import UUID

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from test_probe import (
    ACCOUNT,
    GROUP,
    NAME,
    OPTIONS,
    REGION,
    ROLE,
    SUBNET,
    delete,
    invoke,
    session,
    state,
)
from test_probe_role import POLICY, POLICY_NAME, ROLE_ARN, TRUST, put, role_create, role_delete
from test_probe_security_group import VPC, group_create, group_delete, subnet, visible

from aws_network_asserts import CleanupWarning, ProbeError, RuleBuilder, probe
from aws_network_asserts._recovery import _ProbeManifest, recover_probes

FUNCTION_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}"
ROLE_ID = "AROA0123456789ABCDEFGH"


def run(path, *, resources=("function",), role=ROLE, confirmed=True):
    identities = {
        "function": {
            "function_name": NAME,
            "function_arn": FUNCTION_ARN,
            "revision_id": "original-revision",
            "subnet_id": SUBNET,
            "security_group_ids": [GROUP],
            "execution_role_arn": role,
        },
        "security_group": {"group_id": GROUP, "group_name": NAME, "vpc_id": VPC},
        "role": {"role_name": NAME, "role_arn": ROLE_ARN, "role_id": ROLE_ID},
    }
    with _ProbeManifest.new(
        path,
        name=NAME,
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        subnet_id=SUBNET,
        groups=[GROUP],
    ) as manifest:
        for resource in resources:
            manifest.before_create(resource, identities[resource])
            if confirmed:
                manifest.confirm(resource, identities[resource])
    return path


@pytest.fixture
def cloud(monkeypatch):
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    rule = RuleBuilder(
        session=session(), config_mode="off", account_id=ACCOUNT, poll_interval=0.001
    )
    with (
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("lambda", REGION)) as functions,
        Stubber(rule.clients.client("ec2", REGION)) as ec2,
        Stubber(rule.clients.client("iam", REGION)) as iam,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        yield rule, functions, ec2, iam
        for stub in (sts, functions, ec2, iam):
            stub.assert_no_pending_responses()


def function(functions, *, role=ROLE, **changes):
    functions.add_response(
        "get_function_configuration",
        {
            "FunctionName": NAME,
            "FunctionArn": FUNCTION_ARN,
            "RevisionId": "original-revision",
            "Role": role,
            "VpcConfig": {"SubnetIds": [SUBNET], "SecurityGroupIds": [GROUP]},
            **changes,
        },
        {"FunctionName": NAME},
    )


def group(ec2, **changes):
    ec2.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                {
                    "GroupId": GROUP,
                    "GroupName": NAME,
                    "OwnerId": ACCOUNT,
                    "VpcId": VPC,
                    "Tags": [{"Key": "aws-network-asserts:probe", "Value": NAME}],
                    **changes,
                }
            ]
        },
        {"GroupIds": [GROUP]},
    )


def role(iam, **changes):
    iam.add_response(
        "get_role",
        {
            "Role": {
                "Path": "/",
                "RoleName": NAME,
                "RoleId": ROLE_ID,
                "Arn": ROLE_ARN,
                "CreateDate": datetime(2026, 10, 23, tzinfo=timezone.utc),
                "AssumeRolePolicyDocument": json.dumps(TRUST),
                **changes,
            }
        },
        {"RoleName": NAME},
    )


def dependencies(
    iam,
    ec2,
    functions,
    *,
    consumers=(),
    policies=(POLICY_NAME,),
    next_marker=None,
    list_error=None,
    regions=(REGION,),
):
    iam.add_response(
        "list_role_policies",
        {"PolicyNames": list(policies), "IsTruncated": False},
        {"RoleName": NAME},
    )
    if policies != (POLICY_NAME,):
        return
    iam.add_response(
        "get_role_policy",
        {"RoleName": NAME, "PolicyName": POLICY_NAME, "PolicyDocument": json.dumps(POLICY)},
        {"RoleName": NAME, "PolicyName": POLICY_NAME},
    )
    iam.add_response(
        "list_attached_role_policies",
        {"AttachedPolicies": [], "IsTruncated": False},
        {"RoleName": NAME},
    )
    iam.add_response(
        "list_instance_profiles_for_role",
        {"InstanceProfiles": [], "IsTruncated": False},
        {"RoleName": NAME},
    )
    ec2.add_response(
        "describe_regions",
        {
            "Regions": [
                {"RegionName": region, "OptInStatus": "opt-in-not-required"} for region in regions
            ]
        },
        {"AllRegions": False},
    )
    if list_error:
        functions.add_client_error(
            "list_functions", list_error, expected_params={"FunctionVersion": "ALL"}
        )
    else:
        response = {"Functions": list(consumers)}
        if next_marker:
            response["NextMarker"] = next_marker
        functions.add_response("list_functions", response, {"FunctionVersion": "ALL"})


def test_write_ahead_manifest_precedes_function_creation_and_records_cleanup(
    cloud, tmp_path, monkeypatch
):
    rule, functions, _, _ = cloud
    path = tmp_path / "run.json"
    original = functions.client.create_function

    def create(**request):
        data = json.loads(path.read_text())
        assert data["resources"]["function"]["cleanup"] == "creating"
        assert data["resources"]["function"]["confirmed"] is False
        return original(**request)

    monkeypatch.setattr(functions.client, "create_function", create)
    functions.add_response(
        "create_function",
        {"FunctionName": NAME, "FunctionArn": FUNCTION_ARN, "RevisionId": "original-revision"},
    )
    state(functions)
    invoke(functions)
    delete(functions)
    result = rule.subnet(SUBNET).probe_tcp("database.example", cleanup_manifest=path, **OPTIONS)
    data = json.loads(path.read_text())
    assert data["complete"] is True
    assert data["resources"]["function"]["identity"]["revision_id"] == "original-revision"
    assert data["resources"]["function"]["cleanup"] == "deleted"
    assert result.evidence["cleanup_manifest"] == str(path)
    assert "secret" not in path.read_text().lower()
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_existing_manifest_is_not_overwritten_before_any_create(cloud, tmp_path):
    rule, _, _, _ = cloud
    path = run(tmp_path / "run.json")
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        rule.subnet(SUBNET).probe_tcp("database.example", cleanup_manifest=path, **OPTIONS)
    assert path.read_bytes() == original


def test_journal_failure_before_create_prevents_aws_mutation(cloud, tmp_path, monkeypatch):
    rule, _, _, _ = cloud
    monkeypatch.setattr(_ProbeManifest, "before_create", Mock(side_effect=OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        rule.subnet(SUBNET).probe_tcp(
            "database.example", cleanup_manifest=tmp_path / "run.json", **OPTIONS
        )


def test_journal_confirmation_failure_still_cleans_up_confirmed_function(
    cloud, tmp_path, monkeypatch
):
    rule, functions, _, _ = cloud
    functions.add_response(
        "create_function",
        {"FunctionName": NAME, "FunctionArn": FUNCTION_ARN, "RevisionId": "original-revision"},
    )
    delete(functions)
    monkeypatch.setattr(
        _ProbeManifest, "confirm", Mock(side_effect=OSError("confirmation write failed"))
    )
    with pytest.raises(OSError, match="confirmation write failed") as caught:
        rule.subnet(SUBNET).probe_tcp(
            "database.example", cleanup_manifest=tmp_path / "run.json", **OPTIONS
        )
    assert caught.value.evidence["cleanup"] == "deleted"


def test_dry_run_revalidates_resources_without_deleting_or_rewriting(cloud, tmp_path):
    rule, functions, ec2, iam = cloud
    path = run(
        tmp_path / "run.json", resources=("function", "security_group", "role"), role=ROLE_ARN
    )
    original = path.read_bytes()
    function(functions, role=ROLE_ARN)
    group(ec2)
    role(iam)
    dependencies(
        iam,
        ec2,
        functions,
        consumers=[{"FunctionName": NAME, "FunctionArn": FUNCTION_ARN, "Role": ROLE_ARN}],
    )
    report = recover_probes(rule, path)
    assert report["dry_run"] is True
    assert {item["action"] for item in report["resources"].values()} == {"would_delete"}
    assert path.read_bytes() == original


def test_recovery_deletes_function_then_group_then_role_and_is_idempotent(
    cloud, tmp_path, monkeypatch
):
    rule, functions, ec2, iam = cloud
    path = run(
        tmp_path / "run.json", resources=("function", "security_group", "role"), role=ROLE_ARN
    )
    order = []
    for stub, operation, label in (
        (functions, "delete_function", "function"),
        (ec2, "delete_security_group", "group"),
        (iam, "delete_role_policy", "policy"),
        (iam, "delete_role", "role"),
    ):
        original = getattr(stub.client, operation)

        def observe(*args, _original=original, _label=label, **kwargs):
            order.append(_label)
            return _original(*args, **kwargs)

        monkeypatch.setattr(stub.client, operation, observe)
    function(functions, role=ROLE_ARN)
    delete(functions)
    group(ec2)
    ec2.add_response(
        "delete_security_group", {"Return": True, "GroupId": GROUP}, {"GroupId": GROUP}
    )
    role(iam)
    dependencies(iam, ec2, functions)
    iam.add_response("delete_role_policy", {}, {"RoleName": NAME, "PolicyName": POLICY_NAME})
    iam.add_response("delete_role", {}, {"RoleName": NAME})
    report = recover_probes(rule, path, allow_write=True)
    assert report["complete"]
    assert order == ["function", "group", "policy", "role"]
    assert json.loads(path.read_text())["complete"] is True
    assert recover_probes(rule, path, allow_write=True)["complete"]


@pytest.mark.parametrize(
    "changes",
    [
        {"RevisionId": "new-owner-revision"},
        {"FunctionArn": FUNCTION_ARN + ":1"},
        {"Role": ROLE + "Changed"},
        {"VpcConfig": {"SubnetIds": [SUBNET], "SecurityGroupIds": ["sg-other"]}},
    ],
)
def test_changed_function_identity_never_authorizes_deletion(cloud, tmp_path, changes):
    rule, functions, _, _ = cloud
    path = run(tmp_path / "run.json")
    function(functions, **changes)
    with pytest.warns(CleanupWarning), pytest.raises(ProbeError, match="differs"):
        recover_probes(rule, path, allow_write=True)


@pytest.mark.parametrize(
    "changes",
    [
        {"OwnerId": "222222222222"},
        {"VpcId": "vpc-other"},
        {"GroupName": "existing-group"},
        {"Tags": []},
    ],
)
def test_group_owner_name_vpc_and_run_tag_must_match(cloud, tmp_path, changes):
    rule, _, ec2, _ = cloud
    path = run(tmp_path / "run.json", resources=("security_group",))
    group(ec2, **changes)
    with pytest.warns(CleanupWarning), pytest.raises(ProbeError, match="ownership or run tag"):
        recover_probes(rule, path, allow_write=True)


def test_same_role_name_with_different_native_role_id_is_not_adopted(cloud, tmp_path):
    rule, _, _, iam = cloud
    path = run(tmp_path / "run.json", resources=("role",))
    role(iam, RoleId="AROA9876543210ZYXWVUTS")
    with pytest.warns(CleanupWarning), pytest.raises(ProbeError, match="identity differs"):
        recover_probes(rule, path, allow_write=True)


@pytest.mark.parametrize("consumer", [False, True])
def test_role_policy_drift_or_another_consumer_retains_role(cloud, tmp_path, consumer):
    rule, functions, ec2, iam = cloud
    path = run(tmp_path / "run.json", resources=("role",))
    role(iam)
    dependencies(
        iam,
        ec2,
        functions,
        policies=(POLICY_NAME,) if consumer else ("BusinessPolicy",),
        consumers=[{"FunctionName": "business-function", "Role": ROLE_ARN}],
    )
    with pytest.warns(CleanupWarning, match="retained"):
        report = recover_probes(rule, path, allow_write=True)
    assert report["resources"]["role"]["action"] == "retained"
    assert not report["complete"]


def test_unconfirmed_creation_skips_name_adoption_and_dependent_cleanup(tmp_path, monkeypatch):
    path = run(
        tmp_path / "run.json", resources=("function", "security_group", "role"), confirmed=False
    )
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("No native identity reads for an unconfirmed ID"))
    monkeypatch.setattr(rule, "_live_client", client)
    with pytest.warns(CleanupWarning):
        report = recover_probes(rule, path, allow_write=True)
    assert {item["action"] for item in report["resources"].values()} == {"skipped"}
    client.assert_not_called()


@pytest.mark.parametrize("option", ["account", "region"])
def test_manifest_scope_mismatch_fails_before_client_creation(tmp_path, monkeypatch, option):
    path = run(tmp_path / "run.json")
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    rule = rule.in_account("222222222222") if option == "account" else rule.in_region("us-east-1")
    client = Mock(side_effect=AssertionError("No AWS"))
    monkeypatch.setattr(rule, "_live_client", client)
    with pytest.raises(ValueError, match="account/region"):
        recover_probes(rule, path, allow_write=True)
    client.assert_not_called()


def test_active_deployment_lock_prevents_recovery(tmp_path):
    path = tmp_path / "run.json"
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with _ProbeManifest.new(
        path,
        name=NAME,
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        subnet_id=SUBNET,
        groups=[GROUP],
    ):
        with pytest.raises(OSError):
            recover_probes(rule, path, allow_write=True)


def test_automatic_resources_are_journaled_before_each_create(cloud, tmp_path, monkeypatch):
    rule, functions, ec2, iam = cloud
    path = tmp_path / "run.json"
    for stub, method, resource in (
        (ec2, "create_security_group", "security_group"),
        (iam, "create_role", "role"),
        (functions, "create_function", "function"),
    ):
        original = getattr(stub.client, method)

        def create(*args, _original=original, _resource=resource, **kwargs):
            record = json.loads(path.read_text())["resources"][_resource]
            assert record["cleanup"] == "creating"
            assert record["confirmed"] is False
            return _original(*args, **kwargs)

        monkeypatch.setattr(stub.client, method, create)
    subnet(ec2)
    group_create(ec2)
    visible(ec2)
    role_create(iam)
    put(iam)
    functions.add_response(
        "create_function",
        {"FunctionName": NAME, "FunctionArn": FUNCTION_ARN, "RevisionId": "original-revision"},
    )
    state(functions)
    invoke(functions)
    delete(functions)
    group_delete(ec2)
    role_delete(iam)
    assert rule.subnet(SUBNET).probe_tcp(
        "database.example",
        allow_write=True,
        auto_create_execution_role=True,
        auto_create_security_group=True,
        cleanup_manifest=path,
    )
    data = json.loads(path.read_text())
    assert data["resources"]["role"]["identity"]["role_id"] == ROLE_ID
    assert data["resources"]["security_group"]["identity"]["group_id"] == GROUP
    assert data["complete"]


def test_cleanup_persistence_error_does_not_replace_original_error(cloud, tmp_path, monkeypatch):
    rule, functions, _, _ = cloud
    functions.add_response(
        "create_function",
        {"FunctionName": NAME, "FunctionArn": FUNCTION_ARN, "RevisionId": "original-revision"},
    )
    state(functions)
    original = RuntimeError("original observation error")
    monkeypatch.setattr(functions.client, "invoke", Mock(side_effect=original))
    monkeypatch.setattr(_ProbeManifest, "status", Mock(side_effect=OSError("status disk full")))
    delete(functions)
    with (
        pytest.warns(CleanupWarning, match="status disk full"),
        pytest.raises(RuntimeError) as caught,
    ):
        rule.subnet(SUBNET).probe_tcp(
            "database.example", cleanup_manifest=tmp_path / "run.json", **OPTIONS
        )
    assert caught.value is original
    assert original.evidence["cleanup"] == "deleted"
    assert original.evidence["manifest_errors"] == ["status disk full"]


def test_contradictory_creation_arn_is_unconfirmed_and_not_deleted(cloud, tmp_path):
    rule, functions, _, _ = cloud
    path = tmp_path / "run.json"
    functions.add_response(
        "create_function",
        {
            "FunctionName": NAME,
            "FunctionArn": FUNCTION_ARN.replace(ACCOUNT, "222222222222"),
            "RevisionId": "original-revision",
        },
    )
    with (
        pytest.warns(CleanupWarning),
        pytest.raises(ProbeError, match="contradictory function ARN"),
    ):
        rule.subnet(SUBNET).probe_tcp("database.example", cleanup_manifest=path, **OPTIONS)
    data = json.loads(path.read_text())
    assert data["resources"]["function"]["confirmed"] is False
    assert data["resources"]["function"]["cleanup"] == "creation_unconfirmed"


def test_published_version_on_later_page_keeps_its_role(cloud, tmp_path):
    rule, functions, ec2, iam = cloud
    path = run(tmp_path / "run.json", resources=("role",))
    role(iam)
    dependencies(
        iam,
        ec2,
        functions,
        consumers=[{"FunctionName": "business", "Role": ROLE}],
        next_marker="next-page",
    )
    functions.add_response(
        "list_functions",
        {
            "Functions": [
                {
                    "FunctionName": "business",
                    "FunctionArn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:business:3",
                    "Version": "3",
                    "Role": ROLE_ARN,
                }
            ]
        },
        {"FunctionVersion": "ALL", "Marker": "next-page"},
    )
    with pytest.warns(CleanupWarning):
        report = recover_probes(rule, path, allow_write=True)
    assert report["resources"]["role"]["action"] == "retained"
    assert "Another Lambda" in report["resources"]["role"]["reason"]


def test_denied_regional_consumer_scan_retains_role(cloud, tmp_path):
    rule, functions, ec2, iam = cloud
    path = run(tmp_path / "run.json", resources=("role",))
    role(iam)
    dependencies(iam, ec2, functions, list_error="AccessDeniedException")
    with pytest.warns(CleanupWarning):
        report = recover_probes(rule, path, allow_write=True)
    assert report["resources"]["role"]["action"] == "retained"
    assert "AccessDeniedException" in report["resources"]["role"]["reason"]


def test_recovery_waits_for_original_lambda_enis_without_deleting_them(
    cloud, tmp_path, monkeypatch
):
    rule, functions, ec2, iam = cloud
    path = run(tmp_path / "run.json", resources=("function", "role"), role=ROLE_ARN)
    functions.add_client_error(
        "get_function_configuration",
        "ResourceNotFoundException",
        expected_params={"FunctionName": NAME},
    )
    role(iam)
    dependencies(iam, ec2, functions)
    filters = [
        {"Name": "subnet-id", "Values": [SUBNET]},
        {"Name": "group-id", "Values": [GROUP]},
        {"Name": "interface-type", "Values": ["lambda"]},
    ]
    ec2.add_response(
        "describe_network_interfaces",
        {
            "NetworkInterfaces": [
                {
                    "NetworkInterfaceId": "eni-leftover",
                    "OwnerId": ACCOUNT,
                    "SubnetId": SUBNET,
                    "InterfaceType": "lambda",
                    "Groups": [{"GroupId": GROUP}],
                }
            ]
        },
        {"Filters": filters},
    )
    ec2.add_response("describe_network_interfaces", {"NetworkInterfaces": []}, {"Filters": filters})
    role_delete(iam)
    sleep = Mock()
    monkeypatch.setattr(probe.time, "sleep", sleep)
    assert recover_probes(rule, path, allow_write=True)["complete"]
    sleep.assert_called_once()


def test_unconfirmed_function_retains_confirmed_dependencies_without_reads(tmp_path, monkeypatch):
    path = run(
        tmp_path / "run.json", resources=("function", "security_group", "role"), role=ROLE_ARN
    )
    data = json.loads(path.read_text())
    data["resources"]["function"].update(confirmed=False, cleanup="creating")
    path.write_text(json.dumps(data))
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    monkeypatch.setattr(rule, "_live_client", Mock(side_effect=AssertionError("No AWS")))
    with pytest.warns(CleanupWarning):
        report = recover_probes(rule, path, allow_write=True)
    assert report["resources"]["function"]["action"] == "skipped"
    assert report["resources"]["security_group"]["action"] == "retained"
    assert report["resources"]["role"]["action"] == "retained"


def test_all_recorded_identities_are_preflighted_before_any_delete(tmp_path, monkeypatch):
    path = run(tmp_path / "run.json", resources=("function", "security_group"))
    data = json.loads(path.read_text())
    data["resources"]["security_group"]["identity"]["group_name"] = "existing-group"
    path.write_text(json.dumps(data))
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    monkeypatch.setattr(rule, "_live_client", Mock(side_effect=AssertionError("No AWS")))
    with pytest.raises(ValueError, match="Recorded security group"):
        recover_probes(rule, path, allow_write=True)


def test_consumer_in_another_enabled_region_retains_role(cloud, tmp_path):
    rule, functions, ec2, iam = cloud
    path = run(tmp_path / "run.json", resources=("role",))
    other_region = "us-east-1"
    role(iam)
    dependencies(iam, ec2, functions, regions=(REGION, other_region))
    with (
        Stubber(rule.clients.client("sts", other_region)) as sts,
        Stubber(rule.clients.client("lambda", other_region)) as other,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        other.add_response(
            "list_functions",
            {"Functions": [{"FunctionName": "other-region-consumer", "Role": ROLE_ARN}]},
            {"FunctionVersion": "ALL"},
        )
        with pytest.warns(CleanupWarning):
            report = recover_probes(rule, path, allow_write=True)
        assert report["resources"]["role"]["dependency_evidence"]["consumer_region"] == other_region
        sts.assert_no_pending_responses()
        other.assert_no_pending_responses()


def test_hard_process_exit_preserves_record_and_releases_lock(cloud, tmp_path):
    rule, functions, _, _ = cloud
    path = tmp_path / "run.json"
    header = dict(
        name=NAME,
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        subnet_id=SUBNET,
        groups=[GROUP],
    )
    identity = dict(
        function_name=NAME,
        function_arn=FUNCTION_ARN,
        revision_id="original-revision",
        subnet_id=SUBNET,
        security_group_ids=[GROUP],
        execution_role_arn=ROLE,
    )
    code = (
        "import os\nfrom aws_network_asserts._recovery import _ProbeManifest\n"
        f"with _ProbeManifest.new({str(path)!r}, **{header!r}) as manifest:\n"
        f" manifest.before_create('function', {identity!r})\n"
        f" manifest.confirm('function', {identity!r})\n"
        " os._exit(9)\n"
    )
    process = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=10)
    assert process.returncode == 9, process.stderr.decode()
    function(functions)
    delete(functions)
    assert recover_probes(rule, path, allow_write=True)["complete"]


def test_failed_function_delete_retains_dependencies_and_original_aws_error(cloud, tmp_path):
    rule, functions, _, _ = cloud
    path = run(
        tmp_path / "run.json", resources=("function", "security_group", "role"), role=ROLE_ARN
    )
    function(functions, role=ROLE_ARN)
    functions.add_client_error(
        "delete_function", "AccessDeniedException", expected_params={"FunctionName": NAME}
    )
    with (
        pytest.warns(CleanupWarning),
        pytest.raises(ClientError, match="AccessDeniedException") as caught,
    ):
        recover_probes(rule, path, allow_write=True)
    report = caught.value.evidence
    assert {item["action"] for item in report["resources"].values()} == {"retained"}
    assert json.loads(path.read_text())["resources"]["function"]["cleanup"] == "retained"


def test_failed_cleanup_status_write_keeps_known_deleted_state(cloud, tmp_path, monkeypatch):
    rule, functions, _, _ = cloud
    path = run(tmp_path / "run.json")
    function(functions)
    delete(functions)
    original = OSError("cleanup status write failed")
    monkeypatch.setattr(_ProbeManifest, "write", Mock(side_effect=original))
    with pytest.warns(CleanupWarning), pytest.raises(OSError) as caught:
        recover_probes(rule, path, allow_write=True)
    assert caught.value is original
    assert original.evidence["resources"]["function"]["action"] == "deleted"
    assert original.evidence["manifest_error"] == "cleanup status write failed"


@pytest.mark.parametrize("allow_write", [1, "true", None])
def test_recovery_write_permission_requires_a_boolean(tmp_path, allow_write):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with pytest.raises(ValueError, match="boolean"):
        recover_probes(rule, tmp_path / "run.json", allow_write=allow_write)
