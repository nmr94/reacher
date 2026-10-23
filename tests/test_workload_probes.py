"""Derive Lambda source geometry from verified, current workload interfaces."""

import json
from unittest.mock import Mock
from uuid import UUID

import pytest
from botocore.exceptions import ClientError
from botocore.stub import ANY, Stubber
from test_probe import ACCOUNT, GROUP, NAME, REGION, ROLE, SUBNET, create, delete, session, state
from test_probe_session import dns, packet

from aws_network_asserts import NetworkAssertionError, ProbeError, RuleBuilder, WriteNotAllowedError
from aws_network_asserts import probe as deployment
from aws_network_asserts.probe_session import ProbeSession

ENI = "eni-0123456789abcdef0"
OTHER_ENI = "eni-0123456789abcdef1"
INSTANCE = "i-0123456789abcdef0"
VPC = "vpc-0123456789abcdef0"
ZONE = "eu-west-2a"
OPTIONS = {"allow_write": True, "execution_role_arn": ROLE}


def interface():
    return {
        "NetworkInterfaceId": ENI,
        "OwnerId": ACCOUNT,
        "Status": "in-use",
        "SubnetId": SUBNET,
        "VpcId": VPC,
        "AvailabilityZone": ZONE,
        "PrivateIpAddress": "10.0.1.10",
        "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.1.10", "Primary": True}],
        "Groups": [{"GroupId": GROUP, "GroupName": "application"}],
        "Attachment": {"InstanceId": INSTANCE, "Status": "attached"},
    }


def reservation(*, interfaces=(ENI,), owner=ACCOUNT, state_name="running"):
    return {
        "OwnerId": owner,
        "Instances": [
            {
                "InstanceId": INSTANCE,
                "State": {"Name": state_name},
                "NetworkInterfaces": [{"NetworkInterfaceId": value} for value in interfaces],
            }
        ],
    }


@pytest.fixture
def cloud(monkeypatch):
    monkeypatch.setattr(deployment, "uuid4", lambda: UUID(int=0))
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with (
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("ec2", REGION)) as ec2,
        Stubber(rule.clients.client("lambda", REGION)) as functions,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        yield rule, ec2, functions
        for stub in (sts, ec2, functions):
            stub.assert_no_pending_responses()


def describe_interface(ec2, item=None, *, interface_id=ENI):
    ec2.add_response(
        "describe_network_interfaces",
        {"NetworkInterfaces": [item if item is not None else interface()]},
        {"NetworkInterfaceIds": [interface_id]},
    )


def describe_instance(ec2, item=None):
    ec2.add_response(
        "describe_instances",
        {"Reservations": [item if item is not None else reservation()]},
        {"InstanceIds": [INSTANCE]},
    )


def describe_subnet(ec2, **changes):
    ec2.add_response(
        "describe_subnets",
        {
            "Subnets": [
                {
                    "SubnetId": SUBNET,
                    "OwnerId": ACCOUNT,
                    "State": "available",
                    "VpcId": VPC,
                    "AvailabilityZone": ZONE,
                    **changes,
                }
            ]
        },
        {"SubnetIds": [SUBNET]},
    )


def dual_interface():
    return {**interface(), "Ipv6Addresses": [{"Ipv6Address": "2001:db8:1::10"}]}


def describe_dual_subnet(ec2):
    describe_subnet(
        ec2,
        CidrBlock="10.0.1.0/24",
        Ipv6CidrBlockAssociationSet=[
            {
                "Ipv6CidrBlock": "2001:db8:1::/64",
                "Ipv6CidrBlockState": {"State": "associated"},
            }
        ],
    )


def create_dual(functions):
    functions.add_response(
        "create_function",
        {"FunctionName": NAME, "State": "Pending"},
        {
            "FunctionName": NAME,
            "Runtime": "python3.12",
            "Role": ROLE,
            "Handler": "probe_handler.handler",
            "Code": {"ZipFile": ANY},
            "Timeout": 15,
            "MemorySize": 128,
            "Publish": False,
            "VpcConfig": {
                "SubnetIds": [SUBNET],
                "SecurityGroupIds": [GROUP],
                "Ipv6AllowedForDualStack": True,
            },
        },
    )


@pytest.mark.parametrize("kind", ["eni", "instance"])
def test_derived_probe_verifies_the_workload_and_uses_its_groups(cloud, kind):
    rule, ec2, functions = cloud
    if kind == "instance":
        describe_instance(ec2)
    describe_interface(ec2)
    describe_subnet(ec2)
    if kind == "instance":
        describe_instance(ec2)
    describe_interface(ec2)
    create(functions)
    state(functions)
    dns(functions)
    packet(functions, ProbeSession._prepare("tcp", "service.example"))
    delete(functions)
    selected = getattr(rule, kind)(ENI if kind == "eni" else INSTANCE).named("application")
    with selected.probe_session(**OPTIONS) as source:
        result = source.tcp("service.example")
    assert result, result.message
    evidence = result.evidence
    workload = evidence["source_workload"]
    assert workload["network_interface_id"] == ENI
    assert workload["resource_id"] == selected.resource_id
    assert workload["security_group_ids"] == [GROUP]
    assert workload["account_id"] == ACCOUNT
    assert workload["availability_zone"] == ZONE
    assert workload["host_firewall_tested"] is False
    assert workload["address_family"] == "ipv4"
    assert workload["addresses_by_family"] == {"ipv4": ["10.0.1.10"], "ipv6": []}
    assert evidence["source_context"]["kind"] == "workload_representative"
    assert evidence["source_context"]["subnet_id"] == SUBNET
    assert evidence["deployment"]["cleanup"] == "deleted"
    assert "application" in result.message
    with pytest.raises(RuntimeError, match="more than once"):
        source.__enter__()


@pytest.mark.parametrize("kind", ["eni", "instance"])
@pytest.mark.parametrize("permission", [False, 1, "true", None])
def test_derived_probe_write_gate_precedes_every_client_or_read(kind, permission, monkeypatch):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("No AWS clients"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(WriteNotAllowedError):
        getattr(rule, kind)(ENI if kind == "eni" else INSTANCE).probe_session(
            allow_write=permission, execution_role_arn=ROLE
        )
    client.assert_not_called()


@pytest.mark.parametrize(
    "options",
    [
        {"security_group_ids": [GROUP]},
        {"security_group_ids": None},
        {"auto_create_security_group": True},
        {"source_kind": "synthetic"},
        {"network_interface_id": "bad-id"},
        {"address_family": "unknown"},
    ],
)
def test_derived_probe_option_conflicts_fail_without_discovery(options, monkeypatch):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("No AWS clients"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(ValueError):
        rule.instance(INSTANCE).probe_session(**OPTIONS, **options)
    client.assert_not_called()


def test_derived_probe_needs_a_selected_account_and_typed_workload():
    rule = RuleBuilder(session=session(), config_mode="off")
    with pytest.raises(ValueError, match="account"):
        rule.eni(ENI).probe_session(**OPTIONS)
    with pytest.raises(NetworkAssertionError, match=r"eni\(\) or instance\(\)"):
        rule.in_account(ACCOUNT).resource(ENI).probe_session(**OPTIONS)


@pytest.mark.parametrize(
    "change",
    [
        {"OwnerId": "222222222222"},
        {"OwnerId": "invalid"},
        {"NetworkInterfaceId": OTHER_ENI},
        {"Status": "available"},
        {"SubnetId": ""},
        {"VpcId": ""},
        {"AvailabilityZone": ""},
        {"Groups": []},
        {"Groups": [{"GroupId": GROUP}, {"GroupId": GROUP}]},
        {"Groups": [{"GroupId": "not-a-group"}]},
    ],
)
def test_incomplete_or_contradictory_eni_never_deploys_a_probe(cloud, change):
    rule, ec2, _ = cloud
    describe_interface(ec2, {**interface(), **change})
    with pytest.raises((NetworkAssertionError, ValueError)):
        with rule.eni(ENI).probe_session(**OPTIONS):
            pytest.fail("Invalid source must not enter")


@pytest.mark.parametrize("field", ["OwnerId", "Groups", "Status", "AvailabilityZone"])
def test_missing_source_metadata_never_deploys(cloud, field):
    rule, ec2, _ = cloud
    item = interface()
    del item[field]
    describe_interface(ec2, item)
    with pytest.raises(NetworkAssertionError):
        with rule.eni(ENI).probe_session(**OPTIONS):
            pytest.fail("Incomplete source must not enter")


@pytest.mark.parametrize(
    "item, message",
    [
        (reservation(owner="222222222222"), "OwnerId"),
        (reservation(state_name="stopped"), "running"),
        (reservation(interfaces=(ENI, OTHER_ENI)), "network_interface_id"),
    ],
)
def test_instance_discovery_rejects_wrong_owner_inactive_or_ambiguous_sources(cloud, item, message):
    rule, ec2, _ = cloud
    describe_instance(ec2, item)
    with pytest.raises((NetworkAssertionError, ValueError), match=message):
        with rule.instance(INSTANCE).probe_session(**OPTIONS):
            pytest.fail("Invalid instance must not enter")


def test_multi_eni_instance_can_select_a_specific_attached_interface(cloud):
    rule, ec2, functions = cloud
    describe_instance(ec2, reservation(interfaces=(OTHER_ENI, ENI)))
    describe_interface(ec2)
    # Shared subnet ownership may differ from the workload and Lambda account.
    describe_subnet(ec2, OwnerId="222222222222")
    create(functions)
    state(functions)
    delete(functions)
    with rule.instance(INSTANCE).probe_session(network_interface_id=ENI, **OPTIONS) as source:
        assert source.source_context["subnet_owner_id"] == "222222222222"


def test_selected_eni_must_belong_to_the_instance(cloud):
    rule, ec2, _ = cloud
    describe_instance(ec2)
    with pytest.raises(ProbeError, match="not part"):
        with rule.instance(INSTANCE).probe_session(network_interface_id=OTHER_ENI, **OPTIONS):
            pytest.fail("Foreign interface must not enter")


def test_instance_interface_attachment_is_rechecked_live(cloud):
    rule, ec2, _ = cloud
    describe_instance(ec2)
    item = interface()
    item["Attachment"]["InstanceId"] = "i-other"
    describe_interface(ec2, item)
    with pytest.raises(ProbeError, match="not attached"):
        with rule.instance(INSTANCE).probe_session(**OPTIONS):
            pytest.fail("Detached interface must not enter")


@pytest.mark.parametrize("change", [{"VpcId": "vpc-other"}, {"AvailabilityZone": "eu-west-2b"}])
def test_live_subnet_must_agree_with_the_workload_geometry_before_deployment(cloud, change):
    rule, ec2, _ = cloud
    describe_interface(ec2)
    describe_subnet(ec2, **change)
    with pytest.raises(ProbeError, match="Workload"):
        with rule.eni(ENI).probe_session(**OPTIONS):
            pytest.fail("Contradictory subnet must not enter")


def test_workload_discovery_keeps_native_permission_errors(cloud):
    rule, ec2, _ = cloud
    ec2.add_client_error(
        "describe_network_interfaces",
        service_error_code="UnauthorizedOperation",
        expected_params={"NetworkInterfaceIds": [ENI]},
    )
    with pytest.raises(ClientError) as caught:
        with rule.eni(ENI).probe_session(**OPTIONS):
            pytest.fail("Inaccessible source must not enter")
    assert caught.value.evidence["source_workload"]["resource_id"] == ENI


def test_resource_names_clone_scope_without_mutating_the_original():
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    original = rule.eni(ENI)
    labeled = original.named("  application  ")
    assert original.label is None
    assert labeled.label == "application"
    assert labeled.builder is original.builder
    assert labeled.resource_id == original.resource_id
    assert labeled.region == original.region
    assert labeled.account_id == original.account_id
    with pytest.raises(TypeError):
        bool(labeled)


@pytest.mark.parametrize("label", ["", " ", "line\nbreak", "control\x00", None])
def test_bad_resource_names_are_rejected(label):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with pytest.raises(ValueError):
        rule.eni(ENI).named(label)


@pytest.mark.parametrize("kind", ["eni", "instance"])
@pytest.mark.parametrize(
    "change",
    [
        {"OwnerId": "222222222222"},
        {"Status": "available"},
        {"SubnetId": "subnet-other"},
        {"VpcId": "vpc-other"},
        {"AvailabilityZone": "eu-west-2b"},
        {"Groups": [{"GroupId": "sg-other"}]},
    ],
)
def test_workload_drift_stops_a_fresh_check_and_still_deletes_the_function(cloud, kind, change):
    rule, ec2, functions = cloud
    if kind == "instance":
        describe_instance(ec2)
    describe_interface(ec2)
    describe_subnet(ec2)
    if kind == "instance":
        describe_instance(ec2)
    describe_interface(ec2, {**interface(), **change})
    create(functions)
    state(functions)
    delete(functions)
    selected = getattr(rule, kind)(ENI if kind == "eni" else INSTANCE)
    with pytest.raises(NetworkAssertionError) as caught:
        with selected.probe_session(**OPTIONS) as source:
            source.tcp("service.example")
    assert caught.value.evidence["cleanup"] == "deleted"
    assert caught.value.evidence["source_workload"]["network_interface_id"] == ENI


def test_stopped_instance_after_deployment_cannot_keep_a_representative_label(cloud):
    rule, ec2, functions = cloud
    describe_instance(ec2)
    describe_interface(ec2)
    describe_subnet(ec2)
    describe_instance(ec2, reservation(state_name="stopped"))
    create(functions)
    state(functions)
    delete(functions)
    with pytest.raises(ProbeError, match="running") as caught:
        with rule.instance(INSTANCE).probe_session(**OPTIONS) as source:
            source.tcp("service.example")
    assert caught.value.evidence["cleanup"] == "deleted"
    assert caught.value.evidence["source_workload"]["network_interface_id"] == ENI


def test_instance_attachment_is_freshly_checked_before_every_observation(cloud):
    rule, ec2, functions = cloud
    describe_instance(ec2)
    describe_interface(ec2)
    describe_subnet(ec2)
    describe_instance(ec2)
    changed = interface()
    changed["Attachment"]["Status"] = "detaching"
    describe_interface(ec2, changed)
    create(functions)
    state(functions)
    delete(functions)
    with pytest.raises(ProbeError, match="not attached") as caught:
        with rule.instance(INSTANCE).probe_session(**OPTIONS) as source:
            source.tcp("service.example")
    assert caught.value.evidence["cleanup"] == "deleted"
    assert caught.value.evidence["source_workload"]["network_interface_id"] == ENI


@pytest.mark.parametrize("address_family", ["ipv6", "dual"])
def test_ipv4_only_workload_cannot_gain_ipv6_from_a_dual_subnet(cloud, address_family):
    rule, ec2, _ = cloud
    describe_interface(ec2)
    with pytest.raises(ProbeError, match="assigned addresses"):
        with rule.eni(ENI).probe_session(address_family=address_family, **OPTIONS):
            pytest.fail("A dual-stack subnet cannot supply the workload's missing family")


@pytest.mark.parametrize("address_family", ["ipv6", "dual"])
def test_workload_with_ipv6_can_use_an_explicit_dual_stack_lambda(cloud, address_family):
    rule, ec2, functions = cloud
    describe_interface(ec2, dual_interface())
    describe_dual_subnet(ec2)
    create_dual(functions)
    state(functions)
    delete(functions)
    with rule.eni(ENI).probe_session(address_family=address_family, **OPTIONS) as source:
        workload = source.source_context["source_workload"]
        assert workload["address_family"] == address_family
        assert workload["addresses_by_family"] == {
            "ipv4": ["10.0.1.10"],
            "ipv6": ["2001:db8:1::10"],
        }


@pytest.mark.parametrize("kind", ["dns", "tcp", "tls", "http"])
def test_losing_the_requested_workload_family_stops_each_observation_and_cleans_up(cloud, kind):
    rule, ec2, functions = cloud
    describe_interface(ec2, dual_interface())
    describe_dual_subnet(ec2)
    describe_interface(ec2)
    create_dual(functions)
    state(functions)
    delete(functions)
    target = "https://service.example/" if kind == "http" else "service.example"
    options = {"allowed_cidrs": ["2001:db8::/32"]} if kind == "dns" else {}
    with pytest.raises(ProbeError, match="assigned addresses") as caught:
        with rule.eni(ENI).probe_session(address_family="dual", **OPTIONS) as source:
            getattr(source, kind)(target, address_family="ipv6", **options)
    assert caught.value.evidence["cleanup"] == "deleted"
    failed = caught.value.evidence["failed_source_check"]
    assert failed["addresses_by_family"]["ipv6"] == []


def test_explicit_ipv4_check_uses_current_assignments_without_claiming_original_ip_identity(cloud):
    rule, ec2, functions = cloud
    describe_interface(ec2, dual_interface())
    describe_dual_subnet(ec2)
    current = interface()
    current["PrivateIpAddress"] = "10.0.1.11"
    current["PrivateIpAddresses"] = [{"PrivateIpAddress": "10.0.1.11", "Primary": True}]
    describe_interface(ec2, current)
    create_dual(functions)
    state(functions)
    dns(functions)
    packet(functions, ProbeSession._prepare("tcp", "service.example"))
    delete(functions)
    with rule.eni(ENI).probe_session(address_family="dual", **OPTIONS) as source:
        result = source.tcp("service.example", address_family="ipv4")
    assert result, result.message
    assert result.evidence["address_family"] == "ipv4"
    assert result.evidence["source_workload"]["addresses_by_family"] == {
        "ipv4": ["10.0.1.11"],
        "ipv6": [],
    }
    assert result.evidence["deployment"]["cleanup"] == "deleted"


@pytest.mark.parametrize(
    "change",
    [
        {"PrivateIpAddress": None},
        {"PrivateIpAddress": "2001:db8::1"},
        {"PrivateIpAddress": "0.0.0.0"},
        {"PrivateIpAddress": "127.0.0.1"},
        {"PrivateIpAddress": "169.254.1.1"},
        {"PrivateIpAddress": "224.0.0.1"},
        {"PrivateIpAddresses": None},
        {"PrivateIpAddresses": {}},
        {"PrivateIpAddresses": ["10.0.1.10"]},
        {"PrivateIpAddresses": [{}]},
        {"PrivateIpAddresses": []},
        {"PrivateIpAddresses": [{"PrivateIpAddress": "10.0.1.11"}]},
        {"PrivateIpAddresses": [{"PrivateIpAddress": "10.0.1.10"}] * 2},
        {"Ipv6Addresses": None},
        {"Ipv6Addresses": "2001:db8:1::10"},
        {"Ipv6Addresses": [{}]},
        {"Ipv6Addresses": [{"Ipv6Address": "10.0.1.10"}]},
        {"Ipv6Addresses": [{"Ipv6Address": "::ffff:10.0.1.10"}]},
        {"Ipv6Addresses": [{"Ipv6Address": "fe80::1%eth0"}]},
        {"Ipv6Addresses": [{"Ipv6Address": "::"}]},
        {"Ipv6Addresses": [{"Ipv6Address": "::1"}]},
        {"Ipv6Addresses": [{"Ipv6Address": "fe80::1"}]},
        {"Ipv6Addresses": [{"Ipv6Address": "ff02::1"}]},
        {"Ipv6Addresses": [{"Ipv6Address": "2001:db8::1"}, {"Ipv6Address": "2001:db8::01"}]},
    ],
)
def test_malformed_workload_addresses_are_errors_before_lambda_creation(cloud, monkeypatch, change):
    rule, _, _ = cloud
    # These shapes cannot pass botocore response validation. A local mock lets
    # us test fail-closed handling of malformed custom-endpoint responses too.
    client = rule.ec2
    monkeypatch.setattr(
        client,
        "describe_network_interfaces",
        Mock(return_value={"NetworkInterfaces": [{**interface(), **change}]}),
    )
    with pytest.raises(ProbeError, match="address|collection"):
        with rule.eni(ENI).probe_session(**OPTIONS):
            pytest.fail("Malformed address evidence must not create a Lambda")


@pytest.mark.parametrize("after_deployment", [False, True])
def test_contradictory_attachment_owner_cannot_represent_the_selected_instance(
    cloud, after_deployment
):
    rule, ec2, functions = cloud
    if after_deployment:
        describe_instance(ec2)
        describe_interface(ec2)
        describe_subnet(ec2)
        create(functions)
        state(functions)
        delete(functions)
    describe_instance(ec2)
    changed = interface()
    changed["Attachment"]["InstanceOwnerId"] = "222222222222"
    describe_interface(ec2, changed)
    with pytest.raises(ProbeError, match="not attached") as caught:
        with rule.instance(INSTANCE).probe_session(**OPTIONS) as source:
            source.tcp("service.example")
    if after_deployment:
        assert caught.value.evidence["cleanup"] == "deleted"


def test_malformed_source_after_deployment_keeps_serializable_cleanup_diagnostics(cloud):
    rule, ec2, functions = cloud
    describe_interface(ec2)
    describe_subnet(ec2)
    describe_interface(ec2, {**interface(), "Groups": []})
    create(functions)
    state(functions)
    delete(functions)
    with pytest.raises(ProbeError, match="security groups") as caught:
        with rule.eni(ENI).probe_session(**OPTIONS) as source:
            source.tcp("service.example")
    encoded = json.dumps(caught.value.evidence)
    assert json.loads(encoded)["cleanup"] == "deleted"
