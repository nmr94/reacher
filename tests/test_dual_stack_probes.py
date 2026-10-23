"""DNS-bound connections and dual-stack observations use native SDK contracts."""

from unittest.mock import Mock
from uuid import UUID

import pytest
from botocore.stub import ANY, Stubber
from test_probe import ACCOUNT, GROUP, NAME, OPTIONS, REGION, ROLE, SUBNET, delete, session, state
from test_probe_session import dns, packet, response

from aws_network_asserts import ProbeError, RuleBuilder, probe
from aws_network_asserts.probe_session import ProbeSession

IPV4 = "10.1.2.3"
IPV6 = "2001:db8:2::10"
HOST = "service.example"


@pytest.fixture
def cloud(monkeypatch):
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with (
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("ec2", REGION)) as ec2,
        Stubber(rule.clients.client("lambda", REGION)) as functions,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        yield rule.subnet(SUBNET), functions, ec2
        for stub in (sts, ec2, functions):
            stub.assert_no_pending_responses()


def subnet_response(stub, **changes):
    item = {
        "SubnetId": SUBNET,
        "State": "available",
        "OwnerId": ACCOUNT,
        "VpcId": "vpc-1",
        "AvailabilityZone": "eu-west-2a",
        "CidrBlock": "10.0.1.0/24",
        "Ipv6Native": False,
        "Ipv6CidrBlockAssociationSet": [
            {
                "Ipv6CidrBlock": "2001:db8:1::/64",
                "Ipv6CidrBlockState": {"State": "associated"},
            }
        ],
        **changes,
    }
    stub.add_response("describe_subnets", {"Subnets": [item]}, {"SubnetIds": [SUBNET]})


def create(stub, *, ipv6=True):
    vpc = {"SubnetIds": [SUBNET], "SecurityGroupIds": [GROUP]}
    if ipv6:
        vpc["Ipv6AllowedForDualStack"] = True
    stub.add_response(
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
            "VpcConfig": vpc,
        },
    )


def resolve(stub, addresses=(IPV4, IPV6), *, family="dual", host=HOST, **changes):
    return response(
        stub,
        {"kind": "dns", "host": host, "address_family": family},
        {"kind": "dns", "addresses": list(addresses), "dns_ms": 1, **changes},
    )


@pytest.mark.parametrize("kind", ["tcp", "tls", "http"])
def test_destination_constraint_fails_before_sending_any_connection(cloud, kind):
    subnet, functions, ec2 = cloud
    subnet_response(ec2)
    create(functions, ipv6=False)
    state(functions)
    dns(functions, [IPV4, "192.0.2.1"])
    delete(functions)
    target = f"https://{HOST}/health" if kind == "http" else HOST
    with subnet.probe_session(**OPTIONS) as batch:
        result = getattr(batch, kind)(target, allowed_destination_cidrs=["10.0.0.0/8"])
    assert not result
    assert result.evidence["tested_addresses"] == []
    assert result.evidence["attempts"] == []
    assert result.evidence["resolved_addresses"] == [IPV4, "192.0.2.1"]
    assert result.evidence["deployment"]["cleanup"] == "deleted"


def test_one_shot_exact_dns_binding_uses_the_same_resolved_ip(cloud):
    subnet, functions, ec2 = cloud
    subnet_response(ec2)
    create(functions, ipv6=False)
    state(functions)
    dns(functions)
    packet(functions, ProbeSession._prepare("tcp", HOST, expected_addresses=[IPV4]))
    delete(functions)
    result = subnet.probe_tcp(HOST, **OPTIONS, expected_addresses=[IPV4])
    assert result
    assert result.evidence["expected_addresses"] == result.evidence["tested_addresses"] == [IPV4]


@pytest.mark.parametrize("mode", ["all", "any", "first"])
def test_dual_stack_requires_success_for_each_family(cloud, mode):
    subnet, functions, ec2 = cloud
    subnet_response(ec2)
    create(functions)
    state(functions)
    resolve(functions)
    spec = ProbeSession._prepare("tcp", HOST, address_family="dual", address_mode=mode)
    packet(functions, spec)
    packet(functions, spec, IPV6, source_ip="2001:db8:1::10", outcome="refused")
    delete(functions)
    with subnet.probe_session(**OPTIONS, address_family="dual") as batch:
        result = batch.tcp(HOST, address_mode=mode)
    assert not result
    assert result.evidence["family_results"]["ipv4"]["passed"] is True
    assert result.evidence["family_results"]["ipv6"]["passed"] is False
    assert result.evidence["addresses_by_family"] == {"ipv4": [IPV4], "ipv6": [IPV6]}


def test_dual_first_selects_one_address_from_each_family(cloud):
    subnet, functions, ec2 = cloud
    subnet_response(ec2)
    create(functions)
    state(functions)
    resolve(functions, [IPV4, "10.1.2.4", IPV6, "2001:db8:2::11"])
    spec = ProbeSession._prepare("tcp", HOST, address_family="dual", address_mode="first")
    packet(functions, spec)
    packet(functions, spec, IPV6, source_ip="2001:db8:1::10")
    delete(functions)
    with subnet.probe_session(**OPTIONS, address_family="dual") as batch:
        result = batch.tcp(HOST, address_mode="first")
    assert result
    assert result.evidence["tested_addresses"] == [IPV4, IPV6]


def test_dual_does_not_silently_fall_back_when_dns_lacks_ipv6(cloud):
    subnet, functions, ec2 = cloud
    subnet_response(ec2)
    create(functions)
    state(functions)
    resolve(functions, [IPV4])
    delete(functions)
    with pytest.raises(ProbeError, match="every requested address family") as caught:
        subnet.probe_tls(HOST, **OPTIONS, address_family="dual")
    assert caught.value.evidence["cleanup"] == "deleted"


@pytest.mark.parametrize(
    "changes",
    [
        {"Ipv6CidrBlockAssociationSet": []},
        {"Ipv6Native": True},
        {"CidrBlock": "2001:db8::/64"},
        {
            "Ipv6CidrBlockAssociationSet": [
                {
                    "Ipv6CidrBlock": "2001:db8:1::/64",
                    "Ipv6CidrBlockState": {"State": "associating"},
                }
            ]
        },
    ],
)
def test_ipv6_prerequisites_fail_before_function_creation(cloud, changes):
    subnet, _, ec2 = cloud
    subnet_response(ec2, **changes)
    with pytest.raises(ProbeError, match="verified dual-stack subnet"):
        with subnet.probe_session(**OPTIONS, address_family="ipv6"):
            pytest.fail("An unverified source must not deploy")


def test_ipv6_literal_tls_pins_address_and_certificate_name(cloud):
    subnet, functions, ec2 = cloud
    subnet_response(ec2)
    create(functions)
    state(functions)
    resolve(functions, [IPV6], family="ipv6", host=IPV6)
    spec = ProbeSession._prepare(
        "tls",
        IPV6,
        address_family="ipv6",
        server_hostname=HOST,
        expected_addresses=[IPV6],
        allowed_destination_cidrs=["2001:db8:2::/64"],
    )
    packet(functions, spec, IPV6, source_ip="2001:db8:1::10")
    delete(functions)
    result = subnet.probe_tls(
        IPV6,
        **OPTIONS,
        address_family="ipv6",
        server_hostname=HOST,
        expected_addresses=[IPV6],
        allowed_destination_cidrs=["2001:db8:2::/64"],
        expected_source_cidrs=["2001:db8:1::/64"],
    )
    assert result
    assert result.evidence["family_results"]["ipv6"]["passed"] is True


def test_dual_dns_expectations_report_both_families(cloud):
    subnet, functions, ec2 = cloud
    subnet_response(ec2)
    create(functions)
    state(functions)
    resolve(functions)
    delete(functions)
    result = subnet.probe_dns(
        HOST,
        **OPTIONS,
        address_family="dual",
        expected_addresses=[IPV6, IPV4],
        allowed_cidrs=["10.0.0.0/8", "2001:db8::/32"],
    )
    assert result
    assert result.evidence["addresses_by_family"] == {"ipv4": [IPV4], "ipv6": [IPV6]}


@pytest.mark.parametrize(
    "changes",
    [
        {"addresses_by_family": {"ipv4": [IPV4], "ipv6": []}},
        {"addresses": ["::ffff:10.1.2.3", IPV6]},
    ],
)
def test_malformed_family_evidence_is_not_accepted(cloud, changes):
    subnet, functions, ec2 = cloud
    subnet_response(ec2)
    create(functions)
    state(functions)
    resolve(functions, **changes)
    delete(functions)
    with pytest.raises(ProbeError):
        subnet.probe_tls(HOST, **OPTIONS, address_family="dual")


def test_per_check_family_can_only_narrow_the_deployment(cloud):
    subnet, functions, ec2 = cloud
    subnet_response(ec2)
    create(functions, ipv6=False)
    state(functions)
    delete(functions)
    with subnet.probe_session(**OPTIONS) as batch:
        with pytest.raises(ValueError, match="disabled on its deployment"):
            batch.tcp(HOST, address_family="ipv6")


@pytest.mark.parametrize(
    "options",
    [
        {"expected_addresses": []},
        {"expected_addresses": ["::ffff:10.1.2.3"]},
        {"allowed_destination_cidrs": "10.0.0.0/8"},
        {"address_family": "ipv6", "expected_addresses": [IPV4]},
        {"address_family": "invalid"},
    ],
)
def test_bad_destination_constraints_fail_without_creating_clients(monkeypatch, options):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("No AWS calls"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(ValueError):
        rule.subnet(SUBNET).probe_http(f"https://{HOST}/health", **OPTIONS, **options)
    client.assert_not_called()
