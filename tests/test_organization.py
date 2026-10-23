"""Public organization workflows against botocore models, without AWS calls."""

import json
from datetime import datetime, timezone
from unittest.mock import Mock

import boto3
import pytest
from botocore.stub import ANY, Stubber

from aws_network_asserts import AccountMismatchError, NetworkAssertionError, RuleBuilder

REGION = "eu-west-2"
OTHER_REGION = "us-east-1"
CONFIG_REGION = "eu-west-1"
CENTRAL_ACCOUNT = "999999999999"
MEMBER_ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"
AGGREGATOR = "organization-network"
ENI = "eni-0123456789abcdef0"
DESTINATION = "eni-0fedcba9876543210"
SUBNET = "subnet-0123456789abcdef0"
TABLE = "rtb-0123456789abcdef0"
TGW = "tgw-0123456789abcdef0"
PATH = "nip-0123456789abcdef0"
ANALYSIS = "nia-0123456789abcdef0"
ENDPOINT = "http://localhost:4566"


def session():
    return boto3.Session(aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION)


def organization(**options):
    return RuleBuilder(
        **{
            "session": session(),
            "config_aggregator": AGGREGATOR,
            "config_region": CONFIG_REGION,
            "endpoint_url": ENDPOINT,
            **options,
        }
    )


def eni_arn(account_id, region=REGION, resource_id=ENI):
    return f"arn:aws:ec2:{region}:{account_id}:network-interface/{resource_id}"


def aggregate_snapshot(
    stub, account_id, region, *, resource_type="AWS::EC2::NetworkInterface", resource_id=ENI
):
    stub.add_response(
        "get_aggregate_resource_config",
        {
            "ConfigurationItem": {
                "resourceType": resource_type,
                "resourceId": resource_id,
                "awsRegion": region,
                "accountId": account_id,
                "configurationItemStatus": "OK",
                "configurationItemCaptureTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "configuration": json.dumps({"subnetId": SUBNET}),
                "tags": {"Team": "network"},
            }
        },
        {
            "ConfigurationAggregatorName": AGGREGATOR,
            "ResourceIdentifier": {
                "SourceAccountId": account_id,
                "SourceRegion": region,
                "ResourceType": resource_type,
                "ResourceId": resource_id,
            },
        },
    )


def analysis_lifecycle(stub, source, destination):
    stub.add_response(
        "create_network_insights_path",
        {"NetworkInsightsPath": {"NetworkInsightsPathId": PATH}},
        {
            "Source": source,
            "Destination": destination,
            "Protocol": "tcp",
            "FilterAtSource": {"DestinationPortRange": {"FromPort": 443, "ToPort": 443}},
            "ClientToken": ANY,
        },
    )
    stub.add_response(
        "start_network_insights_analysis",
        {
            "NetworkInsightsAnalysis": {
                "NetworkInsightsAnalysisId": ANALYSIS,
                "NetworkInsightsPathId": PATH,
                "Status": "succeeded",
                "NetworkPathFound": True,
            }
        },
        {"NetworkInsightsPathId": PATH, "ClientToken": ANY},
    )
    stub.add_response(
        "delete_network_insights_analysis",
        {"NetworkInsightsAnalysisId": ANALYSIS},
        {"NetworkInsightsAnalysisId": ANALYSIS},
    )
    stub.add_response(
        "delete_network_insights_path",
        {"NetworkInsightsPathId": PATH},
        {"NetworkInsightsPathId": PATH},
    )


def identity(stub, account_id):
    stub.add_response(
        "get_caller_identity",
        {
            "Account": account_id,
            "Arn": f"arn:aws:sts::{account_id}:assumed-role/NetworkAssertions/test",
            "UserId": "test-user",
        },
        {},
    )


def member_clients(member, monkeypatch, region=REGION):
    clients = {
        service: member.client(service, region_name=region, endpoint_url=ENDPOINT)
        for service in ("sts", "ec2")
    }
    create_client = Mock(side_effect=lambda service, **kwargs: clients[service])
    monkeypatch.setattr(member, "client", create_client)
    return clients, create_client


def test_account_and_region_views_preserve_existing_selectors_and_central_context():
    root = organization()
    member = root.in_account(MEMBER_ACCOUNT)
    selector = member.eni(ENI)
    other = member.in_region(OTHER_REGION).in_account(OTHER_ACCOUNT)

    assert root.account_id is None
    assert root.region_name == REGION
    assert (selector.account_id, selector.region) == (MEMBER_ACCOUNT, REGION)
    assert (other.account_id, other.region_name) == (OTHER_ACCOUNT, OTHER_REGION)
    assert root.clients is member.clients is other.clients
    assert root.config_clients is member.config_clients is other.config_clients
    assert root.inventory.account_id is None
    assert member.inventory.account_id == MEMBER_ACCOUNT
    assert other.inventory.account_id == OTHER_ACCOUNT
    assert other.inventory.aggregator_region == CONFIG_REGION
    assert member.analysis_ec2 is root.analysis_ec2
    assert other.analysis_ec2.meta.region_name == OTHER_REGION


def test_aggregate_inventory_uses_separate_central_session_across_accounts_and_regions(monkeypatch):
    central, config_session = session(), session()
    central_client = Mock(wraps=central.client)
    config_client = Mock(wraps=config_session.client)
    monkeypatch.setattr(central, "client", central_client)
    monkeypatch.setattr(config_session, "client", config_client)
    root = organization(session=central, config_session=config_session)
    config = root.config_clients.client("config", CONFIG_REGION)

    with Stubber(config) as stub:
        for account_id, region in [(MEMBER_ACCOUNT, REGION), (OTHER_ACCOUNT, OTHER_REGION)]:
            aggregate_snapshot(stub, account_id, region)
            scoped = root.in_account(account_id).in_region(region)
            result = scoped.eni(ENI).is_recorded()
            assert result
            assert result.evidence["config"]["account_id"] == account_id
            assert result.evidence["config"]["region"] == region
        stub.add_response(
            "list_aggregate_discovered_resources",
            {
                "ResourceIdentifiers": [
                    {
                        "SourceAccountId": OTHER_ACCOUNT,
                        "SourceRegion": OTHER_REGION,
                        "ResourceType": "AWS::EC2::NetworkInterface",
                        "ResourceId": DESTINATION,
                    }
                ]
            },
            {
                "ConfigurationAggregatorName": AGGREGATOR,
                "ResourceType": "AWS::EC2::NetworkInterface",
                "Filters": {"AccountId": OTHER_ACCOUNT, "Region": OTHER_REGION},
            },
        )
        assert root.in_account(OTHER_ACCOUNT).in_region(OTHER_REGION).resource_ids(
            "AWS::EC2::NetworkInterface"
        ) == [DESTINATION]
        stub.assert_no_pending_responses()

    assert root.config_mode == "required"
    assert config.meta.region_name == CONFIG_REGION
    assert root.config_clients.session is config_session
    assert root.clients.session is central
    config_client.assert_called_once()
    central_client.assert_not_called()


@pytest.mark.parametrize("region", [REGION, OTHER_REGION])
def test_cross_account_ra_uses_central_arn_lifecycle_without_loading_member_profiles(
    monkeypatch, region
):
    central = session()
    create_session = Mock(side_effect=AssertionError("RA must not load a member profile"))
    # The supplied central session must be sufficient for the entire analysis.
    root = organization(
        session=central,
        config_mode="off",
        account_profiles={MEMBER_ACCOUNT: "source-member", OTHER_ACCOUNT: "destination-member"},
    ).in_region(region)
    monkeypatch.setattr("boto3.Session", create_session)
    source = root.in_account(MEMBER_ACCOUNT)
    target = root.in_account(OTHER_ACCOUNT)
    source_arn = eni_arn(MEMBER_ACCOUNT, region)
    destination_arn = eni_arn(OTHER_ACCOUNT, region, DESTINATION)

    with Stubber(root.analysis_ec2) as stub:
        analysis_lifecycle(stub, source_arn, destination_arn)
        result = source.eni(ENI).can_reach(target.eni(DESTINATION))
        assert result
        assert result.evidence["source"] == source_arn
        assert result.evidence["destination"] == destination_arn
        assert result.evidence["account_id"] == MEMBER_ACCOUNT
        assert result.evidence["destination_account_id"] == OTHER_ACCOUNT
        assert result.evidence["region"] == region
        stub.assert_no_pending_responses()
    create_session.assert_not_called()
    assert source.analysis_ec2 is target.analysis_ec2 is root.analysis_ec2


@pytest.mark.parametrize("destination_kind", ["bare_id", "explicit_arn"])
def test_required_inventory_and_central_ra_work_without_member_credentials(destination_kind):
    root = organization(config_session=session())
    source = root.in_account(MEMBER_ACCOUNT)
    destination_account = MEMBER_ACCOUNT if destination_kind == "bare_id" else OTHER_ACCOUNT
    destination_arn = eni_arn(destination_account, resource_id=DESTINATION)
    destination = DESTINATION if destination_kind == "bare_id" else destination_arn

    with (
        Stubber(root.config_clients.client("config", CONFIG_REGION)) as config,
        Stubber(root.analysis_ec2) as ec2,
    ):
        aggregate_snapshot(config, MEMBER_ACCOUNT, REGION)
        analysis_lifecycle(ec2, eni_arn(MEMBER_ACCOUNT), destination_arn)
        result = source.eni(ENI).can_reach(destination)
        assert result
        assert result.evidence["config"]["account_id"] == MEMBER_ACCOUNT
        assert result.evidence["destination_account_id"] == destination_account
        config.assert_no_pending_responses()
        ec2.assert_no_pending_responses()


def test_explicit_central_and_config_profiles_are_separate(monkeypatch):
    central, config_session = session(), session()
    create_session = Mock(side_effect=[central, config_session])
    monkeypatch.setattr("boto3.Session", create_session)
    rule = RuleBuilder(
        profile_name="organization-admin",
        config_profile_name="organization-config",
        config_aggregator=AGGREGATOR,
        config_region=CONFIG_REGION,
        endpoint_url=ENDPOINT,
    ).in_account(MEMBER_ACCOUNT)

    with Stubber(rule.config_clients.client("config", CONFIG_REGION)) as stub:
        aggregate_snapshot(stub, MEMBER_ACCOUNT, REGION)
        assert rule.eni(ENI).has_config_tag("Team", "network")
        stub.assert_no_pending_responses()

    assert [call.kwargs for call in create_session.call_args_list] == [
        {"profile_name": "organization-admin"},
        {"profile_name": "organization-config"},
    ]
    assert rule.clients.session is central
    assert rule.config_clients.session is config_session


@pytest.mark.parametrize("mode", ["required", "prefer"])
@pytest.mark.parametrize("missing", ["config_aggregator", "config_region"])
def test_organization_modes_require_an_explicit_aggregator_location(mode, missing):
    with pytest.raises(ValueError, match="config_aggregator and config_region"):
        organization(config_mode=mode, **{missing: None})


@pytest.mark.parametrize("operation", ["snapshot", "discovery", "live"])
def test_unscoped_organization_checks_fail_before_creating_aws_clients(monkeypatch, operation):
    central = session()
    create_client = Mock(wraps=central.client)
    monkeypatch.setattr(central, "client", create_client)
    root = organization(session=central)
    if operation == "live":
        with pytest.raises(NetworkAssertionError, match="Select a resource account"):
            root.subnet(SUBNET).enis()
    else:
        with pytest.raises(ValueError, match="source account_id"):
            if operation == "snapshot":
                root.eni(ENI).is_recorded()
            else:
                root.resource_ids("AWS::EC2::NetworkInterface")
    create_client.assert_not_called()


def test_unscoped_destination_selector_cannot_resolve_in_central_account(monkeypatch):
    root = organization()
    create_client = Mock(wraps=root.clients.session.client)
    monkeypatch.setattr(root.clients.session, "client", create_client)
    with pytest.raises(ValueError, match="destination.*account"):
        root.in_account(MEMBER_ACCOUNT).eni(ENI).can_reach(root.eni(DESTINATION))
    create_client.assert_not_called()


@pytest.mark.parametrize("mapping", ["session", "profile"])
def test_live_topology_uses_verified_member_credentials_and_central_inventory(monkeypatch, mapping):
    central, member = session(), session()
    clients, create_client = member_clients(member, monkeypatch, OTHER_REGION)
    create_session = Mock(return_value=member)
    options = (
        {"account_sessions": {MEMBER_ACCOUNT: member}}
        if mapping == "session"
        else {"account_profiles": {MEMBER_ACCOUNT: "member-network-role"}}
    )
    root = organization(session=central, **options)
    monkeypatch.setattr("boto3.Session", create_session)
    rule = root.in_account(MEMBER_ACCOUNT).in_region(OTHER_REGION)
    create_session.assert_not_called()

    with (
        Stubber(root.config_clients.client("config", CONFIG_REGION)) as config,
        Stubber(clients["sts"]) as sts,
        Stubber(clients["ec2"]) as ec2,
    ):
        aggregate_snapshot(
            config,
            MEMBER_ACCOUNT,
            OTHER_REGION,
            resource_type="AWS::EC2::Subnet",
            resource_id=SUBNET,
        )
        identity(sts, MEMBER_ACCOUNT)
        ec2.add_response(
            "describe_route_tables",
            {
                "RouteTables": [
                    {
                        "RouteTableId": TABLE,
                        "OwnerId": MEMBER_ACCOUNT,
                        "VpcId": "vpc-member",
                        "Associations": [
                            {
                                "RouteTableAssociationId": "rtbassoc-current",
                                "RouteTableId": TABLE,
                                "SubnetId": SUBNET,
                                "Main": False,
                                "AssociationState": {"State": "associated"},
                            }
                        ],
                        "Routes": [
                            {
                                "DestinationCidrBlock": "10.47.0.0/16",
                                "TransitGatewayId": TGW,
                                "Origin": "CreateRoute",
                                "State": "active",
                            }
                        ],
                    }
                ]
            },
            {"Filters": [{"Name": "association.subnet-id", "Values": [SUBNET]}]},
        )
        result = rule.subnet(SUBNET).has_route_to("10.47.1.1/32", via=TGW)
        assert result
        assert result.evidence["account_id"] == MEMBER_ACCOUNT
        assert result.evidence["region"] == OTHER_REGION
        assert result.evidence["config"]["account_id"] == MEMBER_ACCOUNT
        assert rule.ec2 is clients["ec2"]
        config.assert_no_pending_responses()
        sts.assert_no_pending_responses()
        ec2.assert_no_pending_responses()

    assert [
        (call.args[0], call.kwargs["region_name"]) for call in create_client.call_args_list
    ] == [
        ("sts", OTHER_REGION),
        ("ec2", OTHER_REGION),
    ]
    if mapping == "profile":
        create_session.assert_called_once_with(profile_name="member-network-role")
    else:
        create_session.assert_not_called()
    assert rule.analysis_ec2 is root.in_region(OTHER_REGION).analysis_ec2
    assert rule.analysis_ec2 is not clients["ec2"]


@pytest.mark.parametrize("mapped_session", [False, True])
def test_wrong_credential_account_is_an_error_before_live_topology(monkeypatch, mapped_session):
    central, member = session(), session()
    selected_session = member if mapped_session else central
    clients, create_client = member_clients(selected_session, monkeypatch)
    options = {"account_sessions": {MEMBER_ACCOUNT: member}} if mapped_session else {}
    rule = organization(session=central, config_mode="off", **options).in_account(MEMBER_ACCOUNT)

    with Stubber(clients["sts"]) as sts, Stubber(clients["ec2"]) as ec2:
        identity(sts, CENTRAL_ACCOUNT)
        with pytest.raises(AccountMismatchError, match="account_profiles or account_sessions"):
            rule.subnet(SUBNET).has_route_to("10.47.1.1/32")
        sts.assert_no_pending_responses()
        ec2.assert_no_pending_responses()
    assert [call.args[0] for call in create_client.call_args_list] == ["sts"]
