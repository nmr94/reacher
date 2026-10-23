import json
from datetime import datetime, timezone
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from aws_network_asserts.clients import AwsClients
from aws_network_asserts.errors import ConfigResourceNotFoundError, NetworkAssertionError
from aws_network_asserts.inventory import ConfigInventory

REGION = "eu-west-2"
ACCOUNT = "123456789012"
RESOURCE = "subnet-0123456789abcdef0"
RESOURCE_TYPE = "AWS::EC2::Subnet"
PARAMS = {
    "resourceType": RESOURCE_TYPE,
    "resourceId": RESOURCE,
    "chronologicalOrder": "Reverse",
    "limit": 1,
}


@pytest.fixture
def clients():
    session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION
    )
    return AwsClients(session, endpoint_url="http://localhost:4566")


def item(**updates):
    result = {
        "resourceType": RESOURCE_TYPE,
        "resourceId": RESOURCE,
        "awsRegion": REGION,
        "accountId": ACCOUNT,
        "configurationItemStatus": "OK",
        "configurationItemCaptureTime": datetime(2020, 1, 1, tzinfo=timezone.utc),
        "configuration": json.dumps({"vpcId": "vpc-123", "cidrBlock": "10.0.0.0/24"}),
        "tags": {"Name": "application"},
        "relationships": [{"resourceType": "AWS::EC2::VPC", "resourceId": "vpc-123"}],
    }
    result.update(updates)
    return result


def test_latest_snapshot_parses_configuration_without_rejecting_an_old_capture(clients):
    client = clients.client("config", REGION)
    with Stubber(client) as stub:
        stub.add_response("get_resource_config_history", {"configurationItems": [item()]}, PARAMS)
        snapshot = ConfigInventory(clients).get(RESOURCE_TYPE, RESOURCE, REGION)
        stub.assert_no_pending_responses()

    assert snapshot.configuration == {"vpcId": "vpc-123", "cidrBlock": "10.0.0.0/24"}
    assert snapshot.captured_at.year == 2020
    assert snapshot.account_id == ACCOUNT
    assert snapshot.arn is None
    assert snapshot.tags == {"Name": "application"}
    assert snapshot.relationships[0]["resourceId"] == "vpc-123"


def test_history_follows_an_empty_page_before_returning_latest_record(clients):
    client = clients.client("config", REGION)
    with Stubber(client) as stub:
        stub.add_response(
            "get_resource_config_history", {"configurationItems": [], "nextToken": "older"}, PARAMS
        )
        stub.add_response(
            "get_resource_config_history",
            {"configurationItems": [item()]},
            {**PARAMS, "nextToken": "older"},
        )
        assert ConfigInventory(clients).get(RESOURCE_TYPE, RESOURCE, REGION).resource_id == RESOURCE
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "status", ["ResourceDeleted", "ResourceDeletedNotRecorded", "ResourceNotRecorded"]
)
def test_unusable_latest_record_never_resurrects_an_older_good_record(clients, status):
    client = clients.client("config", REGION)
    with Stubber(client) as stub:
        stub.add_response(
            "get_resource_config_history",
            {"configurationItems": [item(configurationItemStatus=status)], "nextToken": "older"},
            PARAMS,
        )
        with pytest.raises(ConfigResourceNotFoundError, match=status):
            ConfigInventory(clients).get(RESOURCE_TYPE, RESOURCE, REGION)
        stub.assert_no_pending_responses()


def test_empty_history_is_missing_inventory(clients):
    with Stubber(clients.client("config", REGION)) as stub:
        stub.add_response("get_resource_config_history", {"configurationItems": []}, PARAMS)
        with pytest.raises(ConfigResourceNotFoundError, match="No AWS Config record"):
            ConfigInventory(clients).get(RESOURCE_TYPE, RESOURCE, REGION)


def test_resource_not_discovered_is_missing_inventory(clients):
    with Stubber(clients.client("config", REGION)) as stub:
        stub.add_client_error(
            "get_resource_config_history",
            service_error_code="ResourceNotDiscoveredException",
            expected_params=PARAMS,
        )
        with pytest.raises(ConfigResourceNotFoundError, match="has not discovered"):
            ConfigInventory(clients).get(RESOURCE_TYPE, RESOURCE, REGION)


def test_access_denied_is_never_treated_as_missing_inventory(clients):
    with Stubber(clients.client("config", REGION)) as stub:
        stub.add_client_error(
            "get_resource_config_history",
            service_error_code="AccessDeniedException",
            expected_params=PARAMS,
        )
        with pytest.raises(ClientError, match="AccessDenied"):
            ConfigInventory(clients).get(RESOURCE_TYPE, RESOURCE, REGION)


@pytest.mark.parametrize("configuration", ["malformed JSON", "[]", "null"])
def test_malformed_configuration_is_an_error(clients, configuration):
    with Stubber(clients.client("config", REGION)) as stub:
        stub.add_response(
            "get_resource_config_history",
            {"configurationItems": [item(configuration=configuration)]},
            PARAMS,
        )
        with pytest.raises(ValueError):
            ConfigInventory(clients).get(RESOURCE_TYPE, RESOURCE, REGION)


def test_aggregator_client_region_is_separate_from_resource_region(clients):
    inventory = ConfigInventory(
        clients, aggregator_name="network", aggregator_region="eu-west-1", account_id=ACCOUNT
    )
    with Stubber(clients.client("config", "eu-west-1")) as stub:
        stub.add_response(
            "get_aggregate_resource_config",
            {"ConfigurationItem": item()},
            {
                "ConfigurationAggregatorName": "network",
                "ResourceIdentifier": {
                    "SourceAccountId": ACCOUNT,
                    "SourceRegion": REGION,
                    "ResourceId": RESOURCE,
                    "ResourceType": RESOURCE_TYPE,
                },
            },
        )
        assert inventory.get(RESOURCE_TYPE, RESOURCE, REGION).region == REGION
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"aggregator_name": "network"},
        {"aggregator_name": "network", "account_id": ACCOUNT},
        {"aggregator_region": REGION},
    ],
)
def test_aggregator_requires_its_name_and_region_together(clients, kwargs):
    with pytest.raises(ValueError):
        ConfigInventory(clients, **kwargs)


@pytest.mark.parametrize("operation", ["get", "resource_ids"])
def test_aggregator_requires_source_account_before_creating_client(operation):
    clients = Mock(spec=AwsClients)
    inventory = ConfigInventory(clients, aggregator_name="network", aggregator_region=REGION)
    with pytest.raises(ValueError, match=r"source account_id.*in_account"):
        if operation == "get":
            inventory.get(RESOURCE_TYPE, RESOURCE, REGION)
        else:
            inventory.resource_ids(RESOURCE_TYPE, REGION)
    clients.client.assert_not_called()


@pytest.mark.parametrize(
    "account_id", ["", "12345678901", "1234567890123", "abcdefghijkl", 123456789012]
)
def test_inventory_account_scope_must_be_a_valid_account_id(clients, account_id):
    with pytest.raises(ValueError):
        ConfigInventory(clients, account_id=account_id)
    inventory = ConfigInventory(clients, aggregator_name="network", aggregator_region=REGION)
    with pytest.raises(ValueError):
        inventory.in_account(account_id)
    assert inventory.account_id is None


def test_account_views_share_central_aggregator_without_mutating_existing_views(clients):
    inventory = ConfigInventory(clients, aggregator_name="network", aggregator_region="eu-west-1")
    first = inventory.in_account(ACCOUNT)
    second = first.in_account("210987654321")
    assert inventory.account_id is None
    assert first.account_id == ACCOUNT
    assert second.account_id == "210987654321"
    assert first is not inventory and second is not first
    assert first.clients is second.clients is inventory.clients is clients
    assert first.aggregator_name == second.aggregator_name == "network"
    assert first.aggregator_region == second.aggregator_region == "eu-west-1"

    # Both member accounts use the same central client, even across source Regions.
    with Stubber(clients.client("config", "eu-west-1")) as stub:
        for view, region in [(first, REGION), (second, "us-east-1")]:
            arn = f"arn:aws:ec2:{region}:{view.account_id}:subnet/{RESOURCE}"
            stub.add_response(
                "get_aggregate_resource_config",
                {"ConfigurationItem": item(accountId=view.account_id, awsRegion=region, arn=arn)},
                {
                    "ConfigurationAggregatorName": "network",
                    "ResourceIdentifier": {
                        "SourceAccountId": view.account_id,
                        "SourceRegion": region,
                        "ResourceId": RESOURCE,
                        "ResourceType": RESOURCE_TYPE,
                    },
                },
            )
            snapshot = view.get(RESOURCE_TYPE, RESOURCE, region)
            assert snapshot.account_id == view.account_id
            assert snapshot.region == region
            assert snapshot.arn == arn
        stub.assert_no_pending_responses()
    assert inventory.account_id is None
    assert first.account_id == ACCOUNT


@pytest.mark.parametrize("account_id", [None, "210987654321"])
def test_aggregator_snapshot_requires_matching_source_account(clients, account_id):
    inventory = ConfigInventory(
        clients, aggregator_name="network", aggregator_region=REGION
    ).in_account(ACCOUNT)
    record = item(accountId=account_id)
    if account_id is None:
        del record["accountId"]
    with Stubber(clients.client("config", REGION)) as stub:
        stub.add_response(
            "get_aggregate_resource_config",
            {"ConfigurationItem": record},
            {
                "ConfigurationAggregatorName": "network",
                "ResourceIdentifier": {
                    "SourceAccountId": ACCOUNT,
                    "SourceRegion": REGION,
                    "ResourceId": RESOURCE,
                    "ResourceType": RESOURCE_TYPE,
                },
            },
        )
        with pytest.raises(ValueError, match="source accountId"):
            inventory.get(RESOURCE_TYPE, RESOURCE, REGION)
        stub.assert_no_pending_responses()


def test_discovery_paginates_and_excludes_deleted_resources(clients):
    params = {"resourceType": RESOURCE_TYPE, "includeDeletedResources": False}
    with Stubber(clients.client("config", REGION)) as stub:
        stub.add_response(
            "list_discovered_resources",
            {"resourceIdentifiers": [{"resourceId": "subnet-b"}], "nextToken": "next"},
            params,
        )
        stub.add_response(
            "list_discovered_resources",
            {"resourceIdentifiers": [{"resourceId": "subnet-a"}, {"resourceId": "subnet-b"}]},
            {**params, "nextToken": "next"},
        )
        assert ConfigInventory(clients).resource_ids(RESOURCE_TYPE, REGION) == [
            "subnet-a",
            "subnet-b",
        ]
        stub.assert_no_pending_responses()


def test_aggregate_discovery_filters_source_account_and_region_on_every_page(clients):
    params = {
        "ConfigurationAggregatorName": "network",
        "ResourceType": RESOURCE_TYPE,
        "Filters": {"AccountId": ACCOUNT, "Region": REGION},
    }
    inventory = ConfigInventory(
        clients, aggregator_name="network", aggregator_region="eu-west-1"
    ).in_account(ACCOUNT)
    identifier = {
        "SourceAccountId": ACCOUNT,
        "SourceRegion": REGION,
        "ResourceType": RESOURCE_TYPE,
    }
    with Stubber(clients.client("config", "eu-west-1")) as stub:
        stub.add_response(
            "list_aggregate_discovered_resources",
            {
                "ResourceIdentifiers": [{**identifier, "ResourceId": "subnet-b"}],
                "NextToken": "next",
            },
            params,
        )
        stub.add_response(
            "list_aggregate_discovered_resources",
            {"ResourceIdentifiers": [{**identifier, "ResourceId": "subnet-a"}]},
            {**params, "NextToken": "next"},
        )
        assert inventory.resource_ids(RESOURCE_TYPE, REGION) == ["subnet-a", "subnet-b"]
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "field,value", [("awsRegion", "us-east-1"), ("resourceId", "subnet-other")]
)
def test_snapshot_identity_mismatch_is_an_error(clients, field, value):
    with Stubber(clients.client("config", REGION)) as stub:
        stub.add_response(
            "get_resource_config_history", {"configurationItems": [item(**{field: value})]}, PARAMS
        )
        with pytest.raises(ValueError, match="expected"):
            ConfigInventory(clients).get(RESOURCE_TYPE, RESOURCE, REGION)


@pytest.mark.parametrize("operation", ["history", "discovery", "aggregate_discovery"])
def test_missing_result_list_is_an_evaluation_error_not_missing_inventory(clients, operation):
    if operation == "aggregate_discovery":
        inventory = ConfigInventory(
            clients, aggregator_name="network", aggregator_region=REGION, account_id=ACCOUNT
        )
        method = "list_aggregate_discovered_resources"
        params = {
            "ConfigurationAggregatorName": "network",
            "ResourceType": RESOURCE_TYPE,
            "Filters": {"AccountId": ACCOUNT, "Region": REGION},
        }
    else:
        inventory = ConfigInventory(clients)
        method = (
            "get_resource_config_history" if operation == "history" else "list_discovered_resources"
        )
        params = (
            PARAMS
            if operation == "history"
            else {"resourceType": RESOURCE_TYPE, "includeDeletedResources": False}
        )
    with Stubber(clients.client("config", REGION)) as stub:
        stub.add_response(method, {}, params)
        with pytest.raises(NetworkAssertionError, match="list of objects"):
            if operation == "history":
                inventory.get(RESOURCE_TYPE, RESOURCE, REGION)
            else:
                inventory.resource_ids(RESOURCE_TYPE, REGION)


@pytest.mark.parametrize("records", [None, {}, ["not an object"]])
def test_malformed_inventory_list_shapes_are_errors(clients, monkeypatch, records):
    # Stubber rejects deliberately malformed list types before application code
    # receives them, so replace pagination only for this invalid transport data.
    paginator = Mock()
    paginator.paginate.return_value = [{"configurationItems": records}]
    monkeypatch.setattr(clients.client("config", REGION), "get_paginator", lambda _: paginator)
    with pytest.raises(NetworkAssertionError, match="list of objects"):
        ConfigInventory(clients).get(RESOURCE_TYPE, RESOURCE, REGION)
