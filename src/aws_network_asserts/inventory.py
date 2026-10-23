"""Read recorded network inventory from regional Config or an aggregator."""

import json
from copy import copy
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .accounts import validate_account_id
from .clients import AwsClients
from .errors import ConfigResourceNotFoundError, NetworkAssertionError


def _records(page: dict[str, Any], key: str) -> list[dict[str, Any]]:
    records = page.get(key)
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise NetworkAssertionError(f"AWS Config response must contain a {key} list of objects")
    return records


@dataclass(frozen=True)
class ResourceSnapshot:
    """A recorded configuration; ``captured_at`` is not a liveness guarantee.

    Config emits records when configuration changes, so an old timestamp can
    represent an unchanged resource. Configuration keys retain AWS Config's
    lowerCamelCase spelling rather than pretending to be EC2 API responses.
    """

    resource_type: str
    resource_id: str
    region: str
    account_id: str | None
    captured_at: datetime | None
    configuration: dict[str, Any]
    tags: dict[str, str]
    relationships: list[dict[str, Any]]
    status: str
    arn: str | None = None


class ConfigInventory:
    """Query Config explicitly, with no implicit live-EC2 fallback."""

    def __init__(
        self,
        clients: AwsClients,
        *,
        aggregator_name: str | None = None,
        aggregator_region: str | None = None,
        account_id: str | None = None,
    ) -> None:
        if aggregator_name and not aggregator_region:
            raise ValueError("An aggregator requires aggregator_region")
        if aggregator_region and not aggregator_name:
            raise ValueError("aggregator_region requires aggregator_name")
        self.clients = clients
        self.aggregator_name = aggregator_name
        self.aggregator_region = aggregator_region
        self.account_id = validate_account_id(account_id) if account_id is not None else None

    def in_account(self, account_id: str) -> "ConfigInventory":
        """Select a source account while retaining the central Config credentials."""
        account_id = validate_account_id(account_id)
        inventory = copy(self)
        inventory.account_id = account_id
        return inventory

    def _source_account(self) -> str:
        if self.account_id is None:
            raise ValueError(
                "AWS Config aggregator queries require a source account_id; "
                "select it with in_account(...)"
            )
        return validate_account_id(self.account_id)

    def get(self, resource_type: str, resource_id: str, region: str) -> ResourceSnapshot:
        """Return the latest usable CI or raise ConfigResourceNotFoundError.

        Authentication, authorization, transport errors and malformed responses
        propagate: none is evidence that a network resource does not exist.
        """
        account_id = self._source_account() if self.aggregator_name else self.account_id
        client = self.clients.client("config", self.aggregator_region or region)
        try:
            if self.aggregator_name:
                response = client.get_aggregate_resource_config(
                    ConfigurationAggregatorName=self.aggregator_name,
                    ResourceIdentifier={
                        "SourceAccountId": account_id,
                        "SourceRegion": region,
                        "ResourceId": resource_id,
                        "ResourceType": resource_type,
                    },
                )
                item = response["ConfigurationItem"]
            else:
                pages = client.get_paginator("get_resource_config_history").paginate(
                    resourceType=resource_type,
                    resourceId=resource_id,
                    chronologicalOrder="Reverse",
                    PaginationConfig={"MaxItems": 1, "PageSize": 1},
                )
                item = None
                for page in pages:
                    records = _records(page, "configurationItems")
                    if records:
                        item = records[0]
                        break
                if item is None:
                    raise ConfigResourceNotFoundError(
                        f"No AWS Config record for {resource_type} {resource_id} in {region}"
                    )
        except client.exceptions.ResourceNotDiscoveredException as exc:
            raise ConfigResourceNotFoundError(
                f"AWS Config has not discovered {resource_type} {resource_id} in {region}"
            ) from exc
        return self._snapshot(item, resource_type, resource_id, region)

    def resource_ids(self, resource_type: str, region: str) -> list[str]:
        """Discover IDs in exactly the requested account/region inventory scope.

        Discovery alone does not mean a usable CI exists; call ``get`` before
        relying on configuration. Deleted regional resources are excluded.
        """
        account_id = self._source_account() if self.aggregator_name else self.account_id
        client = self.clients.client("config", self.aggregator_region or region)
        if self.aggregator_name:
            pages = client.get_paginator("list_aggregate_discovered_resources").paginate(
                ConfigurationAggregatorName=self.aggregator_name,
                ResourceType=resource_type,
                Filters={"AccountId": account_id, "Region": region},
            )
            ids = {
                resource["ResourceId"]
                for page in pages
                for resource in _records(page, "ResourceIdentifiers")
            }
        else:
            pages = client.get_paginator("list_discovered_resources").paginate(
                resourceType=resource_type,
                includeDeletedResources=False,
            )
            ids = {
                resource["resourceId"]
                for page in pages
                for resource in _records(page, "resourceIdentifiers")
            }
        return sorted(ids)

    def _snapshot(
        self,
        item: dict[str, Any],
        resource_type: str,
        resource_id: str,
        region: str,
    ) -> ResourceSnapshot:
        status = item["configurationItemStatus"]
        if status in {"ResourceNotRecorded", "ResourceDeleted", "ResourceDeletedNotRecorded"}:
            raise ConfigResourceNotFoundError(
                f"AWS Config record for {resource_type} {resource_id} in {region}: {status}"
            )
        if status not in {"OK", "ResourceDiscovered"}:
            raise ValueError(f"Unexpected AWS Config configurationItemStatus: {status!r}")
        for key, expected in (
            ("resourceType", resource_type),
            ("resourceId", resource_id),
            ("awsRegion", region),
        ):
            if key in item and item[key] != expected:
                raise ValueError(f"AWS Config returned {key}={item[key]!r}; expected {expected!r}")
        if self.account_id and item.get("accountId") != self.account_id:
            raise ValueError("AWS Config returned an unexpected or missing source accountId")
        configuration = json.loads(item["configuration"])
        if not isinstance(configuration, dict):
            raise ValueError("AWS Config configuration must decode to a JSON object")
        tags = item.get("tags", {})
        relationships = item.get("relationships", [])
        if not isinstance(tags, dict) or not isinstance(relationships, list):
            raise ValueError("AWS Config tags and relationships have unexpected types")
        return ResourceSnapshot(
            resource_type=resource_type,
            resource_id=resource_id,
            region=region,
            account_id=item.get("accountId"),
            captured_at=item.get("configurationItemCaptureTime"),
            configuration=configuration,
            tags=tags,
            relationships=relationships,
            status=status,
            arn=item.get("arn"),
        )
