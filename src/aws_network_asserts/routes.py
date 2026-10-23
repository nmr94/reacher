"""Effective VPC route checks, including complete CIDR coverage.

This evaluates route selection only, not security groups, ACLs, return paths,
or the health of the next hop. Interval boundaries keep even IPv6 /0 finite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any

from .accounts import validate_account_id
from .errors import NetworkAssertionError, UnsupportedCheckError
from .result import CheckResult

_TARGET_FIELDS = (
    "GatewayId",
    "NatGatewayId",
    "TransitGatewayId",
    "VpcPeeringConnectionId",
    "NetworkInterfaceId",
    "InstanceId",
    "EgressOnlyInternetGatewayId",
    "LocalGatewayId",
    "CarrierGatewayId",
    "CoreNetworkArn",
    "OdbNetworkArn",
    "IpAddress",
)
_DESTINATION_FIELDS = (
    "DestinationCidrBlock",
    "DestinationIpv6CidrBlock",
    "DestinationPrefixListId",
)


def _validate_via(value: str | None) -> None:
    if value is not None and (
        not isinstance(value, str)
        or not value
        or any(char.isspace() or not char.isprintable() for char in value)
    ):
        raise ValueError(
            "via must be a route target ID or ARN without whitespace/control characters"
        )
    if value is not None and value.startswith("arn:"):
        parts = value.split(":", 5)
        if (
            len(parts) != 6
            or not parts[5]
            or any(re.fullmatch(r"[a-z0-9-]+", part) is None for part in parts[1:3])
            or (parts[3] and re.fullmatch(r"[a-z0-9-]+", parts[3]) is None)
        ):
            raise ValueError("via must contain a valid route target ARN")
        validate_account_id(parts[4])
        if parts[2] == "ec2":
            raise UnsupportedCheckError(
                "Use a native EC2 target ID for via; route responses do not establish "
                "an EC2 target ARN's ownership"
            )


@dataclass(frozen=True)
class _Route:
    network: IPv4Network | IPv6Network
    raw: dict[str, Any]

    @property
    def targets(self) -> tuple[str, ...]:
        fields = {key: self.raw[key] for key in _TARGET_FIELDS if self.raw.get(key) is not None}
        values = tuple(fields.values())
        if not all(
            isinstance(value, str)
            and value
            and not any(char.isspace() or not char.isprintable() for char in value)
            for value in values
        ):
            raise NetworkAssertionError(f"Invalid route target: {self.raw!r}")
        if len(fields) > 1 and set(fields) != {"InstanceId", "NetworkInterfaceId"}:
            raise UnsupportedCheckError(f"Ambiguous route targets: {self.raw!r}")
        return values

    @property
    def priority(self) -> int | None:
        if self.raw.get("DestinationPrefixListId"):
            return 1
        origin = self.raw.get("Origin")
        if origin in {"CreateRoute", "CreateRouteTable"}:
            return 2
        if origin == "EnableVgwRoutePropagation":
            return 0
        # No ordering is invented for unknown origins or Route Server BGP ties.
        return None


def _requested_network(value: str, name: str = "destination") -> IPv4Network | IPv6Network:
    """Validate an AWS route range; interface-scoped IPv6 has no route-table meaning."""
    if not isinstance(value, str) or not value or "%" in value:
        raise ValueError(f"{name} must be an IPv4/IPv6 address or CIDR without a scope identifier")
    return ip_network(value, strict=False)


def _network(value: Any, *, context: str) -> IPv4Network | IPv6Network:
    if not isinstance(value, str) or not value:
        raise NetworkAssertionError(f"{context} must contain a CIDR string; got {value!r}")
    if "%" in value:
        raise NetworkAssertionError(f"CIDRs in {context} must not contain scope identifiers")
    try:
        return ip_network(value, strict=False)
    except ValueError as exc:
        raise NetworkAssertionError(f"Invalid CIDR in {context}: {value!r}") from exc


def _expand(client: Any, route_table: dict[str, Any]) -> list[_Route]:
    raw_routes = route_table.get("Routes")
    if not isinstance(raw_routes, list):
        raise NetworkAssertionError("Route table response is missing a Routes list")
    expanded: list[_Route] = []
    prefix_lists: dict[str, list[IPv4Network | IPv6Network]] = {}
    for raw in raw_routes:
        if not isinstance(raw, dict):
            raise NetworkAssertionError(f"Invalid route entry: {raw!r}")
        fields = [key for key in _DESTINATION_FIELDS if raw.get(key)]
        if len(fields) != 1:
            raise NetworkAssertionError(f"Route must have exactly one destination: {raw!r}")
        field = fields[0]
        if field == "DestinationPrefixListId":
            prefix_id = raw[field]
            if not isinstance(prefix_id, str):
                raise NetworkAssertionError(f"Invalid prefix list ID: {prefix_id!r}")
            if prefix_id not in prefix_lists:
                networks = []
                pages = client.get_paginator("get_managed_prefix_list_entries").paginate(
                    PrefixListId=prefix_id
                )
                for page in pages:
                    entries = page.get("Entries")
                    if not isinstance(entries, list):
                        raise NetworkAssertionError(
                            f"Prefix list {prefix_id} response is missing Entries"
                        )
                    for entry in entries:
                        if not isinstance(entry, dict):
                            raise NetworkAssertionError(f"Invalid entry in {prefix_id}: {entry!r}")
                        networks.append(_network(entry.get("Cidr"), context=prefix_id))
                prefix_lists[prefix_id] = networks
            expanded.extend(_Route(network, raw) for network in prefix_lists[prefix_id])
        else:
            network = _network(raw[field], context=field)
            expected_version = 4 if field == "DestinationCidrBlock" else 6
            if network.version != expected_version:
                raise NetworkAssertionError(f"Wrong address family for {field}: {raw[field]}")
            expanded.append(_Route(network, raw))
    return expanded


def _winner(candidates: list[_Route]) -> _Route:
    longest = max(route.network.prefixlen for route in candidates)
    tied = [route for route in candidates if route.network.prefixlen == longest]
    if len(tied) == 1:
        return tied[0]
    priorities = [route.priority for route in tied]
    if all(priority is not None for priority in priorities):
        highest = max(priority for priority in priorities if priority is not None)
        tied = [route for route in tied if route.priority == highest]
    elif len({(route.targets, route.raw.get("State")) for route in tied}) > 1:
        raise UnsupportedCheckError(
            f"Cannot determine equal-prefix route priority for {tied[0].network}: "
            "an origin is missing, unknown, or uses VPC Route Server"
        )
    if len({(route.targets, route.raw.get("State")) for route in tied}) > 1:
        raise UnsupportedCheckError(
            f"Ambiguous equal-priority routes for {tied[0].network}; "
            "AWS can choose between overlapping prefix lists. Use Reachability Analyzer."
        )
    return tied[0]


def check_routes(
    client: Any,
    route_table: dict[str, Any],
    destination: str,
    *,
    via: str | None = None,
) -> CheckResult:
    """Require active effective routes for every address in ``destination``.

    ``via`` optionally constrains every winning route's next hop. A specific
    blackhole defeats a less-specific active route. Prefix list API failures,
    incomplete data and ambiguous ties raise rather than imply isolation.
    """
    requested = _requested_network(destination)
    _validate_via(via)
    table_id = route_table.get("RouteTableId", "<unknown route table>")
    routes = [
        route
        for route in _expand(client, route_table)
        if route.network.version == requested.version and route.network.overlaps(requested)
    ]
    first, stop = int(requested.network_address), int(requested.broadcast_address) + 1
    boundaries = {first, stop}
    for route in routes:
        boundaries.add(max(first, int(route.network.network_address)))
        boundaries.add(min(stop, int(route.network.broadcast_address) + 1))
    ordered = sorted(boundaries)
    evidence: dict[str, Any] = {
        "route_table_id": table_id,
        "destination": str(requested),
        "via": via,
        "coverage": [],
        "route_table": route_table,
    }
    address_type = type(requested.network_address)
    for start, end in zip(ordered, ordered[1:], strict=False):
        address = address_type(start)
        candidates = [route for route in routes if address in route.network]
        span: dict[str, Any] = {
            "first": str(address),
            "last": str(address_type(end - 1)),
        }
        if not candidates:
            evidence["counterexample"] = span
            return CheckResult(
                False, f"{table_id} has no route for {address} within {requested}", evidence
            )
        winner = _winner(candidates)
        state = winner.raw.get("State")
        if state not in {"active", "blackhole"}:
            raise NetworkAssertionError(
                f"{table_id} route {winner.network} has unknown or missing state {state!r}"
            )
        targets = winner.targets
        span.update({"prefix": str(winner.network), "route": winner.raw})
        evidence["coverage"].append(span)
        if state == "blackhole":
            evidence["counterexample"] = span
            return CheckResult(
                False,
                f"{table_id} selects blackhole {winner.network} for {address} within {requested}",
                evidence,
            )
        if not targets:
            raise NetworkAssertionError(
                f"{table_id} active route {winner.network} has no recognized target"
            )
        if via is not None and via not in targets:
            evidence["counterexample"] = span
            return CheckResult(
                False,
                f"{table_id} routes {address} via {', '.join(targets)}, expected {via}",
                evidence,
            )
    target_note = f" via {via}" if via else ""
    return CheckResult(
        True, f"{table_id} has active routes covering all of {requested}{target_note}", evidence
    )
