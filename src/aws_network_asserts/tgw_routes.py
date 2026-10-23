"""Whole-range TGW route selection; incomplete search results never imply coverage."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .accounts import validate_account_id
from .errors import NetworkAssertionError, UnsupportedCheckError
from .result import CheckResult
from .routes import _network, _requested_network, _validate_via


@dataclass(frozen=True)
class _Route:
    network: Any
    raw: dict[str, Any]

    @property
    def targets(self):
        values = self.raw.get("TransitGatewayAttachments")
        if self.raw.get("State") == "blackhole" and values is None:
            return ()
        if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
            raise NetworkAssertionError("TGW route is missing attachments")
        targets = []
        for item in values:
            target = item.get("TransitGatewayAttachmentId")
            if (
                not isinstance(target, str)
                or re.fullmatch(r"tgw-attach-[A-Za-z0-9]+", target) is None
            ):
                raise NetworkAssertionError("TGW route has an invalid attachment ID")
            targets.append(target)
        return tuple(sorted(set(targets)))

    @property
    def priority(self):
        if self.raw.get("PrefixListId"):
            return 1
        if self.raw.get("Type") == "static":
            return 0
        ranks = {
            "vpc": 2,
            "direct-connect-gateway": 3,
            "connect": 4,
            "vpn": 6,
            "vpn-concentrator": 7,
            "client-vpn": 8,
            "peering": 9,
            "tgw-peering": 9,
        }
        items = self.raw.get("TransitGatewayAttachments", [])
        types = {item.get("ResourceType") for item in items if isinstance(item, dict)}
        if len(types) != 1 or next(iter(types)) not in ranks:
            raise UnsupportedCheckError("Cannot determine propagated TGW route priority")
        return ranks[next(iter(types))]


def _search(client, table_id, destination, filter_name):
    token = None
    seen = set()
    routes = []
    while True:
        request = {
            "TransitGatewayRouteTableId": table_id,
            "Filters": [{"Name": filter_name, "Values": [str(destination)]}],
            "MaxResults": 1000,
        }
        if token:
            request["NextToken"] = token
        page = client.search_transit_gateway_routes(**request)
        items = page.get("Routes")
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise NetworkAssertionError("TGW search is missing a Routes list")
        additional = page.get("AdditionalRoutesAvailable")
        if type(additional) is not bool:
            raise NetworkAssertionError("TGW search is missing AdditionalRoutesAvailable")
        routes.extend(items)
        token = page.get("NextToken")
        if token is not None and (not isinstance(token, str) or not token):
            raise NetworkAssertionError("TGW search returned an invalid pagination token")
        if not token:
            if additional:
                raise UnsupportedCheckError("TGW search is truncated without a continuation token")
            return routes
        if token in seen:
            raise NetworkAssertionError("TGW search repeated its pagination token")
        seen.add(token)


def _routes(client, table_id, requested):
    raw = []
    for name in ("route-search.supernet-of-match", "route-search.subnet-of-match"):
        raw.extend(_search(client, table_id, requested, name))
    # Prefix-list references are a separate table resource. Discover them
    # explicitly rather than assuming CIDR-filtered searches expose every entry.
    for page in client.get_paginator("get_transit_gateway_prefix_list_references").paginate(
        TransitGatewayRouteTableId=table_id
    ):
        references = page.get("TransitGatewayPrefixListReferences")
        if not isinstance(references, list):
            raise NetworkAssertionError("TGW table is missing prefix-list references")
        for reference in references:
            if (
                not isinstance(reference, dict)
                or reference.get("TransitGatewayRouteTableId") != table_id
            ):
                raise NetworkAssertionError("TGW prefix-list reference has an unexpected table")
            prefix = reference.get("PrefixListId")
            if not isinstance(prefix, str) or not prefix.startswith("pl-"):
                raise NetworkAssertionError("TGW reference has no prefix-list ID")
            try:
                validate_account_id(reference.get("PrefixListOwnerId"))
            except ValueError as error:
                raise NetworkAssertionError("TGW prefix list has no valid owner") from error
            if (
                reference.get("State") != "available"
                or type(reference.get("Blackhole")) is not bool
            ):
                raise NetworkAssertionError(
                    "TGW prefix-list reference is incomplete or transitioning"
                )
            attachment = reference.get("TransitGatewayAttachment")
            raw.append(
                {
                    "PrefixListId": prefix,
                    "Type": "static",
                    "State": "blackhole" if reference["Blackhole"] else "active",
                    "TransitGatewayAttachments": [] if attachment is None else [attachment],
                    "PrefixListReference": reference,
                }
            )
    expanded = []
    seen = set()
    prefix_lists = {}
    for route in raw:
        key = json.dumps(route, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        if route.get("Type") not in {"static", "propagated"}:
            raise NetworkAssertionError("TGW route has missing/unknown Type")
        if route.get("DestinationCidrBlock"):
            networks = [_network(route["DestinationCidrBlock"], context="TGW route")]
        elif route.get("PrefixListId"):
            prefix = route["PrefixListId"]
            if prefix not in prefix_lists:
                networks = []
                for page in client.get_paginator("get_managed_prefix_list_entries").paginate(
                    PrefixListId=prefix
                ):
                    entries = page.get("Entries")
                    if not isinstance(entries, list):
                        raise NetworkAssertionError("TGW prefix list is missing Entries")
                    for entry in entries:
                        if not isinstance(entry, dict) or not isinstance(entry.get("Cidr"), str):
                            raise NetworkAssertionError("TGW prefix list has an invalid CIDR")
                        networks.append(_network(entry["Cidr"], context="TGW prefix list"))
                prefix_lists[prefix] = networks
            networks = prefix_lists[prefix]
        else:
            raise NetworkAssertionError("TGW route has no destination")
        expanded.extend(
            _Route(network, route)
            for network in networks
            if network.version == requested.version and network.overlaps(requested)
        )
    return expanded


def _winner(candidates):
    longest = max(route.network.prefixlen for route in candidates)
    tied = [route for route in candidates if route.network.prefixlen == longest]
    if len(tied) > 1:
        priority = min(route.priority for route in tied)
        tied = [route for route in tied if route.priority == priority]
        identities = {(route.raw.get("State"), route.targets) for route in tied}
        if len(identities) != 1:
            raise UnsupportedCheckError(
                "Ambiguous equal-priority TGW routes; BGP ordering is unavailable"
            )
    return tied[0]


def check_tgw_routes(client, table_id: str, destination: str, *, via: str | None = None):
    requested = _requested_network(destination)
    _validate_via(via)
    if via is not None and re.fullmatch(r"tgw-attach-[A-Za-z0-9]+", via) is None:
        raise ValueError("via must be a TGW attachment ID")
    routes = _routes(client, table_id, requested)
    first, stop = int(requested.network_address), int(requested.broadcast_address) + 1
    boundaries = {first, stop}
    for route in routes:
        boundaries.update(
            (
                max(first, int(route.network.network_address)),
                min(stop, int(route.network.broadcast_address) + 1),
            )
        )
    ordered = sorted(boundaries)
    address_type = type(requested.network_address)
    evidence = {
        "route_table_id": table_id,
        "destination": str(requested),
        "via": via,
        "coverage": [],
        "routes": [route.raw for route in routes],
    }
    for start, end in zip(ordered, ordered[1:], strict=False):
        address = address_type(start)
        candidates = [route for route in routes if address in route.network]
        span = {"first": str(address), "last": str(address_type(end - 1))}
        if not candidates:
            evidence["counterexample"] = span
            return CheckResult(False, f"{table_id} has no route for {address}", evidence)
        winner = _winner(candidates)
        state = winner.raw.get("State")
        if state not in {"active", "blackhole"}:
            raise NetworkAssertionError(f"TGW route has unknown or transitional State {state!r}")
        span.update(prefix=str(winner.network), route=winner.raw)
        evidence["coverage"].append(span)
        if state == "blackhole":
            evidence["counterexample"] = span
            return CheckResult(False, f"{table_id} selects a blackhole for {address}", evidence)
        targets = winner.targets
        if not targets:
            raise NetworkAssertionError("Active TGW route has no next-hop attachments")
        if via is not None and any(target != via for target in targets):
            evidence["counterexample"] = span
            return CheckResult(
                False, f"{table_id} can select {targets}, expected only {via}", evidence
            )
    return CheckResult(True, f"{table_id} has active TGW routes covering {requested}", evidence)
