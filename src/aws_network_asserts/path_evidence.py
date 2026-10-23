"""Interpret reported RA components without inventing packet paths or diagnoses."""

import re
from collections.abc import Sequence
from typing import Any

from .accounts import validate_account_id
from .errors import AnalysisError, UnsupportedCheckError

_DESCRIPTIONS = {
    "ENI_SG_RULES_MISMATCH": "No security-group rule permits the selected traffic",
    "SG_HAS_NO_RULES": "The security group has no rules",
    "SUBNET_ACL_RESTRICTION": "The subnet's network ACL does not admit the selected traffic",
    "NO_ROUTE_TO_DESTINATION": "No applicable route leads to the destination",
    "BAD_STATE_ROUTE": "The selected route is not usable",
    "BAD_STATE": "The component is not operational",
    "DISCONNECTED_VPCS": "The VPCs have no supported connection",
    "TGW_ATTACH_MISSING_TGW_RTB_ASSOCIATION": "The TGW attachment has no valid table association",
    "TGW_RTB_NO_ROUTE_TO_TGW_ATTACHMENT": "The TGW table has no route to the attachment",
    "FIREWALL_RULES_RESTRICTION": "A matching Network Firewall rule blocks the traffic",
    "PROTOCOL_RESTRICTION": "The component does not accept the selected protocol",
}
_TRAFFIC_PREFIXES = {
    "network-interface": "eni-",
    "instance": "i-",
    "internet-gateway": "igw-",
    "transit-gateway": "tgw-",
    "transit-gateway-attachment": "tgw-attach-",
    "vpc-endpoint": "vpce-",
    "vpc-endpoint-service": "vpce-svc-",
    "vpc-peering-connection": "pcx-",
    "natgateway": "nat-",
    "vpn-gateway": "vgw-",
}
# Explanations also identify configuration objects, which are not traffic hops.
_EC2_PREFIXES = {
    **_TRAFFIC_PREFIXES,
    "network-acl": "acl-",
    "security-group": "sg-",
    "security-group-rule": "sgr-",
    "route-table": "rtb-",
    "subnet": "subnet-",
    "vpc": "vpc-",
    "transit-gateway-route-table": "tgw-rtb-",
    "prefix-list": "pl-",
    "customer-gateway": "cgw-",
    "vpn-connection": "vpn-",
}
_HOP_ID = re.compile(
    "(?:" + "|".join(re.escape(prefix) for prefix in _TRAFFIC_PREFIXES.values()) + r")[A-Za-z0-9]+"
)
_COMPONENT_ID = re.compile(
    "(?:" + "|".join(re.escape(prefix) for prefix in _EC2_PREFIXES.values()) + r")[A-Za-z0-9]+"
)
_INFORMATIONAL_DETAILS = {
    "AVAILABILITY_ZONE_CROSSED",
    "UNIDIRECTIONAL_PATH_ANALYSIS_ONLY",
    "RESPONSE_RTB_HAS_NO_ROUTE_TO_TRANSIT_GATEWAY",
    "TRANSIT_GATEWAY_APPLIANCE_MODE_RECOMMENDED",
}


def _ec2_resource(resource: str, prefixes: dict[str, str]) -> bool:
    resource_type, separator, resource_id = resource.partition("/")
    prefix = prefixes.get(resource_type)
    return bool(
        separator and prefix and re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]+", resource_id)
    )


def _service_resource(service: str, resource: str) -> bool:
    prefixes = {
        "network-firewall": ("firewall/",),
        "elasticloadbalancing": ("listener/", "loadbalancer/"),
    }.get(service, ())
    return resource.startswith(prefixes) and bool(
        re.fullmatch(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+", resource)
    )


def _identity(value: Any, *, strict: bool = False) -> set[str]:
    if not isinstance(value, dict):
        raise AnalysisError("RA component evidence must be an object")
    identities = set()
    for field in ("Id", "Arn"):
        if field in value:
            text = value[field]
            if not isinstance(text, str) or not text or any(char.isspace() for char in text):
                raise AnalysisError(f"RA component has an invalid {field}")
            identities.add(text)
            if field == "Arn":
                parts = text.split(":", 5)
                if (
                    len(parts) != 6
                    or parts[0] != "arn"
                    or not all(parts[1:])
                    or any(re.fullmatch(r"[a-z0-9-]+", part) is None for part in parts[1:4])
                ):
                    raise AnalysisError("RA component has an invalid ARN")
                try:
                    validate_account_id(parts[4])
                except ValueError as error:
                    raise AnalysisError("RA component ARN has no valid account") from error
                if parts[2] == "ec2" and not _ec2_resource(parts[5], _EC2_PREFIXES):
                    raise AnalysisError(
                        "RA component ARN resource type and ID disagree or are unsupported"
                    )
                if strict and parts[2] != "ec2" and not _service_resource(parts[2], parts[5]):
                    raise AnalysisError("RA forward path contains an unsupported component ARN")
    if not identities:
        raise AnalysisError("RA component has no resource ID or ARN")
    if value.get("Id") and value.get("Arn", "").startswith("arn:"):
        parts = value["Arn"].split(":", 5)
        if len(parts) != 6 or (parts[2] == "ec2" and _short(value["Arn"]) != value["Id"]):
            raise AnalysisError("RA component ID and ARN disagree")
        if strict and parts[2] != "ec2" and _COMPONENT_ID.fullmatch(value["Id"]):
            raise AnalysisError("RA component ID and ARN service disagree")
    if strict and "Arn" not in value and _COMPONENT_ID.fullmatch(value.get("Id", "")) is None:
        raise AnalysisError("RA forward path contains an unknown component identity")
    return identities


def _short(identifier: str) -> str:
    return (
        identifier.split(":", 5)[-1].rsplit("/", 1)[-1]
        if identifier.startswith("arn:")
        else identifier
    )


def _kind(identities: set[str]) -> tuple[str, str]:
    for value in identities:
        if value.startswith("arn:"):
            parts = value.split(":", 5)
            return parts[2], parts[5].split("/", 1)[0]
    identifier = next(iter(identities))
    for resource_type, prefix in _EC2_PREFIXES.items():
        if re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]+", identifier):
            return "ec2", resource_type
    raise AnalysisError("RA component has no recognized resource kind")


def validate_components(
    values: Sequence[str], label: str, region: str, *, partition: str | None = None
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError(f"{label} must be a sequence of resource IDs or ARNs")
    result = []
    for value in values:
        if not isinstance(value, str) or not value or any(char.isspace() for char in value):
            raise ValueError(f"{label} needs nonempty resource IDs or ARNs")
        if value.startswith("arn:"):
            parts = value.split(":", 5)
            if (
                len(parts) != 6
                or any(re.fullmatch(r"[a-z0-9-]+", part) is None for part in parts[1:4])
                or not parts[5]
            ):
                raise ValueError(f"Invalid component ARN: {value}")
            if parts[3] != region:
                raise ValueError("Path components must belong to the analysis region")
            if partition is not None and parts[1] != partition:
                raise ValueError("Path components must belong to the analysis partition")
            validate_account_id(parts[4])
            if not (
                (parts[2] == "ec2" and _ec2_resource(parts[5], _TRAFFIC_PREFIXES))
                or _service_resource(parts[2], parts[5])
            ):
                raise ValueError(
                    "Path constraints need traffic components, not configuration objects"
                )
        elif _HOP_ID.fullmatch(value) is None:
            raise ValueError(f"Unsupported component ID: {value}")
        if value in result:
            raise ValueError(f"{label} must not contain duplicate components")
        result.append(value)
    return tuple(result)


def _matches(requested: str, identities: set[str]) -> bool:
    if requested in identities:
        return True
    short = _short(requested)
    if requested.startswith("arn:"):
        if short in identities and not any(
            item.startswith("arn:") and _short(item) == short for item in identities
        ):
            raise AnalysisError("RA omitted ARN ownership needed to evaluate a path constraint")
        return False
    return any(
        item.startswith("arn:") and item.split(":", 5)[2] == "ec2" and _short(item) == short
        for item in identities
    )


def _appears(requested: str, resources: list[set[str]]) -> bool:
    # One exact reported ARN is sufficient evidence of presence. To prove its
    # absence, each occurrence of the same short ID needs its own ownership.
    if any(requested in identities for identities in resources):
        return True
    return any([_matches(requested, identities) for identities in resources])


def _check_details(component: dict[str, Any]) -> None:
    details = component.get("AdditionalDetails", [])
    if not isinstance(details, list) or any(
        not isinstance(detail, dict)
        or not isinstance(detail.get("AdditionalDetailType"), str)
        or detail.get("AdditionalDetailType") not in _INFORMATIONAL_DETAILS
        for detail in details
    ):
        raise AnalysisError("RA additional details leave modeled reachability unconfirmed")


def validate_additional_details(analysis: dict[str, Any]) -> None:
    """Do not promote ignored rules or omitted inspection into a conclusive answer."""
    for field in ("ForwardPathComponents", "ReturnPathComponents"):
        components = analysis.get(field, [])
        if not isinstance(components, list) or any(not isinstance(row, dict) for row in components):
            raise AnalysisError("RA path components must be a list of objects")
        for component in components:
            _check_details(component)


def forward_path_constraints(
    analysis: dict[str, Any],
    source: str,
    destination: str,
    through: tuple[str, ...],
    avoiding: tuple[str, ...],
    *,
    region: str,
    partition: str | None = None,
) -> dict[str, Any]:
    """Check reported forward hops only, requiring both resource boundary anchors."""
    if not analysis["NetworkPathFound"]:
        return {"passed": False, "evaluated": False, "reason": "No successful modeled path"}
    if analysis.get("WarningMessage"):
        raise AnalysisError("A warned analysis cannot establish complete path constraints")
    components = analysis.get("ForwardPathComponents")
    if not isinstance(components, list) or not components:
        raise AnalysisError("Path constraints require complete forward path components")
    positions = [item.get("SequenceNumber") for item in components if isinstance(item, dict)]
    if (
        len(positions) != len(components)
        or any(type(number) is not int or number < 0 for number in positions)
        or len(set(positions)) != len(positions)
        or min(positions) not in {0, 1}
        or sorted(positions) != list(range(min(positions), min(positions) + len(positions)))
    ):
        raise AnalysisError("RA forward path has missing, duplicate or incomplete sequence numbers")
    ordered = sorted(components, key=lambda item: item["SequenceNumber"])
    hops = []
    resources = []
    boundaries = []
    for item in ordered:
        reported = [_identity(item.get("Component"), strict=True)]
        component_kind = _kind(reported[0])
        boundary = list(reported)
        for field in ("AttachedTo", "TransitGateway", "ElasticLoadBalancerListener"):
            if field in item:
                reference = _identity(item[field], strict=True)
                kind = _kind(reference)
                if (
                    (field == "TransitGateway" and kind != ("ec2", "transit-gateway"))
                    or (
                        field == "ElasticLoadBalancerListener"
                        and kind != ("elasticloadbalancing", "listener")
                    )
                    or (field == "AttachedTo" and kind == ("ec2", "network-interface"))
                    or (
                        field == "AttachedTo"
                        and kind == ("ec2", "instance")
                        and component_kind != ("ec2", "network-interface")
                    )
                ):
                    raise AnalysisError(f"RA path has a contradictory {field} resource kind")
                reported.append(reference)
                if (
                    field == "AttachedTo"
                    and kind == ("ec2", "instance")
                    and component_kind == ("ec2", "network-interface")
                ) or (
                    field == "TransitGateway"
                    and component_kind == ("ec2", "transit-gateway-attachment")
                ):
                    boundary.append(reference)
        identities = set().union(*reported)
        if any(
            value.startswith("arn:") and value.split(":", 5)[3] != region for value in identities
        ):
            raise AnalysisError("RA forward path contains a component outside the analysis region")
        if partition is not None and any(
            value.startswith("arn:") and value.split(":", 5)[1] != partition for value in identities
        ):
            raise AnalysisError(
                "RA forward path contains a component outside the analysis partition"
            )
        if item.get("Explanations"):
            raise AnalysisError(
                "An explained/partial forward path cannot establish path constraints"
            )
        _check_details(item)
        hops.append(identities)
        resources.append(reported)
        boundaries.append(boundary)
    if analysis.get("Explanations"):
        raise AnalysisError("An explained analysis cannot establish complete path constraints")
    for expected, boundary in (
        (source, boundaries[0]),
        (destination, boundaries[-1]),
    ):
        if not _appears(expected, boundary):
            raise AnalysisError(
                "RA forward path does not confirm both requested endpoint boundaries"
            )
    # Keep each reported resource's ID and ARN together. Merging all identities
    # would let an ARN on another hop supply ownership for an ID-only component.
    identities = [identity for hop in resources for identity in hop]
    missing = [value for value in through if not _appears(value, identities)]
    forbidden = [value for value in avoiding if _appears(value, identities)]
    return {
        "direction": "forward",
        "evaluated": True,
        "passed": not missing and not forbidden,
        "through": list(through),
        "avoiding": list(avoiding),
        "missing": missing,
        "forbidden": forbidden,
        "components": [sorted(hop) for hop in hops],
    }


def blocker_summaries(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    """Keep AWS's explanation, direction and resource roles beside plain descriptions."""
    summaries = []

    def add(rows, path_direction, component=None):
        if not isinstance(rows, list):
            raise AnalysisError("RA explanations must be a list")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("ExplanationCode"), str):
                raise AnalysisError("RA explanation has no explanation code")
            code = row["ExplanationCode"]
            if not code:
                raise AnalysisError("RA explanation code must not be empty")
            resources = []
            for role, value in row.items():
                candidates = value if isinstance(value, list) else [value]
                for candidate in candidates:
                    if isinstance(candidate, dict) and ("Id" in candidate or "Arn" in candidate):
                        _identity(candidate)
                        resources.append({"role": role, **candidate})
            if not resources and component:
                resources.append({"role": "PathComponent", **component})
            summary = {
                "code": code,
                "description": _DESCRIPTIONS.get(code, f"AWS reported {code}"),
                "path_direction": path_direction,
                "direction": row.get("Direction", "unspecified"),
                "resources": resources,
                "reported": row,
            }
            summaries.append(summary)

    add(analysis.get("Explanations", []), "unspecified")
    for field, direction in (
        ("ForwardPathComponents", "forward"),
        ("ReturnPathComponents", "return"),
    ):
        if field not in analysis:
            continue
        rows = analysis[field]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise AnalysisError("RA path components must be a list of objects")
        for row in rows:
            add(row.get("Explanations", []), direction, row.get("Component"))
    return summaries


def require_resource_path(destination: str) -> None:
    if not destination.startswith("arn:") and not destination.startswith(
        ("eni-", "i-", "igw-", "tgw-", "vpce-", "pcx-", "vgw-")
    ):
        raise UnsupportedCheckError("Path constraints require an explicit resource destination")
