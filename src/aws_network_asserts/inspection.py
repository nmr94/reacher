"""Current inspection topology; these checks do not establish packet delivery."""

from __future__ import annotations

import re
from collections.abc import Mapping

from .builder import (
    _TGW_ATTACHMENT_STATES,
    RouteTableRule,
    SubnetRule,
    _id,
    _items,
    _one,
    _owner_id,
    _required_text,
    _state,
)
from .errors import NetworkAssertionError, _attach_evidence
from .result import CheckResult
from .routes import _requested_network, _validate_via


def check_appliance_mode(tgw, vpc_id: str) -> CheckResult:
    """Require an available VPC attachment with appliance mode explicitly enabled."""
    _id(vpc_id, "vpc-")
    if tgw.account_id is None:
        raise ValueError("Select the TGW owner's account before checking appliance mode")
    context = tgw._context()
    client, gateway = tgw._live_gateway()
    attachments = list(
        _items(
            client,
            "describe_transit_gateway_vpc_attachments",
            "TransitGatewayVpcAttachments",
            Filters=[
                {"Name": "transit-gateway-id", "Values": [tgw.resource_id]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ],
        )
    )
    available = []
    identifiers = set()
    for item in attachments:
        identifier = _required_text(item, "TransitGatewayAttachmentId", "VPC attachment")
        if (
            re.fullmatch(r"tgw-attach-[A-Za-z0-9]+", identifier) is None
            or identifier in identifiers
            or item.get("TransitGatewayId") != tgw.resource_id
            or item.get("VpcId") != vpc_id
        ):
            raise NetworkAssertionError("VPC attachment identity is contradictory or duplicated")
        identifiers.add(identifier)
        _owner_id(item, "VpcOwnerId", "VPC attachment")
        if _state(item, _TGW_ATTACHMENT_STATES, "VPC attachment") == "available":
            options = item.get("Options")
            mode = options.get("ApplianceModeSupport") if isinstance(options, dict) else None
            if mode not in {"enable", "disable"}:
                raise NetworkAssertionError("VPC attachment has no known appliance mode")
            available.append(item)
    if len(available) > 1:
        raise NetworkAssertionError("Multiple available attachments leave appliance mode ambiguous")
    passed = bool(available) and available[0]["Options"]["ApplianceModeSupport"] == "enable"
    return tgw._decorate(
        CheckResult(
            passed,
            f"{tgw.resource_id} {'has' if passed else 'has no'} available appliance-mode "
            f"attachment for {vpc_id}",
            {"transit_gateway": gateway, "attachments": attachments, "claim": "appliance_mode"},
        ),
        context,
    )


def validate_firewall_request(vpc, firewall_arn: str, subnets_by_az: Mapping[str, str]):
    if vpc.account_id is None:
        raise ValueError("Select the inspection VPC owner's account")
    partition = vpc.builder.clients.session.get_partition_for_region(vpc.region)
    pattern = (
        rf"arn:{re.escape(partition)}:network-firewall:{re.escape(vpc.region)}:"
        rf"{vpc.account_id}:firewall/[A-Za-z0-9-]+"
    )
    if not isinstance(firewall_arn, str) or re.fullmatch(pattern, firewall_arn) is None:
        raise ValueError("firewall_arn must identify a firewall in the selected account and region")
    if not isinstance(subnets_by_az, Mapping) or not subnets_by_az:
        raise ValueError("Declare a nonempty mapping of Availability Zones to firewall subnets")
    expected = dict(subnets_by_az)
    for zone, subnet in expected.items():
        if (
            not isinstance(zone, str)
            or not zone
            or any(char.isspace() or not char.isprintable() for char in zone)
        ):
            raise ValueError("Availability Zone names must be nonempty and contain no whitespace")
        _id(subnet, "subnet-")
    if len(set(expected.values())) != len(expected):
        raise ValueError("Each declared Availability Zone needs a distinct firewall subnet")
    return expected


def check_firewall_endpoints(
    vpc, firewall_arn: str, subnets_by_az: Mapping[str, str]
) -> CheckResult:
    """Require exactly the declared ready Network Firewall endpoints, placed by AZ."""
    expected = validate_firewall_request(vpc, firewall_arn, subnets_by_az)
    context = vpc._context()
    client = vpc.builder.ec2
    live_vpc = _one(
        list(_items(client, "describe_vpcs", "Vpcs", VpcIds=[vpc.resource_id])),
        "inspection VPC",
    )
    if live_vpc.get("VpcId") != vpc.resource_id:
        raise NetworkAssertionError("Inspection VPC identity does not match")
    vpc._check_owner(live_vpc)
    vpc_state = _state(live_vpc, {"pending", "available"}, "inspection VPC")
    subnets = list(
        _items(client, "describe_subnets", "Subnets", SubnetIds=sorted(expected.values()))
    )
    actual = {}
    for subnet in subnets:
        identifier = _required_text(subnet, "SubnetId", "firewall subnet")
        if identifier in actual or identifier not in expected.values():
            raise NetworkAssertionError("Firewall subnet response has unexpected/duplicate IDs")
        vpc._check_owner(subnet)
        if subnet.get("VpcId") != vpc.resource_id:
            raise NetworkAssertionError("Declared firewall subnet is outside the selected VPC")
        _required_text(subnet, "AvailabilityZone", "firewall subnet")
        _state(subnet, {"pending", "available"}, "firewall subnet")
        actual[identifier] = subnet
    if set(actual) != set(expected.values()):
        raise NetworkAssertionError("Some declared firewall subnets could not be verified")
    response = vpc.builder._live_client("network-firewall").describe_firewall(
        FirewallArn=firewall_arn
    )
    firewall, status = response.get("Firewall"), response.get("FirewallStatus")
    if not isinstance(firewall, dict) or not isinstance(status, dict):
        raise NetworkAssertionError("DescribeFirewall is missing firewall/status metadata")
    if firewall.get("FirewallArn") != firewall_arn:
        raise NetworkAssertionError("DescribeFirewall returned a contradictory firewall identity")
    _id(_required_text(firewall, "VpcId", "firewall"), "vpc-")
    state = _state(
        status, {"PROVISIONING", "DELETING", "READY", "FAILED"}, "firewall", key="Status"
    )
    sync = _state(
        status,
        {"PENDING", "IN_SYNC", "CAPACITY_CONSTRAINED"},
        "firewall",
        key="ConfigurationSyncStateSummary",
    )
    mappings = firewall.get("SubnetMappings")
    if not isinstance(mappings, list) or any(not isinstance(item, dict) for item in mappings):
        raise NetworkAssertionError("Firewall response is missing SubnetMappings")
    mapped = [_required_text(item, "SubnetId", "firewall mapping") for item in mappings]
    if len(set(mapped)) != len(mapped):
        raise NetworkAssertionError("Firewall has duplicate subnet mappings")
    sync_states = status.get("SyncStates")
    if not isinstance(sync_states, dict):
        raise NetworkAssertionError("Firewall response is missing AZ sync states")
    endpoints = {}
    for zone, item in sync_states.items():
        if not isinstance(zone, str) or not zone or not isinstance(item, dict):
            raise NetworkAssertionError("Firewall has malformed AZ sync states")
        attachment = item.get("Attachment")
        if not isinstance(attachment, dict):
            raise NetworkAssertionError("Firewall AZ sync state is missing its attachment")
        attachment_state = _state(
            attachment,
            {"CREATING", "DELETING", "FAILED", "ERROR", "SCALING", "READY"},
            "firewall endpoint",
            key="Status",
        )
        subnet_id = _required_text(attachment, "SubnetId", "firewall endpoint")
        if subnet_id not in mapped:
            raise NetworkAssertionError(
                "Firewall endpoint contradicts its declared subnet mappings"
            )
        if attachment_state == "READY":
            endpoint_id = _required_text(attachment, "EndpointId", "firewall endpoint")
            if re.fullmatch(r"vpce-[A-Za-z0-9]+", endpoint_id) is None:
                raise NetworkAssertionError("Firewall endpoint has an invalid endpoint ID")
        configuration = item.get("Config", {})
        if not isinstance(configuration, dict) or any(
            not isinstance(value, dict)
            or value.get("SyncStatus")
            not in {"PENDING", "IN_SYNC", "CAPACITY_CONSTRAINED", "NOT_SUBSCRIBED", "DEPRECATED"}
            for value in configuration.values()
        ):
            raise NetworkAssertionError("Firewall endpoint has malformed configuration sync status")
        endpoints[zone] = attachment
        if any(value["SyncStatus"] != "IN_SYNC" for value in configuration.values()):
            sync = "PENDING"
    ready_ids = [item.get("EndpointId") for item in endpoints.values() if item["Status"] == "READY"]
    if len(set(ready_ids)) != len(ready_ids):
        raise NetworkAssertionError("Firewall reports the same endpoint in multiple AZs")
    passed = (
        vpc_state == "available"
        and firewall["VpcId"] == vpc.resource_id
        and state == "READY"
        and sync == "IN_SYNC"
        and set(mapped) == set(expected.values())
        and set(endpoints) == set(expected)
        and all(
            actual[subnet]["State"] == "available"
            and actual[subnet]["AvailabilityZone"] == zone
            and endpoints.get(zone, {}).get("SubnetId") == subnet
            and endpoints.get(zone, {}).get("Status") == "READY"
            for zone, subnet in expected.items()
        )
    )
    return vpc._decorate(
        CheckResult(
            passed,
            f"{vpc.resource_id} firewall endpoints {'match' if passed else 'do not match'} "
            "the declared ready AZ/subnet layout",
            {
                "claim": "firewall_endpoint_placement",
                "expected_subnets_by_az": expected,
                "firewall": firewall,
                "firewall_status": status,
                "subnets": subnets,
                "vpc": live_vpc,
            },
        ),
        context,
    )


def paired_vpc_routes(subject, destination, *, source, return_table, via=None, return_via=None):
    """Two explicit effective route checks; this does not infer an entire path."""
    if not isinstance(return_table, (SubnetRule, RouteTableRule)):
        raise TypeError("return_table must be a subnet or VPC route-table selector")
    if return_table.region != subject.region:
        raise ValueError("Paired inspection routes must stay in one region")
    if _requested_network(source, "source").version != _requested_network(destination).version:
        raise ValueError("Forward and return route ranges must use the same address family")
    _validate_via(via)
    _validate_via(return_via)
    forward = subject.has_route_to(destination, via=via)
    try:
        reverse = return_table.has_route_to(source, via=return_via)
    except BaseException as error:
        _attach_evidence(
            error,
            {"claim": "paired_vpc_routes", "forward": forward, "return_evaluated": False},
            "paired_route_evidence",
        )
        raise
    return CheckResult(
        forward.passed and reverse.passed,
        f"Forward: {forward.message}; return: {reverse.message}",
        {"claim": "paired_vpc_routes", "forward": forward, "return": reverse},
    )
