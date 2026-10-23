"""Fluent selectors; terminal methods return truth-testable CheckResult values."""

from __future__ import annotations

import math
import re
from collections.abc import Iterator, Mapping, Sequence
from copy import copy
from dataclasses import asdict, dataclass, replace
from ipaddress import ip_address
from typing import Any, TypeVar

import boto3
from botocore.config import Config

from .accounts import AccountClients, validate_account_id
from .clients import AwsClients
from .errors import (
    ConfigResourceNotFoundError,
    NetworkAssertionError,
    ProbeError,
    ResourceNotFoundError,
    UnsupportedCheckError,
    WriteNotAllowedError,
    _attach_evidence,
)
from .inventory import ConfigInventory, ResourceSnapshot
from .path_evidence import require_resource_path, validate_components
from .probe import LambdaProbe
from .probe_role import TemporaryProbeRole
from .probe_security_group import TemporaryProbeSecurityGroup
from .probe_session import ProbeSession, one_shot
from .reachability import ReachabilityAnalyzer, qualify_endpoint
from .result import CheckResult
from .routes import _requested_network, _validate_via, check_routes
from .tgw_routes import check_tgw_routes

_Resource = TypeVar("_Resource", bound="ResourceRule")

_TGW_TABLE_STATES = {"pending", "available", "deleting", "deleted"}
_TGW_PROPAGATION_STATES = {"enabling", "enabled", "disabling", "disabled"}
_TGW_ATTACHMENT_STATES = {
    "initiating",
    "initiatingRequest",
    "pendingAcceptance",
    "rollingBack",
    "pending",
    "available",
    "modifying",
    "deleting",
    "deleted",
    "failed",
    "rejected",
    "rejecting",
    "failing",
}


def _id(value: str, prefix: str) -> str:
    if not isinstance(value, str) or not value.startswith(prefix) or len(value) <= len(prefix):
        raise ValueError(f"Expected a {prefix}... resource ID, received {value!r}")
    if any(char.isspace() for char in value) or "/" in value or ":" in value:
        raise ValueError(f"Expected a plain resource ID, received {value!r}")
    if prefix == "tgw-" and value.startswith(("tgw-rtb-", "tgw-attach-")):
        raise ValueError("Select the transit gateway ID (tgw-...), not its table or attachment")
    return value


def _items(client: Any, operation: str, key: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
    for page in client.get_paginator(operation).paginate(**kwargs):
        items = page.get(key)
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise NetworkAssertionError(
                f"{operation} response must contain a {key} list of objects"
            )
        yield from items


def _one(items: Sequence[dict[str, Any]], description: str) -> dict[str, Any]:
    if not items:
        raise ResourceNotFoundError(f"No {description} found")
    if len(items) != 1:
        raise NetworkAssertionError(f"Expected one {description}; received {len(items)}")
    return items[0]


def _required_text(item: dict[str, Any], key: str, description: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value:
        raise NetworkAssertionError(f"{description} response is missing a valid {key}")
    return value


def _owner_id(item: dict[str, Any], key: str, description: str) -> str:
    try:
        return validate_account_id(item.get(key))
    except ValueError as error:
        raise NetworkAssertionError(
            f"{description} response is missing a valid {key} account ID"
        ) from error


def _state(item: dict[str, Any], allowed: set[str], description: str, *, key: str = "State") -> str:
    value = _required_text(item, key, description)
    if value not in allowed:
        raise NetworkAssertionError(f"{description} response has an unknown {key} {value!r}")
    return value


class RuleBuilder:
    """Organization-scoped assertions with central inventory and analysis credentials.

    Config uses a central aggregator. Reachability Analyzer always uses the central
    session; account profiles are used for live topology and opt-in Lambda probes.
    ``required`` snapshots are the default. ``prefer`` permits absent records and
    ``off`` supports standalone/custom-endpoint checks without Config.
    """

    def __init__(
        self,
        *,
        region_name: str | None = None,
        session: boto3.Session | None = None,
        profile_name: str | None = None,
        config_session: boto3.Session | None = None,
        config_profile_name: str | None = None,
        account_profiles: Mapping[str, str] | None = None,
        account_sessions: Mapping[str, boto3.Session] | None = None,
        endpoint_url: str | None = None,
        endpoint_urls: Mapping[str, str] | None = None,
        boto_config: Config | None = None,
        verify: bool | str | None = None,
        config_mode: str = "required",
        config_aggregator: str | None = None,
        config_region: str | None = None,
        account_id: str | None = None,
        timeout: float = 120.0,
        poll_interval: float = 2.0,
        keep_analysis: bool = False,
        additional_accounts: Sequence[str] = (),
    ) -> None:
        if type(keep_analysis) is not bool:
            raise ValueError("keep_analysis must be a boolean")
        if config_mode not in {"prefer", "required", "off"}:
            raise ValueError("config_mode must be 'prefer', 'required', or 'off'")
        for label, profile in (
            ("profile_name", profile_name),
            ("config_profile_name", config_profile_name),
        ):
            if profile is not None and (not isinstance(profile, str) or not profile.strip()):
                raise ValueError(f"{label} must be a nonempty profile name")
        if session is not None and profile_name is not None:
            raise ValueError("Supply session or profile_name, not both")
        if config_session is not None and config_profile_name is not None:
            raise ValueError("Supply config_session or config_profile_name, not both")
        if config_mode != "off" and (not config_aggregator or not config_region):
            raise ValueError(
                "Organization checks require config_aggregator and config_region; "
                "use config_mode='off' explicitly for checks without AWS Config"
            )
        if account_id is not None:
            validate_account_id(account_id)
        for name, value in (("timeout", timeout), ("poll_interval", poll_interval)):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a positive finite number")
        if isinstance(additional_accounts, str):
            raise ValueError("additional_accounts must be a sequence of account IDs")
        additional_accounts = tuple(validate_account_id(value) for value in additional_accounts)
        if profile_name is not None:
            session = boto3.Session(profile_name=profile_name)
        self.clients = AwsClients(
            session=session,
            endpoint_url=endpoint_url,
            endpoint_urls=endpoint_urls,
            boto_config=boto_config,
            verify=verify,
        )
        self.region_name = region_name or self.clients.region_name
        if not self.region_name:
            raise ValueError("Set region_name or configure a region on your boto3 session")
        if config_profile_name is not None:
            config_session = boto3.Session(profile_name=config_profile_name)
        self.config_clients = (
            self.clients
            if config_session is None
            else AwsClients(
                session=config_session,
                endpoint_url=endpoint_url,
                endpoint_urls=endpoint_urls,
                boto_config=boto_config,
                verify=verify,
            )
        )
        self._accounts = AccountClients(
            self.clients, account_profiles=account_profiles, account_sessions=account_sessions
        )
        self.account_id = account_id
        self.config_aggregator = config_aggregator
        self.config_region = config_region
        self.inventory = ConfigInventory(
            self.config_clients,
            aggregator_name=config_aggregator,
            aggregator_region=config_region,
            account_id=account_id,
        )
        self.config_mode = config_mode
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.keep_analysis = keep_analysis
        self.additional_accounts = tuple(additional_accounts)

    def in_region(self, region_name: str) -> RuleBuilder:
        """Return a region-scoped view without changing this builder or its selectors."""
        if not isinstance(region_name, str) or not region_name.strip():
            raise ValueError("region_name must be a nonempty string")
        scoped = copy(self)
        scoped.region_name = region_name
        return scoped

    def in_account(self, account_id: str) -> RuleBuilder:
        """Select resource ownership without changing central Config or RA credentials."""
        scoped = copy(self)
        scoped.account_id = validate_account_id(account_id)
        scoped.inventory = self.inventory.in_account(account_id)
        return scoped

    @property
    def ec2(self) -> Any:
        """Live topology client, using credentials verified for the selected account."""
        return self._live_client("ec2")

    def _live_client(self, service: str) -> Any:
        """Share account verification and transport settings across live services."""
        if self.account_id is not None:
            return self._accounts.client(service, self.region_name, self.account_id)
        if self.config_mode != "off":
            raise NetworkAssertionError(
                "Select a resource account with in_account() or account_id before live checks"
            )
        return self.clients.client(service, self.region_name)

    @property
    def analysis_ec2(self) -> Any:
        """Central management/delegated-admin client for the complete RA lifecycle."""
        return self.clients.client("ec2", self.region_name)

    def eni(self, resource_id: str) -> EniRule:
        return EniRule(self, _id(resource_id, "eni-"), "AWS::EC2::NetworkInterface")

    def instance(self, resource_id: str) -> EndpointRule:
        return EndpointRule(self, _id(resource_id, "i-"), "AWS::EC2::Instance")

    def subnet(self, resource_id: str) -> SubnetRule:
        return SubnetRule(self, _id(resource_id, "subnet-"), "AWS::EC2::Subnet")

    def route_table(self, resource_id: str) -> RouteTableRule:
        return RouteTableRule(self, _id(resource_id, "rtb-"), "AWS::EC2::RouteTable")

    def vpc(self, resource_id: str) -> VpcRule:
        return VpcRule(self, _id(resource_id, "vpc-"), "AWS::EC2::VPC")

    def tgw(self, resource_id: str) -> TransitGatewayRule:
        return TransitGatewayRule(self, _id(resource_id, "tgw-"), "AWS::EC2::TransitGateway")

    def resource(self, resource_id_or_arn: str) -> EndpointRule:
        """Other RA endpoints, including ARNs; no automatic Config type inference."""
        if not isinstance(resource_id_or_arn, str) or not resource_id_or_arn:
            raise ValueError("A resource ID or ARN is required")
        return EndpointRule(self, resource_id_or_arn, None)

    def resource_ids(self, resource_type: str) -> list[str]:
        """Discover recorded IDs in the selected account and resource region."""
        self._require_config()
        return self.inventory.resource_ids(resource_type, self.region_name)

    def _require_config(self) -> None:
        if self.config_mode == "off":
            raise UnsupportedCheckError("This operation requires AWS Config; config_mode is 'off'")

    def _analyzer(self) -> ReachabilityAnalyzer:
        return ReachabilityAnalyzer(
            self.analysis_ec2,
            timeout=self.timeout,
            poll_interval=self.poll_interval,
            keep_analysis=self.keep_analysis,
        )


@dataclass(frozen=True)
class ResourceRule:
    builder: RuleBuilder
    resource_id: str
    config_type: str | None
    label: str | None = None

    def named(self: _Resource, label: str) -> _Resource:
        """Give a selector a human name without changing its ownership or identity."""
        if (
            not isinstance(label, str)
            or not label.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in label)
        ):
            raise ValueError("A resource name must be nonempty text without control characters")
        return replace(self, label=label.strip())

    @property
    def region(self) -> str:
        return self.builder.region_name

    @property
    def account_id(self) -> str | None:
        return self.builder.account_id

    def __bool__(self) -> bool:
        raise TypeError("A resource selector is not an assertion; call a terminal check method")

    def _check_owner(self, item: dict[str, Any], key: str = "OwnerId") -> None:
        if self.account_id is None:
            return
        owner = _owner_id(item, key, self.resource_id)
        if owner != self.account_id:
            raise NetworkAssertionError(
                f"{self.resource_id} has {key}={owner}; expected selected account {self.account_id}"
            )

    def config_snapshot(self) -> ResourceSnapshot:
        self.builder._require_config()
        if self.config_type is None:
            raise UnsupportedCheckError("Use a typed selector such as eni() for Config snapshots")
        return self.builder.inventory.get(self.config_type, self.resource_id, self.region)

    def is_recorded(self) -> CheckResult:
        """Whether Config has a usable snapshot, not whether a resource exists live."""
        try:
            snapshot = self.config_snapshot()
        except ConfigResourceNotFoundError as exc:
            return CheckResult(False, str(exc), {"resource_id": self.resource_id})
        return CheckResult(
            True,
            f"{self.resource_id} is recorded in AWS Config "
            f"({snapshot.account_id}/{self.region}, {snapshot.captured_at})",
            {"config": asdict(snapshot)},
        )

    def has_config_tag(self, key: str, value: str) -> CheckResult:
        """Compare a recorded tag explicitly; current EC2 tags may have changed."""
        if not isinstance(key, str) or not key or not isinstance(value, str):
            raise ValueError("Tag key must be a nonempty string and tag value must be a string")
        snapshot = self.config_snapshot()
        actual = snapshot.tags.get(key)
        return CheckResult(
            key in snapshot.tags and actual == value,
            f"Config tag {key!r} on {self.resource_id}: expected {value!r}, recorded {actual!r}",
            {"config": asdict(snapshot)},
        )

    def _context(self) -> dict[str, Any]:
        context: dict[str, Any] = {
            "region": self.region,
            "account_id": self.account_id,
            "resource_id": self.resource_id,
        }
        if self.label is not None:
            context["resource_name"] = self.label
        if self.builder.config_mode == "off":
            return context
        if self.config_type is None:
            if self.builder.config_mode == "required":
                raise UnsupportedCheckError(
                    "config_mode='required' needs a typed selector; use eni(), instance(), or tgw()"
                )
            context["config_unavailable"] = "Generic resource() has no inferred Config type"
            return context
        try:
            context["config"] = asdict(self.config_snapshot())
        except ConfigResourceNotFoundError as exc:
            if self.builder.config_mode == "required":
                raise
            context["config_unavailable"] = str(exc)
        return context

    def _decorate(self, result: CheckResult, context: dict[str, Any]) -> CheckResult:
        name = f"{self.label}: " if self.label is not None else ""
        identity = {"resource_name": self.label} if self.label is not None else {}
        return CheckResult(
            result.passed,
            f"[{self.account_id + '/' if self.account_id else ''}{self.region}] "
            f"{name}{result.message}",
            {**result.evidence, **context, **identity},
        )


@dataclass(frozen=True)
class EndpointRule(ResourceRule):
    def can_reach(
        self,
        destination: str | EndpointRule,
        *,
        protocol: str = "tcp",
        port: int | None = 443,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        source_port: int | None = None,
        through: Sequence[str] = (),
        avoiding: Sequence[str] = (),
    ) -> CheckResult:
        return self._reach(
            destination,
            True,
            protocol,
            port,
            source_ip,
            destination_ip,
            source_port,
            through,
            avoiding,
        )

    def cannot_reach(
        self,
        destination: str | EndpointRule,
        *,
        protocol: str = "tcp",
        port: int | None = 443,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        source_port: int | None = None,
        through: Sequence[str] = (),
        avoiding: Sequence[str] = (),
    ) -> CheckResult:
        return self._reach(
            destination,
            False,
            protocol,
            port,
            source_ip,
            destination_ip,
            source_port,
            through,
            avoiding,
        )

    def _reach(
        self,
        destination: str | EndpointRule,
        expected: bool,
        protocol: str,
        port: int | None,
        source_ip: str | None,
        destination_ip: str | None,
        source_port: int | None,
        through: Sequence[str],
        avoiding: Sequence[str],
    ) -> CheckResult:
        partition = self.builder.clients.session.get_partition_for_region(self.region)
        through = validate_components(through, "through", self.region, partition=partition)
        avoiding = validate_components(avoiding, "avoiding", self.region, partition=partition)
        if set(through) & set(avoiding):
            raise ValueError("A component cannot be both required and forbidden")
        if not expected and (through or avoiding):
            raise ValueError("Path constraints belong to positive can_reach() checks")
        destination_account = self.account_id
        destination_name = None
        if isinstance(destination, ResourceRule):
            if not isinstance(destination, EndpointRule):
                raise UnsupportedCheckError("Use an ENI or other RA endpoint, not a subnet or VPC")
            if destination.region != self.region:
                raise UnsupportedCheckError(
                    "A single Reachability Analyzer analysis must stay in one region. "
                    "Use regional checks plus cross-region route/peering assertions."
                )
            if (
                destination.account_id is None
                and not destination.resource_id.startswith("arn:")
                and self.builder.config_mode != "off"
            ):
                raise ValueError(
                    "Select the destination account with in_account() or account_id; "
                    "a bare destination string instead uses the source account"
                )
            destination_account = destination.account_id
            destination_name = destination.label
            destination = destination.resource_id
        elif isinstance(destination, str) and destination.startswith("arn:"):
            # An explicit destination ARN can name another account in the organization.
            destination_account = None
        source = qualify_endpoint(
            self.resource_id,
            account_id=self.account_id,
            region=self.region,
            partition=partition,
        )
        target = qualify_endpoint(
            destination,
            account_id=destination_account,
            region=self.region,
            partition=partition,
            allow_ip=True,
        )
        if through or avoiding:
            require_resource_path(target)
        context = self._context()
        if destination_name is not None:
            context["destination_name"] = destination_name
        if target.startswith("arn:"):
            context["destination_account_id"] = target.split(":", 5)[4]
        constraints = {}
        if through:
            constraints["through"] = through
        if avoiding:
            constraints["avoiding"] = avoiding
        result = self.builder._analyzer().check(
            source,
            target,
            protocol=protocol,
            port=port,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            expect_reachable=expected,
            additional_accounts=self.builder.additional_accounts,
            **constraints,
        )
        return self._decorate(result, context)

    def probe_session(
        self, *, network_interface_id: str | None = None, **options: Any
    ) -> ProbeSession:
        """Probe from a verified workload's subnet/groups using a temporary Lambda.

        Source discovery happens when entering the context, after the explicit
        write gate. The Lambda never executes inside the instance or reuses its
        network interface. Select an ENI explicitly for multi-interface instances.
        """
        return _WorkloadProbeSession(self, network_interface_id=network_interface_id, **options)

    def ssm_probe_session(self, **options: Any):
        """Run explicitly authorized protocol checks in a managed Linux instance."""
        if self.config_type != "AWS::EC2::Instance":
            raise UnsupportedCheckError("SSM probes require an instance() selector")
        from .ssm_probe import SsmProbeSession

        return SsmProbeSession(self, **options)


@dataclass(frozen=True)
class EniRule(EndpointRule):
    def _live(self) -> dict[str, Any]:
        response = self.builder.ec2.describe_network_interfaces(
            NetworkInterfaceIds=[self.resource_id]
        )
        interface = _one(response["NetworkInterfaces"], f"network interface {self.resource_id}")
        self._check_owner(interface)
        return interface

    def in_subnet(self, subnet_id: str) -> CheckResult:
        return self._field("SubnetId", _id(subnet_id, "subnet-"))

    def in_vpc(self, vpc_id: str) -> CheckResult:
        return self._field("VpcId", _id(vpc_id, "vpc-"))

    def _field(self, key: str, expected: str) -> CheckResult:
        context = self._context()
        live = self._live()
        if key not in live:
            raise NetworkAssertionError(f"Network interface response is missing {key}")
        return self._decorate(
            CheckResult(
                live[key] == expected,
                f"{self.resource_id} {key}: expected {expected}, observed {live[key]}",
                {"network_interface": live},
            ),
            context,
        )


@dataclass(frozen=True)
class SubnetRule(ResourceRule):
    def probe_tcp(
        self,
        host: str,
        *,
        execution_role_arn: str | None = None,
        auto_create_execution_role: bool = False,
        security_group_ids: Sequence[str] | None = None,
        auto_create_security_group: bool = False,
        allow_write: bool = False,
        port: int = 443,
        connect_timeout: float = 3.0,
        ready_timeout: float = 300.0,
        role_cleanup_timeout: float = 1200.0,
        security_group_cleanup_timeout: float = 1200.0,
        address_mode: str = "first",
        attempts: int = 1,
        successes_required: int | None = None,
        interval: float = 0,
        max_latency_ms: float | None = None,
        source_kind: str = "synthetic",
        expected_source_cidrs: Sequence[str] = (),
        expected_addresses: Sequence[str] | None = None,
        allowed_destination_cidrs: Sequence[str] = (),
        address_family: str = "ipv4",
        cleanup_manifest=None,
    ) -> CheckResult:
        """Deploy, invoke and delete a Lambda for one observed IPv4 TCP handshake.

        Requires ``allow_write=True`` on this call, a selected account, an existing
        execution role in that account (or ``auto_create_execution_role=True``)
        and explicit security groups (or ``auto_create_security_group=True``).
        A failed connection is not proof of isolation. DNS/deployment/execution
        failures raise. The source is the Lambda, not an existing workload's ENI.
        """
        options = dict(
            execution_role_arn=execution_role_arn,
            auto_create_execution_role=auto_create_execution_role,
            security_group_ids=security_group_ids,
            auto_create_security_group=auto_create_security_group,
            allow_write=allow_write,
            ready_timeout=ready_timeout,
            role_cleanup_timeout=role_cleanup_timeout,
            security_group_cleanup_timeout=security_group_cleanup_timeout,
            address_family=address_family,
            cleanup_manifest=cleanup_manifest,
        )
        if (
            address_mode != "first"
            or attempts != 1
            or successes_required is not None
            or interval != 0
            or max_latency_ms is not None
            or source_kind != "synthetic"
            or expected_source_cidrs
            or not isinstance(expected_source_cidrs, (list, tuple))
            or expected_addresses is not None
            or allowed_destination_cidrs
            or not isinstance(allowed_destination_cidrs, (list, tuple))
            or address_family != "ipv4"
        ):
            return one_shot(
                self,
                "tcp",
                host,
                {
                    **options,
                    "port": port,
                    "connect_timeout": connect_timeout,
                    "address_mode": address_mode,
                    "attempts": attempts,
                    "successes_required": successes_required,
                    "interval": interval,
                    "max_latency_ms": max_latency_ms,
                    "source_kind": source_kind,
                    "expected_source_cidrs": expected_source_cidrs,
                    "expected_addresses": expected_addresses,
                    "allowed_destination_cidrs": allowed_destination_cidrs,
                },
            )
        probe = self._validate_probe(host, port=port, connect_timeout=connect_timeout, **options)
        ProbeSession._prepare(
            "tcp",
            host,
            port=port,
            connect_timeout=connect_timeout,
            address_mode=address_mode,
            attempts=attempts,
            successes_required=successes_required,
            interval=interval,
            max_latency_ms=max_latency_ms,
        )
        client, role, security_group, context = self._probe_resources(**options)
        result = self._decorate(
            probe.check(
                client,
                self.resource_id,
                poll_interval=self.builder.poll_interval,
                role=role,
                security_group=security_group,
            ),
            context,
        )

        result.evidence["source_context"] = {
            "kind": "synthetic",
            "account_id": self.account_id,
            "region": self.region,
            "subnet_id": self.resource_id,
            "security_group_ids": result.evidence["security_group_ids"],
            "security_group_mode": "automatic" if auto_create_security_group else "supplied",
            "host_firewall_tested": False,
        }
        result.evidence.update(kind="tcp", target=host)
        return result

    def probe_session(self, **options: Any) -> ProbeSession:
        """Authorise one temporary deployment for several checks in a with block."""
        return ProbeSession(self, **options)

    def probe_tls(self, host: str, **options: Any) -> CheckResult:
        """Verify a real TLS handshake, trust chain and server hostname."""
        return one_shot(self, "tls", host, options)

    def probe_http(self, url: str, **options: Any) -> CheckResult:
        """GET/HEAD an exact HTTP(S) URL without following redirects."""
        return one_shot(self, "http", url, options)

    def probe_dns(self, host: str, **options: Any) -> CheckResult:
        """Assert resolved IPv4 addresses inside the VPC against explicit expectations."""
        return one_shot(self, "dns", host, options)

    def _validate_probe(
        self,
        host: str,
        *,
        port: int = 443,
        connect_timeout: float = 3.0,
        execution_role_arn: str | None = None,
        auto_create_execution_role: bool = False,
        security_group_ids: Sequence[str] | None = None,
        auto_create_security_group: bool = False,
        allow_write: bool = False,
        ready_timeout: float = 300.0,
        role_cleanup_timeout: float = 1200.0,
        security_group_cleanup_timeout: float = 1200.0,
        address_family: str = "ipv4",
        cleanup_manifest=None,
    ) -> LambdaProbe:
        if allow_write is not True:
            raise WriteNotAllowedError("Lambda probes require allow_write=True on this test call")
        if self.account_id is None:
            raise ValueError("Select the Lambda account with in_account() or account_id")
        if type(auto_create_execution_role) is not bool:
            raise ValueError("auto_create_execution_role must be a boolean")
        if type(auto_create_security_group) is not bool:
            raise ValueError("auto_create_security_group must be a boolean")
        if (auto_create_execution_role and execution_role_arn is not None) or (
            not auto_create_execution_role and execution_role_arn is None
        ):
            raise ValueError(
                "Supply execution_role_arn or auto_create_execution_role=True, not both"
            )
        if (auto_create_security_group and security_group_ids is not None) or (
            not auto_create_security_group and security_group_ids is None
        ):
            raise ValueError(
                "Supply security_group_ids or auto_create_security_group=True, not both"
            )
        for label, value in (
            ("role_cleanup_timeout", role_cleanup_timeout),
            ("security_group_cleanup_timeout", security_group_cleanup_timeout),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{label} must be a positive finite number")
        partition = self.builder.clients.session.get_partition_for_region(self.region)
        role_pattern = rf"arn:{re.escape(partition)}:iam::{self.account_id}:role/[^\s:]+"
        if not auto_create_execution_role and (
            not isinstance(execution_role_arn, str)
            or re.fullmatch(role_pattern, execution_role_arn) is None
        ):
            raise ValueError(
                "execution_role_arn must be an IAM role ARN in the selected account/partition"
            )
        return LambdaProbe(
            host,
            port,
            execution_role_arn,
            security_group_ids,
            connect_timeout,
            ready_timeout,
            address_family=address_family,
            cleanup_manifest=cleanup_manifest,
            account_id=self.account_id,
        )

    def _probe_resources(
        self,
        *,
        execution_role_arn=None,
        auto_create_execution_role=False,
        security_group_ids=None,
        auto_create_security_group=False,
        allow_write=False,
        ready_timeout=300.0,
        role_cleanup_timeout=1200.0,
        security_group_cleanup_timeout=1200.0,
        address_family="ipv4",
        cleanup_manifest=None,
    ):
        partition = self.builder.clients.session.get_partition_for_region(self.region)
        context = self._context()
        client = self.builder._live_client("lambda")
        security_group = None
        if auto_create_security_group:
            security_group = TemporaryProbeSecurityGroup(
                self.builder.ec2,
                account_id=self.account_id,
                timeout=security_group_cleanup_timeout,
                poll_interval=self.builder.poll_interval,
            )
        role = None
        if auto_create_execution_role:
            role = TemporaryProbeRole(
                self.builder._live_client("iam"),
                self.builder.ec2,
                account_id=self.account_id,
                partition=partition,
                timeout=role_cleanup_timeout,
                poll_interval=self.builder.poll_interval,
            )
        return client, role, security_group, context

    def has_route_to(self, destination: str, *, via: str | None = None) -> CheckResult:
        _requested_network(destination)
        _validate_via(via)

        def identifier(item, key, prefix, description):
            value = _required_text(item, key, description)
            if re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]+", value) is None:
                raise NetworkAssertionError(f"{description} has an invalid {key}")
            return value

        context = self._context()
        client = self.builder.ec2
        tables = list(
            _items(
                client,
                "describe_route_tables",
                "RouteTables",
                Filters=[{"Name": "association.subnet-id", "Values": [self.resource_id]}],
            )
        )
        association = "explicit"
        vpc_id = None
        if not tables:
            subnet = _one(
                list(_items(client, "describe_subnets", "Subnets", SubnetIds=[self.resource_id])),
                f"subnet {self.resource_id}",
            )
            self._check_owner(subnet)
            if identifier(subnet, "SubnetId", "subnet-", "Live subnet") != self.resource_id:
                raise NetworkAssertionError(
                    "Live subnet identity does not match the selected subnet"
                )
            vpc_id = identifier(subnet, "VpcId", "vpc-", "Live subnet")
            if _state(subnet, {"pending", "available"}, "Live subnet") != "available":
                raise NetworkAssertionError(
                    "Live subnet is not available for effective route selection"
                )
            tables = list(
                _items(
                    client,
                    "describe_route_tables",
                    "RouteTables",
                    Filters=[
                        {"Name": "vpc-id", "Values": [vpc_id]},
                        {"Name": "association.main", "Values": ["true"]},
                    ],
                )
            )
            association = "main"
        table = _one(tables, f"effective route table for {self.resource_id}")
        self._check_owner(table)
        table_id = identifier(table, "RouteTableId", "rtb-", "Effective route table")
        table_vpc = identifier(table, "VpcId", "vpc-", "Effective route table")
        if vpc_id is not None and table_vpc != vpc_id:
            raise NetworkAssertionError("Main route table belongs to a different live subnet VPC")
        rows = table.get("Associations")
        if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
            raise NetworkAssertionError("Effective route table has no complete Associations list")
        matching = []
        seen = set()
        for row in rows:
            association_id = identifier(
                row, "RouteTableAssociationId", "rtbassoc-", "Route association"
            )
            if association_id in seen:
                raise NetworkAssertionError(
                    "Effective route table has duplicate route association identities"
                )
            seen.add(association_id)
            if row.get("RouteTableId") != table_id or type(row.get("Main")) is not bool:
                raise NetworkAssertionError(
                    "Route association table identity or Main flag is contradictory"
                )
            if row["Main"] and (
                row.get("SubnetId") is not None or row.get("GatewayId") is not None
            ):
                raise NetworkAssertionError(
                    "Main route association cannot name a subnet or gateway"
                )
            if not row["Main"] and (row.get("SubnetId") is not None) == (
                row.get("GatewayId") is not None
            ):
                raise NetworkAssertionError(
                    "Non-main route association must name exactly one subnet or gateway"
                )
            if row.get("SubnetId") is not None:
                identifier(row, "SubnetId", "subnet-", "Route association")
            if (
                row.get("GatewayId") is not None
                and re.fullmatch(r"(?:igw|vgw)-[A-Za-z0-9]+", row["GatewayId"]) is None
            ):
                raise NetworkAssertionError("Route association has an invalid GatewayId")
            state = row.get("AssociationState")
            if not isinstance(state, dict):
                raise NetworkAssertionError("Route association is missing AssociationState")
            status = _state(
                state,
                {"associating", "associated", "disassociating", "disassociated", "failed"},
                "Route association",
            )
            selected = (
                row["Main"] if association == "main" else row.get("SubnetId") == self.resource_id
            )
            if selected:
                if status != "associated":
                    raise NetworkAssertionError(
                        "Selected route association is not actively associated"
                    )
                matching.append(row)
        if len(matching) != 1:
            raise NetworkAssertionError(
                "Effective route table does not confirm one matching active association"
            )
        context.update(
            {
                "subnet_id": self.resource_id,
                "vpc_id": table_vpc,
                "association": association,
                "route_table_association": matching[0],
            }
        )
        return self._decorate(check_routes(client, table, destination, via=via), context)

    def has_bidirectional_routes(
        self, destination: str, *, source: str, return_table, via=None, return_via=None
    ) -> CheckResult:
        """Check effective routes in both explicitly selected subnet/table contexts."""
        from .inspection import paired_vpc_routes

        return paired_vpc_routes(
            self,
            destination,
            source=source,
            return_table=return_table,
            via=via,
            return_via=return_via,
        )

    def enis(self) -> list[EniRule]:
        """List live ENIs, preserving ownership for account-scoped builders.

        Shared subnets can contain participant-owned ENIs. Callers choose which
        ENIs to test; an empty list proves nothing.
        """
        interfaces = []
        for item in _items(
            self.builder.ec2,
            "describe_network_interfaces",
            "NetworkInterfaces",
            Filters=[{"Name": "subnet-id", "Values": [self.resource_id]}],
        ):
            builder = self.builder
            if self.account_id is not None:
                owner = _owner_id(item, "OwnerId", "Network interface")
                builder = builder.in_account(owner)
            interfaces.append(builder.eni(item["NetworkInterfaceId"]))
        return interfaces


class _WorkloadProbeSession(ProbeSession):
    """Resolve a workload once per deployment, then use the ordinary probe lifecycle."""

    def __init__(self, workload: EndpointRule, *, network_interface_id=None, **options):
        if options.get("allow_write") is not True:
            raise WriteNotAllowedError("Lambda probes require allow_write=True on this test call")
        if workload.account_id is None:
            raise ValueError("Select the Lambda account with in_account() or account_id")
        if workload.config_type not in {"AWS::EC2::Instance", "AWS::EC2::NetworkInterface"}:
            raise UnsupportedCheckError("Derive probe settings with eni() or instance()")
        if network_interface_id is not None:
            _id(network_interface_id, "eni-")
            if workload.config_type != "AWS::EC2::Instance":
                raise ValueError("network_interface_id selects an interface of an instance()")
        if "security_group_ids" in options or options.get("auto_create_security_group"):
            raise ValueError(
                "Workload probes derive their exact security groups; omit group options"
            )
        if options.pop("source_kind", "workload_representative") != "workload_representative":
            raise ValueError("A derived workload probe uses source_kind='workload_representative'")
        self.workload = workload
        self.network_interface_id = network_interface_id
        self._source_used = False
        self._source_workload = {
            "resource_id": workload.resource_id,
            "account_id": workload.account_id,
            "region": workload.region,
            "host_firewall_tested": False,
        }
        if workload.label is not None:
            self._source_workload["resource_name"] = workload.label
        # Validate role, write and deployment options before any discovery calls.
        # The real groups replace this placeholder after ENI ownership is verified.
        super().__init__(
            workload.builder.subnet("subnet-derived"),
            source_kind="workload_representative",
            security_group_ids=["sg-derived"],
            **options,
        )
        self._source_workload["address_family"] = self.address_family

    def __enter__(self):
        if self._source_used:
            raise RuntimeError("A probe session cannot be entered more than once")
        self._source_used = True
        try:
            self._source_workload.update(self.workload._context())
            interface_id = (
                self._instance_interface()
                if (self.workload.config_type == "AWS::EC2::Instance")
                else self.workload.resource_id
            )
            geometry = self._live_interface(interface_id)
            self._source_workload.update(geometry)
            self.selector = self.workload.builder.subnet(geometry["subnet_id"])
            if self.workload.label is not None:
                self.selector = self.selector.named(self.workload.label)
            groups = geometry["security_group_ids"]
            self.options["security_group_ids"] = groups
            self._settings = replace(self._settings, security_group_ids=tuple(groups))
            entered = super().__enter__()
            self.evidence["source_workload"] = dict(self._source_workload)
            return entered
        except BaseException as error:
            self._attach_source(error)
            raise

    def _attach_source(self, error):
        evidence = getattr(error, "evidence", None)
        if evidence is self._source_workload or evidence is self.evidence:
            evidence = dict(evidence)
            _attach_evidence(error, evidence)
        if not isinstance(evidence, dict):
            evidence = {}
            _attach_evidence(error, evidence)
        evidence.setdefault("source_workload", dict(self._source_workload))
        evidence.setdefault("deployment", self.evidence)
        if self._active:
            # The lifecycle attaches its final deployment evidence to the error.
            # Retain the source failure there without a circular deployment link.
            self.evidence["source_workload"] = dict(self._source_workload)
            self.evidence["failed_source_check"] = {
                key: value for key, value in evidence.items() if key != "deployment"
            }

    def _live_interface(self, interface_id, *, address_family=None):
        interface = _one(
            list(
                _items(
                    self.workload.builder.ec2,
                    "describe_network_interfaces",
                    "NetworkInterfaces",
                    NetworkInterfaceIds=[interface_id],
                )
            ),
            f"workload interface {interface_id}",
        )
        self.workload._check_owner(interface)
        if interface.get("NetworkInterfaceId") != interface_id:
            raise ProbeError(
                "Workload interface identity does not match", dict(self._source_workload)
            )
        if interface.get("Status") != "in-use":
            raise ProbeError("Workload interface must be in-use", dict(self._source_workload))
        if self.workload.config_type == "AWS::EC2::Instance":
            attachment = interface.get("Attachment", {})
            if (
                not isinstance(attachment, dict)
                or attachment.get("InstanceId") != self.workload.resource_id
                or attachment.get("Status") != "attached"
                or (
                    "InstanceOwnerId" in attachment
                    and attachment["InstanceOwnerId"] != self.workload.account_id
                )
            ):
                raise ProbeError(
                    "Workload interface is not attached to the selected instance",
                    dict(self._source_workload),
                )
        subnet_id = _id(_required_text(interface, "SubnetId", "Workload ENI"), "subnet-")
        vpc_id = _id(_required_text(interface, "VpcId", "Workload ENI"), "vpc-")
        zone = _required_text(interface, "AvailabilityZone", "Workload ENI")
        groups = interface.get("Groups")
        if (
            not isinstance(groups, list)
            or not 1 <= len(groups) <= 5
            or any(not isinstance(group, dict) for group in groups)
        ):
            raise ProbeError(
                "Workload ENI needs one to five security groups", dict(self._source_workload)
            )
        group_ids = [
            _id(_required_text(group, "GroupId", "Workload group"), "sg-") for group in groups
        ]
        if len(set(group_ids)) != len(group_ids):
            raise ProbeError(
                "Workload ENI has duplicate security groups", dict(self._source_workload)
            )
        group_ids.sort()
        addresses = self._interface_addresses(interface)
        family = self.address_family if address_family is None else address_family
        required = ("ipv4", "ipv6") if family == "dual" else (family,)
        if any(not addresses[version] for version in required):
            raise ProbeError(
                f"Workload ENI must have assigned addresses for {family}",
                {**self._source_workload, "addresses_by_family": addresses},
            )
        return {
            "network_interface_id": interface_id,
            "subnet_id": subnet_id,
            "vpc_id": vpc_id,
            "availability_zone": zone,
            "security_group_ids": group_ids,
            "addresses_by_family": addresses,
        }

    @staticmethod
    def _interface_addresses(interface):
        def parse(value, version):
            try:
                if not isinstance(value, str) or "%" in value:
                    raise ValueError
                address = ip_address(value)
                if (
                    address.version != version
                    or getattr(address, "ipv4_mapped", None)
                    or address.is_unspecified
                    or address.is_loopback
                    or address.is_multicast
                    or address.is_link_local
                ):
                    raise ValueError
                return str(address)
            except ValueError as error:
                raise ProbeError("Workload ENI has invalid assigned IP addresses", {}) from error

        def collection(key, field, version):
            if key not in interface:
                return []
            items = interface[key]
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise ProbeError(f"Workload ENI has an invalid {key} collection", {})
            addresses = [parse(item.get(field), version) for item in items]
            if len(set(addresses)) != len(addresses):
                raise ProbeError(f"Workload ENI has duplicate {key} addresses", {})
            return addresses

        ipv4 = collection("PrivateIpAddresses", "PrivateIpAddress", 4)
        if "PrivateIpAddress" in interface:
            primary = parse(interface["PrivateIpAddress"], 4)
            if "PrivateIpAddresses" in interface and primary not in ipv4:
                raise ProbeError(
                    "Workload ENI primary IPv4 address disagrees with its collection", {}
                )
            if not ipv4:
                ipv4 = [primary]
        return {
            "ipv4": sorted(ipv4),
            "ipv6": sorted(collection("Ipv6Addresses", "Ipv6Address", 6)),
        }

    def _instance_interface(self):
        instances = []
        for reservation in _items(
            self.workload.builder.ec2,
            "describe_instances",
            "Reservations",
            InstanceIds=[self.workload.resource_id],
        ):
            self.workload._check_owner(reservation)
            items = reservation.get("Instances")
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise ProbeError(
                    "Instance discovery is missing Instances", dict(self._source_workload)
                )
            instances.extend(items)
        instance = _one(instances, f"workload instance {self.workload.resource_id}")
        if (
            instance.get("InstanceId") != self.workload.resource_id
            or not isinstance(instance.get("State"), dict)
            or instance["State"].get("Name") != "running"
        ):
            raise ProbeError(
                "Workload instance must match and be running", dict(self._source_workload)
            )
        interfaces = instance.get("NetworkInterfaces")
        if (
            not isinstance(interfaces, list)
            or not interfaces
            or any(not isinstance(item, dict) for item in interfaces)
        ):
            raise ProbeError(
                "Workload instance has no complete interface list", dict(self._source_workload)
            )
        identifiers = [
            _id(_required_text(item, "NetworkInterfaceId", "Instance interface"), "eni-")
            for item in interfaces
        ]
        if len(set(identifiers)) != len(identifiers):
            raise ProbeError(
                "Workload instance has duplicate interface identities", dict(self._source_workload)
            )
        if self.network_interface_id is None:
            if len(identifiers) != 1:
                raise ValueError(
                    "For a multi-interface instance, select network_interface_id explicitly"
                )
            selected = identifiers[0]
        elif self.network_interface_id in identifiers:
            selected = self.network_interface_id
        else:
            raise ProbeError(
                "Selected ENI is not part of the workload instance", dict(self._source_workload)
            )
        self._source_workload["instance_id"] = self.workload.resource_id
        return selected

    def _begin(self, kind, target, port, *, address_family=None):
        if not self._active:
            return super()._begin(kind, target, port, address_family=address_family)
        try:
            interface_id = (
                self._instance_interface()
                if self.workload.config_type == "AWS::EC2::Instance"
                else self.workload.resource_id
            )
            actual = self._live_interface(interface_id, address_family=address_family)
            if any(
                self._source_workload.get(key) != value
                for key, value in actual.items()
                if key != "addresses_by_family"
            ):
                raise ProbeError(
                    "Workload source changed after deployment; open a new probe session",
                    {"expected_workload": dict(self._source_workload), "actual_workload": actual},
                )
            self._source_workload.update(self.workload._context())
            # The Lambda uses its own assigned IP. Require the same address
            # families as the workload, while allowing its addresses to change.
            self._source_workload["addresses_by_family"] = actual["addresses_by_family"]
            self.source_context["source_workload"] = dict(self._source_workload)
            return super()._begin(kind, target, port, address_family=address_family)
        except BaseException as error:
            self._attach_source(error)
            raise


@dataclass(frozen=True)
class RouteTableRule(ResourceRule):
    def has_bidirectional_routes(
        self, destination: str, *, source: str, return_table, via=None, return_via=None
    ) -> CheckResult:
        """Check both explicitly declared VPC route-table directions."""
        from .inspection import paired_vpc_routes

        return paired_vpc_routes(
            self,
            destination,
            source=source,
            return_table=return_table,
            via=via,
            return_via=return_via,
        )

    def has_route_to(self, destination: str, *, via: str | None = None) -> CheckResult:
        _requested_network(destination)
        _validate_via(via)
        context = self._context()
        client = self.builder.ec2
        table = _one(
            client.describe_route_tables(RouteTableIds=[self.resource_id])["RouteTables"],
            f"route table {self.resource_id}",
        )
        if table.get("RouteTableId") != self.resource_id:
            raise NetworkAssertionError("Route table response does not match the selected table")
        self._check_owner(table)
        return self._decorate(check_routes(client, table, destination, via=via), context)


@dataclass(frozen=True)
class VpcRule(ResourceRule):
    def has_firewall_endpoints(
        self, firewall_arn: str, *, subnets_by_az: Mapping[str, str]
    ) -> CheckResult:
        """Verify the exact ready Network Firewall endpoint layout by AZ."""
        from .inspection import check_firewall_endpoints

        return check_firewall_endpoints(self, firewall_arn, subnets_by_az)

    def has_peering_with(
        self,
        other: str | VpcRule,
        *,
        region: str | None = None,
        account_id: str | None = None,
    ) -> CheckResult:
        if isinstance(other, VpcRule):
            if region is not None and region != other.region:
                raise ValueError("region disagrees with the other VPC selector")
            if account_id is not None and other.account_id is not None:
                if account_id != other.account_id:
                    raise ValueError("account_id disagrees with the other VPC selector")
            if other.account_id is not None:
                account_id = other.account_id
            region = other.region
            other = other.resource_id
        if account_id is not None:
            validate_account_id(account_id)
        _id(other, "vpc-")
        context = self._context()
        observed = []
        # Requester/accepter filters are ANDed by AWS, so query the two orientations.
        for local_side, remote_side in (
            ("RequesterVpcInfo", "AccepterVpcInfo"),
            ("AccepterVpcInfo", "RequesterVpcInfo"),
        ):
            prefix = "requester" if local_side == "RequesterVpcInfo" else "accepter"
            for peering in _items(
                self.builder.ec2,
                "describe_vpc_peering_connections",
                "VpcPeeringConnections",
                Filters=[{"Name": f"{prefix}-vpc-info.vpc-id", "Values": [self.resource_id]}],
            ):
                local, remote = peering[local_side], peering[remote_side]
                local_id = _required_text(local, "VpcId", "VPC peering local identity")
                remote_id = _required_text(remote, "VpcId", "VPC peering remote identity")
                if local_id != self.resource_id or remote_id != other:
                    continue
                if self.account_id is not None and (
                    _required_text(local, "OwnerId", "VPC peering local identity")
                    != self.account_id
                ):
                    continue
                if local.get("Region", self.region) != self.region:
                    continue
                if region is not None and _required_text(remote, "Region", "VPC peering") != region:
                    continue
                if account_id is not None and (
                    _required_text(remote, "OwnerId", "VPC peering") != account_id
                ):
                    continue
                observed.append(peering)
                status = peering.get("Status")
                if not isinstance(status, dict):
                    raise NetworkAssertionError("VPC peering response is missing Status")
                code = _required_text(status, "Code", "VPC peering Status")
                if code not in {
                    "initiating-request",
                    "pending-acceptance",
                    "active",
                    "deleted",
                    "rejected",
                    "failed",
                    "expired",
                    "provisioning",
                    "deleting",
                }:
                    raise NetworkAssertionError(f"Unknown VPC peering status {code!r}")
                if code == "active":
                    return self._decorate(
                        CheckResult(
                            True,
                            f"{self.resource_id} has active peering with {other}",
                            {"peering": peering},
                        ),
                        context,
                    )
        return self._decorate(
            CheckResult(
                False,
                f"{self.resource_id} has no active peering with {other}"
                + (f" in {region}" if region else ""),
                {"matching_peerings": observed},
            ),
            context,
        )


@dataclass(frozen=True)
class TransitGatewayRule(EndpointRule):
    def has_appliance_mode(self, vpc_id: str) -> CheckResult:
        """Require appliance mode on the selected available VPC attachment."""
        from .inspection import check_appliance_mode

        return check_appliance_mode(self, vpc_id)

    def route_table(self, route_table_id: str) -> TransitGatewayRouteTableRule:
        """Select a TGW table on this TGW; topology checks do not prove packet delivery."""
        return TransitGatewayRouteTableRule(self, _id(route_table_id, "tgw-rtb-"))

    def _live_gateway(self):
        client = self.builder.ec2
        gateways = list(
            _items(
                client,
                "describe_transit_gateways",
                "TransitGateways",
                TransitGatewayIds=[self.resource_id],
            )
        )
        gateway = _one(gateways, "transit gateway")
        if gateway.get("TransitGatewayId") != self.resource_id:
            raise NetworkAssertionError("TGW response does not match the selected gateway")
        self._check_owner(gateway)
        if (
            _state(gateway, {"pending", "available", "modifying", "deleting", "deleted"}, "TGW")
            != "available"
        ):
            raise ResourceNotFoundError("Transit gateway is not available")
        return client, gateway

    def propagates(self, route_table_id: str) -> PropagationRule:
        if route_table_id.startswith("rtb-"):
            raise ValueError("TGW propagation needs tgw-rtb-..., not a VPC route table (rtb-...)")
        return PropagationRule(self, _id(route_table_id, "tgw-rtb-"))

    def has_attachment(self, vpc_id: str) -> CheckResult:
        _id(vpc_id, "vpc-")
        context = self._context()
        attachments = list(
            _items(
                self.builder.ec2,
                "describe_transit_gateway_attachments",
                "TransitGatewayAttachments",
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [self.resource_id]},
                    {"Name": "resource-id", "Values": [vpc_id]},
                    {"Name": "resource-type", "Values": ["vpc"]},
                ],
            )
        )
        if self.account_id is not None:
            for item in attachments:
                if (
                    item.get("ResourceType") == "vpc"
                    and item.get("ResourceId") == vpc_id
                    and item.get("TransitGatewayId") == self.resource_id
                ):
                    self._check_owner(item, "TransitGatewayOwnerId")
        passed = any(
            _state(item, _TGW_ATTACHMENT_STATES, "TGW attachment") == "available"
            and _required_text(item, "ResourceType", "TGW attachment") == "vpc"
            and _required_text(item, "ResourceId", "TGW attachment") == vpc_id
            and _required_text(item, "TransitGatewayId", "TGW attachment") == self.resource_id
            for item in attachments
        )
        return self._decorate(
            CheckResult(
                passed,
                f"{self.resource_id} {'has' if passed else 'has no'} "
                f"available attachment to {vpc_id}",
                {"attachments": attachments},
            ),
            context,
        )


@dataclass(frozen=True)
class PropagationRule:
    tgw: TransitGatewayRule
    route_table_id: str

    def __bool__(self) -> bool:
        raise TypeError("Complete the propagation assertion with from_vpc() or to_vpc()")

    def from_vpc(self, vpc_id: str) -> CheckResult:
        """Assert that this VPC attachment has enabled propagation INTO the TGW table."""
        _id(vpc_id, "vpc-")
        context = self.tgw._context()
        client = self.tgw.builder.ec2
        if self.tgw.account_id is not None:
            self.tgw._live_gateway()
        table = _one(
            list(
                _items(
                    client,
                    "describe_transit_gateway_route_tables",
                    "TransitGatewayRouteTables",
                    TransitGatewayRouteTableIds=[self.route_table_id],
                )
            ),
            f"TGW route table {self.route_table_id}",
        )
        if table.get("TransitGatewayRouteTableId") != self.route_table_id:
            raise NetworkAssertionError(
                "TGW route table identity does not match the selected table"
            )
        table_tgw = _required_text(table, "TransitGatewayId", "TGW route table")
        table_state = _state(table, _TGW_TABLE_STATES, "TGW route table")
        if table_tgw != self.tgw.resource_id or table_state != "available":
            return self.tgw._decorate(
                CheckResult(
                    False,
                    f"{self.route_table_id} is not an available table on {self.tgw.resource_id}",
                    {"transit_gateway_route_table": table},
                ),
                context,
            )
        propagations = list(
            _items(
                client,
                "get_transit_gateway_route_table_propagations",
                "TransitGatewayRouteTablePropagations",
                TransitGatewayRouteTableId=self.route_table_id,
                Filters=[
                    {"Name": "resource-id", "Values": [vpc_id]},
                    {"Name": "resource-type", "Values": ["vpc"]},
                ],
            )
        )
        passed = any(
            _required_text(item, "ResourceId", "TGW propagation") == vpc_id
            and _required_text(item, "ResourceType", "TGW propagation") == "vpc"
            and _state(item, _TGW_PROPAGATION_STATES, "TGW propagation") == "enabled"
            for item in propagations
        )
        return self.tgw._decorate(
            CheckResult(
                passed,
                f"Propagation from {vpc_id} into {self.route_table_id} "
                f"on {self.tgw.resource_id} is {'enabled' if passed else 'not enabled'}",
                {"transit_gateway_route_table": table, "propagations": propagations},
            ),
            context,
        )

    def to_vpc(self, vpc_id: str) -> CheckResult:
        """Compatibility spelling: checks VPC-to-table propagation, same as from_vpc()."""
        return self.from_vpc(vpc_id)


@dataclass(frozen=True)
class TransitGatewayRouteTableRule:
    tgw: TransitGatewayRule
    route_table_id: str

    def __bool__(self) -> bool:
        raise TypeError("A TGW route table selector is not an assertion")

    def _live(self):
        client, _ = self.tgw._live_gateway()
        tables = list(
            _items(
                client,
                "describe_transit_gateway_route_tables",
                "TransitGatewayRouteTables",
                TransitGatewayRouteTableIds=[self.route_table_id],
            )
        )
        table = _one(tables, "transit gateway route table")
        if (
            table.get("TransitGatewayRouteTableId") != self.route_table_id
            or table.get("TransitGatewayId") != self.tgw.resource_id
        ):
            raise NetworkAssertionError("TGW route table does not belong to the selected gateway")
        if _state(table, _TGW_TABLE_STATES, "TGW table") != "available":
            raise ResourceNotFoundError("TGW route table is not available")
        return client, table

    def has_association(self, attachment_id: str) -> CheckResult:
        _id(attachment_id, "tgw-attach-")
        context = self.tgw._context()
        client, table = self._live()
        items = list(
            _items(
                client,
                "describe_transit_gateway_attachments",
                "TransitGatewayAttachments",
                TransitGatewayAttachmentIds=[attachment_id],
            )
        )
        attachment = _one(items, "transit gateway attachment")
        if (
            attachment.get("TransitGatewayAttachmentId") != attachment_id
            or attachment.get("TransitGatewayId") != self.tgw.resource_id
        ):
            raise NetworkAssertionError("Attachment is outside the selected TGW")
        self.tgw._check_owner(attachment, "TransitGatewayOwnerId")
        for key in ("ResourceId", "ResourceType"):
            _required_text(attachment, key, "TGW attachment")
        state = _state(attachment, _TGW_ATTACHMENT_STATES, "TGW attachment")
        associations = list(
            _items(
                client,
                "get_transit_gateway_route_table_associations",
                "Associations",
                TransitGatewayRouteTableId=self.route_table_id,
                Filters=[{"Name": "transit-gateway-attachment-id", "Values": [attachment_id]}],
            )
        )
        if len(associations) > 1:
            raise NetworkAssertionError("Ambiguous TGW attachment associations")
        passed = False
        if associations:
            item = associations[0]
            if any(
                item.get(key) != attachment.get(key)
                for key in ("TransitGatewayAttachmentId", "ResourceId", "ResourceType")
            ):
                raise NetworkAssertionError("Association identity disagrees with its attachment")
            association_state = _state(
                item,
                {"associating", "associated", "disassociating", "disassociated"},
                "TGW association",
            )
            passed = state == "available" and association_state == "associated"
        return self.tgw._decorate(
            CheckResult(
                passed,
                f"{attachment_id} {'is' if passed else 'is not'} "
                f"associated with {self.route_table_id}",
                {
                    "transit_gateway_route_table": table,
                    "attachment": attachment,
                    "associations": associations,
                },
            ),
            context,
        )

    def has_route_to(self, destination: str, *, via: str | None = None) -> CheckResult:
        # Validate user inputs before any AWS calls.
        _requested_network(destination)
        if via is not None:
            _id(via, "tgw-attach-")
        context = self.tgw._context()
        client, table = self._live()
        result = check_tgw_routes(client, self.route_table_id, destination, via=via)
        result.evidence["transit_gateway_route_table"] = table
        return self.tgw._decorate(result, context)

    def has_bidirectional_routes(
        self,
        destination: str,
        *,
        source: str,
        return_table: TransitGatewayRouteTableRule,
        via: str | None = None,
        return_via: str | None = None,
    ) -> CheckResult:
        """Check both explicit routing directions; this is not a reachability analysis."""
        if not isinstance(return_table, TransitGatewayRouteTableRule):
            raise TypeError("return_table must be a TGW route table selector")
        if (
            return_table.tgw.resource_id != self.tgw.resource_id
            or return_table.tgw.account_id != self.tgw.account_id
            or return_table.tgw.region != self.tgw.region
        ):
            raise ValueError("Forward and return tables must belong to the same scoped TGW")
        source_network = _requested_network(source, "source")
        destination_network = _requested_network(destination)
        if source_network.version != destination_network.version:
            raise ValueError("Forward and return CIDRs must use the same address family")
        for attachment in (via, return_via):
            if attachment is not None:
                _id(attachment, "tgw-attach-")
        forward = self.has_route_to(destination, via=via)
        reverse = return_table.has_route_to(source, via=return_via)
        return CheckResult(
            bool(forward) and bool(reverse),
            "TGW forward and return route coverage",
            {
                "forward": forward,
                "return": reverse,
            },
        )
