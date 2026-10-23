"""A small, synchronous wrapper around EC2 Reachability Analyzer."""

from __future__ import annotations

import logging
import math
import re
import sys
import warnings
from collections.abc import Sequence
from ipaddress import ip_network
from time import monotonic, sleep
from typing import Any
from uuid import uuid4

from .accounts import validate_account_id
from .errors import (
    AnalysisError,
    AnalysisTimeoutError,
    CleanupWarning,
    UnsupportedCheckError,
    _attach_evidence,
)
from .path_evidence import (
    blocker_summaries,
    forward_path_constraints,
    require_resource_path,
    validate_additional_details,
    validate_components,
)
from .result import CheckResult

_RESOURCE_PREFIXES = {
    "network-interface": "eni-",
    "instance": "i-",
    "internet-gateway": "igw-",
    "transit-gateway": "tgw-",
    "transit-gateway-attachment": "tgw-attach-",
    "vpn-gateway": "vgw-",
    "vpc-endpoint": "vpce-",
    "vpc-endpoint-service": "vpce-svc-",
    "vpc-peering-connection": "pcx-",
}
_INCONCLUSIVE_CODES = {
    "IGW_NAT_REFLECTION",
    "NO_PATH",
    "TGW_RTB_ROUTES_ARE_UNKNOWN",
    "UNASSOCIATED_COMPONENT",
    "UNKNOWN_DESTINATION",
    "UNKNOWN_PEERED_SGS",
    "UNKNOWN_RESOURCE",
    "NO_SOURCE_OR_DESTINATION",
    "NO_POSSIBLE_DESTINATION",
    "UNSUPPORTED_COMPONENT",
}


def _ipv4_host(value: str, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be an IPv4 address or /32 string")
    try:
        network = ip_network(value, strict=False)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be an IPv4 address or /32, got {value!r}") from error
    if network.version != 4 or network.prefixlen != 32:
        raise UnsupportedCheckError(
            f"{name} must be one IPv4 address or /32; Reachability Analyzer cannot "
            "prove reachability for an entire CIDR or IPv6 address."
        )
    return str(network.network_address)


def _port(value: int | None, name: str) -> None:
    if value is not None and (type(value) is not int or not 0 <= value <= 65535):
        raise ValueError(f"{name} must be an integer from 0 to 65535, or None")


def _explanation_codes(value: Any) -> set[str]:
    if isinstance(value, dict):
        codes = {value["ExplanationCode"]} if value.get("ExplanationCode") else set()
        for item in value.values():
            codes.update(_explanation_codes(item))
        return codes
    if isinstance(value, list):
        return set().union(*(_explanation_codes(item) for item in value))
    return set()


def _resource(value: str, region: str, *, partition: str | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("A nonempty AWS resource ID or ARN is required")
    resource_id = value
    prefixes = tuple(_RESOURCE_PREFIXES.values())
    if value.startswith("arn:"):
        parts = value.split(":", 5)
        if (
            len(parts) != 6
            or parts[2] != "ec2"
            or not parts[3]
            or re.fullmatch(r"[a-z0-9-]+", parts[1]) is None
        ):
            raise UnsupportedCheckError(f"Unsupported Reachability Analyzer ARN: {value!r}")
        validate_account_id(parts[4])
        if partition is not None and parts[1] != partition:
            raise UnsupportedCheckError("Reachability Analyzer endpoints must use its partition")
        if parts[3] != region:
            raise UnsupportedCheckError(
                f"Reachability Analyzer requires both endpoints in {region}; "
                f"{value!r} is in {parts[3]}. Run regional checks separately."
            )
        resource_type, separator, resource_id = parts[5].partition("/")
        if not separator or resource_type not in _RESOURCE_PREFIXES:
            raise UnsupportedCheckError(f"Unsupported Reachability Analyzer ARN: {value!r}")
        prefixes = (_RESOURCE_PREFIXES[resource_type],)
    if not any(
        re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]+", resource_id) for prefix in prefixes
    ):
        raise UnsupportedCheckError(
            f"Unsupported Reachability Analyzer endpoint {value!r}. "
            "Use an ENI, instance, or another supported gateway/endpoint resource. "
            "For a subnet, choose an explicit representative ENI."
        )
    return value


def qualify_endpoint(
    identifier: str,
    *,
    account_id: str | None,
    region: str,
    partition: str = "aws",
    allow_ip: bool = False,
) -> str:
    """Qualify an account-scoped endpoint without calling AWS.

    Cross-account Reachability Analyzer endpoints need ARNs. Explicit ARNs are
    preserved, but must agree with the selected region and any account scope.
    A destination IPv4 address or /32 can pass through with ``allow_ip=True``.
    """
    if account_id is not None:
        validate_account_id(account_id)
    if not isinstance(region, str) or not region:
        raise ValueError("region must be a nonempty AWS region name")
    if not isinstance(partition, str) or not re.fullmatch(r"[a-z0-9-]+", partition):
        raise ValueError("partition must be a nonempty AWS partition name")
    if (
        allow_ip
        and isinstance(identifier, str)
        and not identifier.startswith("arn:")
        and not re.match(r"^[A-Za-z]+(?:-[A-Za-z]+)*-", identifier)
    ):
        return _ipv4_host(identifier, "destination")
    identifier = _resource(identifier, region, partition=partition)
    if identifier.startswith("arn:"):
        arn_account = identifier.split(":", 5)[4]
        if account_id is not None and arn_account != account_id:
            raise ValueError(
                f"Endpoint {identifier!r} belongs to account {arn_account}, "
                f"not the selected account {account_id}."
            )
        return identifier
    if account_id is None:
        return identifier
    for resource_type, prefix in _RESOURCE_PREFIXES.items():
        if re.fullmatch(re.escape(prefix) + r"[A-Za-z0-9]+", identifier):
            return f"arn:{partition}:ec2:{region}:{account_id}:{resource_type}/{identifier}"
    raise UnsupportedCheckError(f"Unsupported Reachability Analyzer endpoint {identifier!r}")


class ReachabilityAnalyzer:
    """Create, evaluate, and normally remove one analysis for every check.

    ``timeout`` bounds polling, not boto3 HTTP calls or cleanup. Configure SDK
    connect/read timeouts separately. Analysis exceptions carry ``evidence``
    containing the request, resource IDs, and last analysis response.
    """

    def __init__(
        self,
        client: Any,
        *,
        timeout: float = 120.0,
        poll_interval: float = 2.0,
        keep_analysis: bool = False,
    ) -> None:
        if type(keep_analysis) is not bool:
            raise ValueError("keep_analysis must be a boolean")
        for name, value in (("timeout", timeout), ("poll_interval", poll_interval)):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a positive finite number")
        self.client = client
        self.region = client.meta.region_name
        self.partition = client.meta.partition
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.keep_analysis = keep_analysis

    def check(
        self,
        source: str,
        destination: str,
        *,
        protocol: str = "tcp",
        port: int | None = 443,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        source_port: int | None = None,
        expect_reachable: bool = True,
        additional_accounts: tuple[str, ...] = (),
        through: Sequence[str] = (),
        avoiding: Sequence[str] = (),
    ) -> CheckResult:
        """Test modeled IPv4 reachability for one packet-header selection.

        ``destination_ip`` filters the destination address leaving the source,
        including when a destination resource is also specified. ``port=None``
        leaves the destination port unconstrained; it does not assert all ports.
        API errors, failed analyses, and unsupported scope always raise, including
        when ``expect_reachable=False``.
        """
        source = _resource(source, self.region, partition=self.partition)
        if not isinstance(protocol, str) or protocol.lower() not in {"tcp", "udp"}:
            raise ValueError("protocol must be 'tcp' or 'udp'")
        protocol = protocol.lower()
        _port(port, "port")
        _port(source_port, "source_port")
        if type(expect_reachable) is not bool:
            raise ValueError("expect_reachable must be a boolean")
        if not isinstance(destination, str) or not destination:
            raise ValueError("A destination resource ID, ARN, or IPv4 address is required")
        through = validate_components(through, "through", self.region, partition=self.partition)
        avoiding = validate_components(avoiding, "avoiding", self.region, partition=self.partition)
        if set(through) & set(avoiding):
            raise ValueError("A component cannot be both required and forbidden")
        if through or avoiding:
            if not expect_reachable:
                raise ValueError("Path constraints apply to positive reachability checks only")
            require_resource_path(destination)

        request: dict[str, Any] = {
            "Source": source,
            "Protocol": protocol,
            "ClientToken": str(uuid4()),
        }
        packet_filter: dict[str, Any] = {}
        if destination.startswith("arn:") or re.match(r"^[A-Za-z]+(?:-[A-Za-z]+)*-", destination):
            request["Destination"] = _resource(destination, self.region, partition=self.partition)
        else:
            packet_filter["DestinationAddress"] = _ipv4_host(destination, "destination")
        if destination_ip is not None:
            address = _ipv4_host(destination_ip, "destination_ip")
            if (
                "DestinationAddress" in packet_filter
                and packet_filter["DestinationAddress"] != address
            ):
                raise ValueError("destination and destination_ip specify different IP addresses")
            packet_filter["DestinationAddress"] = address
        if source_ip is not None:
            packet_filter["SourceAddress"] = _ipv4_host(source_ip, "source_ip")
        if port is not None:
            packet_filter["DestinationPortRange"] = {"FromPort": port, "ToPort": port}
        if source_port is not None:
            packet_filter["SourcePortRange"] = {"FromPort": source_port, "ToPort": source_port}
        if packet_filter:
            request["FilterAtSource"] = packet_filter
        if isinstance(additional_accounts, str):
            raise ValueError("additional_accounts must be a sequence of 12-digit account IDs")
        accounts = tuple(additional_accounts)
        for account in accounts:
            validate_account_id(account)

        evidence: dict[str, Any] = {
            "region": self.region,
            "source": source,
            "destination": destination,
            "request": request,
            "additional_accounts": list(accounts),
            "cleanup": {"path": "not_created", "analysis": "not_created"},
        }
        path_id: str | None = None
        analysis_id: str | None = None
        try:
            evidence["cleanup"]["path"] = "creation_unconfirmed"
            path = self.client.create_network_insights_path(**request).get(
                "NetworkInsightsPath", {}
            )
            evidence["path"] = path
            returned_path_id = path.get("NetworkInsightsPathId")
            evidence["path_id"] = returned_path_id
            if (
                not isinstance(returned_path_id, str)
                or re.fullmatch(r"nip-[A-Za-z0-9]+", returned_path_id) is None
            ):
                self._raise("CreateNetworkInsightsPath returned no path ID", evidence)
            path_id = returned_path_id
            evidence["cleanup"]["path"] = "pending"
            start: dict[str, Any] = {
                "NetworkInsightsPathId": path_id,
                "ClientToken": str(uuid4()),
            }
            if accounts:
                start["AdditionalAccounts"] = list(accounts)
            evidence["cleanup"]["analysis"] = "creation_unconfirmed"
            analysis = self.client.start_network_insights_analysis(**start).get(
                "NetworkInsightsAnalysis", {}
            )
            returned_analysis_id = analysis.get("NetworkInsightsAnalysisId")
            evidence["analysis_id"] = returned_analysis_id
            evidence["analysis"] = analysis
            if (
                not isinstance(returned_analysis_id, str)
                or re.fullmatch(r"nia-[A-Za-z0-9]+", returned_analysis_id) is None
            ):
                self._raise("StartNetworkInsightsAnalysis returned no analysis ID", evidence)
            if analysis.get("NetworkInsightsPathId") != path_id:
                self._raise(
                    "StartNetworkInsightsAnalysis returned an unconfirmed path identity", evidence
                )
            analysis_id = returned_analysis_id
            evidence["cleanup"]["analysis"] = "pending"
            deadline = monotonic() + self.timeout
            while True:
                if (
                    analysis.get("NetworkInsightsAnalysisId") != analysis_id
                    or analysis.get("NetworkInsightsPathId", path_id) != path_id
                ):
                    self._raise(
                        "Analysis identity does not match the created path/analysis", evidence
                    )
                for field in ("FilterInArns", "FilterOutArns"):
                    if field in analysis and analysis[field] != []:
                        self._raise(
                            f"Analysis returned unexpected {field}; its scope is unconfirmed",
                            evidence,
                        )
                if "AdditionalAccounts" in analysis and (
                    not isinstance(analysis["AdditionalAccounts"], list)
                    or sorted(analysis["AdditionalAccounts"]) != sorted(accounts)
                ):
                    self._raise("Analysis returned a different account scope", evidence)
                status = analysis.get("Status")
                if status == "succeeded":
                    break
                if status != "running":
                    self._raise(
                        f"Analysis did not succeed: status={status!r}; "
                        f"{analysis.get('StatusMessage', 'No status message')}",
                        evidence,
                    )
                remaining = deadline - monotonic()
                if remaining <= 0:
                    self._raise(
                        f"Analysis exceeded polling timeout of {self.timeout:g}s",
                        evidence,
                        timeout=True,
                    )
                sleep(min(self.poll_interval, remaining))
                if monotonic() >= deadline:
                    self._raise(
                        f"Analysis exceeded polling timeout of {self.timeout:g}s",
                        evidence,
                        timeout=True,
                    )
                analyses = []
                for page in self.client.get_paginator(
                    "describe_network_insights_analyses"
                ).paginate(NetworkInsightsAnalysisIds=[analysis_id]):
                    items = page.get("NetworkInsightsAnalyses")
                    if not isinstance(items, list) or any(
                        not isinstance(item, dict) for item in items
                    ):
                        self._raise(
                            "DescribeNetworkInsightsAnalyses returned malformed analyses", evidence
                        )
                    analyses.extend(items)
                if (
                    len(analyses) != 1
                    or analyses[0].get("NetworkInsightsAnalysisId") != analysis_id
                ):
                    self._raise(
                        "DescribeNetworkInsightsAnalyses returned no matching analysis", evidence
                    )
                analysis = analyses[0]
                evidence["analysis"] = analysis

            reachable = analysis.get("NetworkPathFound")
            if type(reachable) is not bool:
                self._raise("Succeeded analysis returned no boolean NetworkPathFound", evidence)
            validate_additional_details(analysis)
            codes = sorted(_explanation_codes(analysis))
            if _INCONCLUSIVE_CODES.intersection(codes):
                self._raise(
                    f"Analysis cannot establish the requested scope: {', '.join(codes)}", evidence
                )
            blockers = blocker_summaries(analysis)
            evidence["explanations"] = blockers
            passed = reachable == expect_reachable
            if through or avoiding:
                constraints = forward_path_constraints(
                    analysis,
                    source,
                    destination,
                    through,
                    avoiding,
                    region=self.region,
                    partition=self.partition,
                )
                evidence["path_constraints"] = constraints
                passed = passed and constraints["passed"]
            observed = "reachable" if reachable else "unreachable"
            expected = "reachable" if expect_reachable else "unreachable"
            message = (
                f"{source} -> {destination} ({protocol}/{port if port is not None else 'any'}, "
                f"{self.region}): {observed}; expected {expected}; analysis={analysis_id}"
            )
            if codes:
                message += f"; explanations={', '.join(codes)}"
            for blocker in blockers:
                resources = ", ".join(
                    f"{item['role']}={item.get('Id', item.get('Arn'))}"
                    for item in blocker["resources"]
                )
                message += (
                    f"; {blocker['path_direction']}/{blocker['direction']}: "
                    f"{blocker['description']}" + (f" ({resources})" if resources else "")
                )
            if through or avoiding:
                status = "matched" if constraints["passed"] else "not matched"
                message += f"; forward path constraints: {status}"
            if analysis.get("WarningMessage"):
                message += f"; AWS warning: {analysis['WarningMessage']}"
            return CheckResult(passed, message, evidence)
        except BaseException as error:
            _attach_evidence(error, evidence)
            raise
        finally:
            if self.keep_analysis:
                for kind, identifier in (("path", path_id), ("analysis", analysis_id)):
                    if identifier is not None:
                        evidence["cleanup"][kind] = "retained"
            elif path_id:
                self._cleanup(
                    path_id,
                    analysis_id,
                    preserve_error=sys.exc_info()[0] is not None,
                    evidence=evidence,
                )

    @staticmethod
    def _raise(message: str, evidence: dict[str, Any], *, timeout: bool = False) -> None:
        error_type = AnalysisTimeoutError if timeout else AnalysisError
        error = error_type(
            f"{message}; region={evidence['region']}; path={evidence.get('path_id')}; "
            f"analysis={evidence.get('analysis_id')}"
        )
        error.evidence = evidence  # type: ignore[attr-defined]
        raise error

    def _cleanup(
        self,
        path_id: str,
        analysis_id: str | None,
        *,
        preserve_error: bool,
        evidence: dict[str, Any],
    ) -> None:
        failures = []
        cleanup = evidence["cleanup"]
        cleanup_interrupt = None
        for kind, identifier, operation, parameter in (
            (
                "analysis",
                analysis_id,
                self.client.delete_network_insights_analysis,
                "NetworkInsightsAnalysisId",
            ),
            (
                "path",
                path_id,
                self.client.delete_network_insights_path,
                "NetworkInsightsPathId",
            ),
        ):
            if identifier is None:
                continue
            try:
                response = operation(**{parameter: identifier})
                if not isinstance(response, dict) or response.get(parameter) != identifier:
                    raise AnalysisError("Delete response did not confirm the requested identity")
                cleanup[kind] = "deleted"
            except BaseException as error:
                reason = str(error) or type(error).__name__
                cleanup[kind] = "unconfirmed"
                cleanup[f"{kind}_error"] = reason
                failures.append(f"{kind} {identifier}: {reason}")
                if not isinstance(error, Exception):
                    cleanup[f"{kind}_interrupted"] = True
                    if cleanup_interrupt is None:
                        cleanup_interrupt = error
        if failures:
            message = (
                f"Reachability Analyzer cleanup in {self.region} requires attention "
                f"(path={path_id}, analysis={analysis_id}): {'; '.join(failures)}"
            )
            try:
                warnings.warn(message, CleanupWarning, stacklevel=3)
            except CleanupWarning:
                if not preserve_error and cleanup_interrupt is None:
                    raise
                logging.getLogger(__name__).warning(message)
        if cleanup_interrupt is not None and not preserve_error:
            _attach_evidence(cleanup_interrupt, evidence)
            raise cleanup_interrupt
