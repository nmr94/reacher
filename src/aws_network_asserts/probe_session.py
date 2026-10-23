"""Explicit, synchronous batches of fresh DNS/TCP/TLS/HTTP observations."""

from __future__ import annotations

import json
import math
import ssl
import time
from collections.abc import Sequence
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import quote, urlsplit

from .accounts import validate_account_id
from .errors import ProbeError
from .probe import LambdaProbe
from .result import CheckResult

_DEPLOYMENT_OPTIONS = {
    "cleanup_manifest",
    "execution_role_arn",
    "auto_create_execution_role",
    "security_group_ids",
    "auto_create_security_group",
    "allow_write",
    "ready_timeout",
    "role_cleanup_timeout",
    "security_group_cleanup_timeout",
    "source_kind",
    "expected_source_cidrs",
    "address_family",
}

_SUCCESS_OUTCOMES = {"tcp": "connected", "tls": "tls_verified", "http": "http_response"}
_UNSET = object()


def _number(value: Any, name: str, maximum: float, *, zero: bool = False) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
        or (not zero and value == 0)
        or value > maximum
    ):
        raise ValueError(
            f"{name} must be finite, {'nonnegative' if zero else 'positive'}, and <= {maximum}"
        )


def _families(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or value not in {"ipv4", "ipv6", "dual"}:
        raise ValueError("address_family must be ipv4, ipv6, or dual")
    return (4, 6) if value == "dual" else (6,) if value == "ipv6" else (4,)


def _address(value: str):
    if not isinstance(value, str) or "%" in value:
        raise ValueError("Expected an IP address without a scope identifier")
    address = ip_address(value)
    if getattr(address, "ipv4_mapped", None) is not None:
        raise ValueError("IPv4-mapped IPv6 addresses cannot establish IPv6 coverage")
    return address


def _networks(values: Sequence[str], name: str):
    if (
        isinstance(values, (str, bytes))
        or not isinstance(values, Sequence)
        or any(not isinstance(value, str) or "%" in value for value in values)
    ):
        raise ValueError(f"{name} must be a sequence of IPv4/IPv6 CIDRs")
    return tuple(ip_network(value, strict=False) for value in values)


def _addresses(values: Sequence[str] | None, name: str = "expected_addresses"):
    if values is None:
        return None
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence) or not values:
        raise ValueError(f"{name} must be a nonempty sequence")
    return {str(_address(value)) for value in values}


def _inside(address: str, networks) -> bool:
    parsed = _address(address)
    return any(parsed.version == network.version and parsed in network for network in networks)


def _matches_dns(addresses, expected, networks):
    return (expected is None or set(addresses) == expected) and (
        not networks or all(_inside(address, networks) for address in addresses)
    )


class ProbeSession:
    """One explicitly authorised deployment, fresh invocations, cleanup on exit.

    A session must be used as a context manager. It is single-use and synchronous.
    Source groups are caller-supplied or explicitly created; a Lambda source never
    reproduces a workload's host firewall or process environment.
    """

    def __init__(
        self,
        selector: Any,
        *,
        source_kind: str = "synthetic",
        expected_source_cidrs: Sequence[str] = (),
        address_family: str = "ipv4",
        **deployment_options: Any,
    ) -> None:
        # Reuse the exact one-shot write gate, account, role and SG validation.
        self._settings = selector._validate_probe(
            "127.0.0.1", address_family=address_family, **deployment_options
        )
        _families(address_family)
        self.address_family = address_family
        if source_kind not in {"synthetic", "workload_representative"}:
            raise ValueError("source_kind must be synthetic or workload_representative")
        if source_kind == "workload_representative" and deployment_options.get(
            "auto_create_security_group"
        ):
            raise ValueError(
                "workload_representative checks require supplied workload security groups"
            )
        self._networks = _networks(expected_source_cidrs, "expected_source_cidrs")
        self.selector = selector
        self.source_kind = source_kind
        self.options = {**deployment_options, "address_family": address_family}
        self._active = False
        self._used = False
        self._manager = None
        self.evidence: dict[str, Any] = {}

    def __bool__(self):
        raise TypeError("A probe session is not an assertion; call tcp(), tls(), http(), or dns()")

    def __enter__(self):
        if self._used:
            raise RuntimeError("A probe session cannot be entered more than once")
        self._used = True
        self._client, role, group, _ = self.selector._probe_resources(**self.options)
        subnets = []
        for page in self.selector.builder.ec2.get_paginator("describe_subnets").paginate(
            SubnetIds=[self.selector.resource_id]
        ):
            items = page.get("Subnets")
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise ProbeError("Source discovery is missing a Subnets list", {})
            subnets.extend(items)
        if len(subnets) != 1:
            raise ProbeError("Source discovery needs one live subnet", {})
        subnet = subnets[0]
        if (
            subnet.get("SubnetId") != self.selector.resource_id
            or subnet.get("State") != "available"
        ):
            raise ProbeError("Source subnet is not available or does not match", {"subnet": subnet})
        try:
            validate_account_id(subnet.get("OwnerId"))
        except ValueError as error:
            raise ProbeError("Source subnet has no valid owner", {"subnet": subnet}) from error
        for key in ("VpcId", "AvailabilityZone"):
            if not isinstance(subnet.get(key), str) or not subnet[key]:
                raise ProbeError(f"Source subnet is missing {key}", {"subnet": subnet})
        if self.address_family != "ipv4":
            try:
                ipv4 = ip_network(subnet["CidrBlock"])
                associations = subnet["Ipv6CidrBlockAssociationSet"]
                if ipv4.version != 4 or subnet.get("Ipv6Native") is True:
                    raise ValueError("An IPv4 subnet is required alongside IPv6")
                if not isinstance(associations, list) or any(
                    not isinstance(item, dict) for item in associations
                ):
                    raise ValueError("Malformed IPv6 subnet associations")
                ipv6 = [
                    ip_network(item["Ipv6CidrBlock"])
                    for item in associations
                    if item.get("Ipv6CidrBlockState", {}).get("State") == "associated"
                ]
                if not ipv6 or any(network.version != 6 for network in ipv6):
                    raise ValueError("No associated IPv6 subnet CIDR")
            except (KeyError, TypeError, ValueError, AttributeError) as error:
                raise ProbeError(
                    "IPv6 probes require a verified dual-stack subnet with an associated IPv6 CIDR",
                    {"subnet": subnet},
                ) from error
        workload = getattr(self, "_source_workload", None)
        if workload is not None and any(
            workload.get(key) != value
            for key, value in (
                ("subnet_id", self.selector.resource_id),
                ("vpc_id", subnet["VpcId"]),
                ("availability_zone", subnet["AvailabilityZone"]),
                ("account_id", self.selector.account_id),
            )
        ):
            raise ProbeError(
                "Workload source disagrees with the live subnet/account",
                {"subnet": subnet, "source_workload": workload},
            )
        self.source_context = {
            "kind": self.source_kind,
            "account_id": self.selector.account_id,
            "region": self.selector.region,
            "subnet_id": self.selector.resource_id,
            "availability_zone": subnet["AvailabilityZone"],
            "vpc_id": subnet["VpcId"],
            "subnet_owner_id": subnet["OwnerId"],
            "host_firewall_tested": False,
            "security_group_mode": "automatic" if group is not None else "supplied",
            "address_family": self.address_family,
        }
        if workload is not None:
            self.source_context["source_workload"] = dict(workload)
        self._manager = self._settings.deployed(
            self._client,
            self.selector.resource_id,
            poll_interval=self.selector.builder.poll_interval,
            role=role,
            security_group=group,
            application=True,
        )
        self.evidence = self._manager.__enter__()
        self.source_context["security_group_ids"] = list(self.evidence["security_group_ids"])
        self._active = True
        return self

    def __exit__(self, *error):
        self._active = False
        return self._manager.__exit__(*error)

    def _check_family(self, family):
        family = self.address_family if family is None else family
        if not set(_families(family)) <= set(_families(self.address_family)):
            raise ValueError("A check cannot request an address family disabled on its deployment")
        return family

    def _protocol(self, kind, target, options):
        family = self._check_family(options.pop("address_family", None))
        return self._run(self._prepare(kind, target, address_family=family, **options))

    def tcp(self, host: str, **options: Any) -> CheckResult:
        return self._protocol("tcp", host, options)

    def tls(self, host: str, **options: Any) -> CheckResult:
        return self._protocol("tls", host, options)

    def http(self, url: str, **options: Any) -> CheckResult:
        return self._protocol("http", url, options)

    def dns(
        self,
        host: str,
        *,
        expected_addresses: Sequence[str] | None = None,
        allowed_cidrs: Sequence[str] = (),
        max_addresses: int = 32,
        address_family: str | None = None,
    ) -> CheckResult:
        family = self._check_family(address_family)
        expected, networks = _dns_expectations(
            host,
            expected_addresses=expected_addresses,
            allowed_cidrs=allowed_cidrs,
            max_addresses=max_addresses,
            address_family=family,
        )
        evidence = self._begin("dns", host, None, address_family=family)
        response = self._resolve(host, max_addresses, evidence, family)
        addresses = response["addresses"]
        passed = _matches_dns(addresses, expected, networks)
        evidence.update(
            address_family=family,
            resolved_addresses=addresses,
            dns=response,
            addresses_by_family=response["addresses_by_family"],
            expected_addresses=sorted(expected) if expected is not None else None,
            allowed_cidrs=[str(network) for network in networks],
        )
        return self._finish(passed, f"DNS {host}: {', '.join(addresses)}", evidence)

    @staticmethod
    def _prepare(
        kind: str,
        target: str,
        *,
        port: int | None = None,
        address_mode: str = "all",
        attempts: int = 1,
        successes_required: int | None = None,
        interval: float = 0,
        max_latency_ms: float | None = None,
        connect_timeout: float = 3.0,
        read_timeout: Any = _UNSET,
        max_addresses: int = 32,
        server_hostname: str | None = None,
        ca_pem: str | None = None,
        expected_statuses: Any = _UNSET,
        body_contains: Any = _UNSET,
        max_body_bytes: Any = _UNSET,
        http_method: Any = _UNSET,
        address_family: str = "ipv4",
        expected_addresses: Sequence[str] | None = None,
        allowed_destination_cidrs: Sequence[str] = (),
    ) -> dict[str, Any]:
        if kind not in _SUCCESS_OUTCOMES:
            raise ValueError("Protocol checks must use tcp, tls, or http")
        http_options = {
            "expected_statuses": expected_statuses,
            "body_contains": body_contains,
            "max_body_bytes": max_body_bytes,
            "http_method": http_method,
        }
        if kind != "http" and any(value is not _UNSET for value in http_options.values()):
            supplied = ", ".join(
                name for name, value in http_options.items() if value is not _UNSET
            )
            raise ValueError(f"{supplied} only apply to HTTP checks")
        if kind == "tcp" and read_timeout is not _UNSET:
            raise ValueError("read_timeout only applies to TLS and HTTP checks")
        read_timeout = 3.0 if read_timeout is _UNSET else read_timeout
        expected_statuses = (200,) if expected_statuses is _UNSET else expected_statuses
        body_contains = None if body_contains is _UNSET else body_contains
        max_body_bytes = 4096 if max_body_bytes is _UNSET else max_body_bytes
        http_method = "GET" if http_method is _UNSET else http_method
        host, path, host_header, use_tls = target, "/", target, kind == "tls"
        if kind == "http":
            if not isinstance(target, str) or any(
                ord(char) <= 32 or ord(char) == 127 for char in target
            ):
                raise ValueError("HTTP URL must not contain whitespace or control characters")
            parsed = urlsplit(target)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise ValueError(
                    "HTTP checks require an http(s) URL without credentials or fragments"
                )
            host = parsed.hostname
            url_port = (
                parsed.port
                if parsed.port is not None
                else (443 if parsed.scheme == "https" else 80)
            )
            if port is not None and port != url_port:
                raise ValueError("port disagrees with the HTTP URL")
            port = url_port
            path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
            if parsed.query:
                path += "?" + quote(parsed.query, safe="%=&/:@!$'()*+,;?-._~")
            use_tls = parsed.scheme == "https"
            host_header = parsed.netloc
            if any(ord(character) < 32 or ord(character) > 126 for character in host_header):
                raise ValueError("HTTP host must be printable ASCII")
        if not use_tls and (server_hostname is not None or ca_pem is not None):
            raise ValueError("server_hostname and ca_pem only apply to TLS or HTTPS checks")
        port = port if port is not None else 443
        families = _families(address_family)
        LambdaProbe(host, port, None, None, connect_timeout, 300, address_family=address_family)
        try:
            literal = _address(host)
        except ValueError:
            literal = None
        if literal is not None and (len(families) != 1 or literal.version not in families):
            raise ValueError(
                "An IP literal must match one requested address family; dual needs a hostname"
            )
        expected = _addresses(expected_addresses)
        networks = _networks(allowed_destination_cidrs, "allowed_destination_cidrs")
        if expected is not None and any(
            _address(address).version not in families for address in expected
        ):
            raise ValueError("Expected addresses disagree with address_family")
        _number(read_timeout, "read_timeout", 10)
        if address_mode not in {"first", "any", "all"}:
            raise ValueError("address_mode must be first, any, or all")
        if type(attempts) is not int or not 1 <= attempts <= 10:
            raise ValueError("attempts must be an integer between 1 and 10")
        required = attempts if successes_required is None else successes_required
        if type(required) is not int or not 1 <= required <= attempts:
            raise ValueError("successes_required must be between 1 and attempts")
        if type(max_addresses) is not int or not 1 <= max_addresses <= 32:
            raise ValueError("max_addresses must be between 1 and 32")
        _number(interval, "interval", 5, zero=True)
        if max_latency_ms is not None:
            _number(max_latency_ms, "max_latency_ms", 1_000_000)
        if server_hostname is not None:
            LambdaProbe(server_hostname, port, None, None, connect_timeout, 300)
        if ca_pem is not None:
            if not isinstance(ca_pem, str) or len(ca_pem) > 128_000:
                raise ValueError("ca_pem must contain a PEM CA bundle of at most 128000 characters")
            ssl.create_default_context(cadata=ca_pem)
        stages = int(use_tls) + int(kind == "http")
        if connect_timeout + stages * read_timeout > 12:
            raise ValueError("Connection and protocol timeouts must total at most 12 seconds")
        if (
            isinstance(expected_statuses, (str, bytes))
            or not isinstance(expected_statuses, Sequence)
            or not expected_statuses
            or any(
                type(status) is not int or not 100 <= status <= 599 for status in expected_statuses
            )
        ):
            raise ValueError("expected_statuses must contain HTTP status integers")
        if http_method not in {"GET", "HEAD"}:
            raise ValueError("http_method must be GET or HEAD")
        if body_contains is not None and (
            not isinstance(body_contains, str) or not body_contains or http_method == "HEAD"
        ):
            raise ValueError("body_contains must be nonempty text on a GET request")
        if type(max_body_bytes) is not int or not 1 <= max_body_bytes <= 65536:
            raise ValueError("max_body_bytes must be between 1 and 65536")
        return {
            "kind": kind,
            "target": target,
            "host": host,
            "port": port,
            "address_mode": address_mode,
            "attempts": attempts,
            "successes_required": required,
            "interval": interval,
            "max_latency_ms": max_latency_ms,
            "max_addresses": max_addresses,
            "connect_timeout": connect_timeout,
            "read_timeout": read_timeout,
            "server_hostname": server_hostname or host,
            "ca_pem": ca_pem,
            "tls": use_tls,
            "path": path,
            "host_header": host_header,
            "expected_statuses": list(expected_statuses),
            "body_contains": body_contains,
            "max_body_bytes": max_body_bytes,
            "http_method": http_method,
            "address_family": address_family,
            "expected_addresses": sorted(expected) if expected is not None else None,
            "allowed_destination_cidrs": [str(network) for network in networks],
        }

    def _begin(self, kind, target, port, *, address_family=None):
        if not self._active:
            raise RuntimeError(
                "Probe checks require an active with subnet.probe_session(...) context"
            )
        return {
            **self.selector._context(),
            "method": f"lambda_{kind}",
            "kind": kind,
            "target": target,
            "port": port,
            "source_context": dict(self.source_context),
            "deployment": self.evidence,
            **(
                {"source_workload": dict(self._source_workload)}
                if hasattr(self, "_source_workload")
                else {}
            ),
        }

    def _invoke(self, request, evidence):
        response = self._client.invoke(
            FunctionName=self.evidence["function_name"],
            InvocationType="RequestResponse",
            LogType="None",
            Payload=json.dumps(request).encode(),
        )
        payload = response.get("Payload")
        if payload is None:
            raise ProbeError("Lambda invocation returned no Payload", evidence)
        try:
            raw = payload.read()
        finally:
            payload.close()
        try:
            observation = json.loads(raw)
        except (ValueError, TypeError) as error:
            raise ProbeError("Lambda invocation returned invalid JSON", evidence) from error
        evidence["last_observation"] = observation
        if (
            response.get("StatusCode") != 200
            or response.get("FunctionError")
            or not isinstance(observation, dict)
        ):
            raise ProbeError("Lambda execution did not return a valid observation", evidence)
        return observation

    def _resolve(self, host, maximum, evidence, family="ipv4"):
        request = {"kind": "dns", "host": host}
        if family != "ipv4":
            request["address_family"] = family
        result = self._invoke(request, evidence)
        addresses = result.get("addresses")
        if result.get("kind") != "dns" or not isinstance(addresses, list) or not addresses:
            raise ProbeError("DNS returned no nonempty address collection", evidence)
        versions = _families(family)
        try:
            parsed = [_address(address) for address in addresses]
            if any(address.version not in versions for address in parsed):
                raise ValueError("Unexpected address family")
        except ValueError as error:
            raise ProbeError(
                "DNS returned an invalid IP address or address family", evidence
            ) from error
        addresses = [str(address) for address in parsed]
        by_family = {
            f"ipv{version}": [str(address) for address in parsed if address.version == version]
            for version in versions
        }
        if "addresses_by_family" in result and result["addresses_by_family"] != by_family:
            raise ProbeError("DNS family evidence disagrees with its addresses", evidence)
        result.update(addresses=addresses, addresses_by_family=by_family)
        evidence.update(dns=result, resolved_addresses=addresses, addresses_by_family=by_family)
        try:
            requested_ip = str(_address(host))
        except ValueError:
            requested_ip = None
        if requested_ip is not None and addresses != [requested_ip]:
            raise ProbeError(
                "DNS returned different addresses for an IPv4 literal or IPv6 literal", evidence
            )
        if len(addresses) > maximum or len(set(addresses)) != len(addresses):
            raise ProbeError(
                "DNS address collection is duplicated or exceeds max_addresses", evidence
            )
        duration = result.get("dns_ms")
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(duration)
            or duration < 0
        ):
            raise ProbeError("DNS returned invalid timing evidence", evidence)
        if any(not values for values in by_family.values()):
            raise ProbeError("DNS did not establish every requested address family", evidence)
        return result

    def _run(self, spec):
        evidence = self._begin(
            spec["kind"], spec["target"], spec["port"], address_family=spec["address_family"]
        )
        dns = self._resolve(spec["host"], spec["max_addresses"], evidence, spec["address_family"])
        addresses = dns["addresses"]
        if spec["address_mode"] == "first":
            addresses = [values[0] for values in dns["addresses_by_family"].values()]
        evidence.update(
            resolved_addresses=dns["addresses"],
            tested_addresses=addresses,
            dns=dns,
            address_mode=spec["address_mode"],
            attempts=[],
            successes_required=spec["successes_required"],
            max_latency_ms=spec["max_latency_ms"],
            address_family=spec["address_family"],
            addresses_by_family=dns["addresses_by_family"],
            expected_addresses=spec["expected_addresses"],
            allowed_destination_cidrs=spec["allowed_destination_cidrs"],
        )
        if not _matches_dns(
            dns["addresses"],
            set(spec["expected_addresses"]) if spec["expected_addresses"] is not None else None,
            _networks(spec["allowed_destination_cidrs"], "allowed_destination_cidrs"),
        ):
            evidence.update(
                tested_addresses=[], address_results=[], destination_addresses_match=False
            )
            return self._finish(
                False,
                f"{spec['target']}: resolved addresses do not meet destination expectations; "
                "no connection attempted",
                evidence,
            )
        evidence["destination_addresses_match"] = True
        address_results = []
        for address in addresses:
            successes = 0
            for index in range(spec["attempts"]):
                if index:
                    time.sleep(spec["interval"])
                request = {
                    key: spec[key]
                    for key in (
                        "kind",
                        "port",
                        "connect_timeout",
                        "read_timeout",
                        "server_hostname",
                        "ca_pem",
                        "tls",
                        "path",
                        "host_header",
                        "body_contains",
                        "max_body_bytes",
                        "http_method",
                    )
                }
                request["resolved_ip"] = address
                observation = self._invoke(request, evidence)
                self._validate_observation(observation, spec, address, evidence)
                expected = _SUCCESS_OUTCOMES[spec["kind"]]
                passed = observation["outcome"] == expected
                if spec["kind"] == "http" and passed:
                    passed = observation["status"] in spec["expected_statuses"]
                    if spec["body_contains"] is not None:
                        if not observation["body_matches"] and observation["body_truncated"]:
                            raise ProbeError(
                                "Body assertion exceeds max_body_bytes; absence is unknown",
                                evidence,
                            )
                        passed = passed and observation["body_matches"]
                if spec["max_latency_ms"] is not None:
                    passed = passed and observation["elapsed_ms"] <= spec["max_latency_ms"]
                if self._networks:
                    source = observation.get("source_ip")
                    if source is None:
                        raise ProbeError("Cannot establish the required source address", evidence)
                    passed = passed and any(
                        _address(source).version == network.version and _address(source) in network
                        for network in self._networks
                    )
                evidence["attempts"].append(
                    {
                        "address": address,
                        "number": index + 1,
                        "passed": passed,
                        "observation": observation,
                    }
                )
                successes += passed
            address_results.append(
                {
                    "address": address,
                    "address_family": f"ipv{_address(address).version}",
                    "successes": successes,
                    "passed": successes >= spec["successes_required"],
                }
            )
        aggregate = all if spec["address_mode"] != "any" else any
        family_results = {
            f"ipv{version}": {
                "passed": aggregate(
                    item["passed"]
                    for item in address_results
                    if _address(item["address"]).version == version
                ),
                "addresses": [
                    item for item in address_results if _address(item["address"]).version == version
                ],
            }
            for version in _families(spec["address_family"])
        }
        passed = all(item["passed"] for item in family_results.values())
        evidence.update(address_results=address_results, family_results=family_results)
        return self._finish(
            passed,
            f"{spec['kind'].upper()} {spec['target']}:{spec['port']}: "
            f"{sum(item['passed'] for item in address_results)}/{len(address_results)} "
            "addresses passed",
            evidence,
        )

    @staticmethod
    def _validate_observation(observation, spec, address, evidence):
        outcomes = {
            "timeout",
            "refused",
            "unreachable",
            "connection_reset",
        }
        outcomes.add(_SUCCESS_OUTCOMES[spec["kind"]])
        if spec["tls"]:
            outcomes.add("tls_error")
        if spec["kind"] == "http":
            outcomes.add("http_error")
        if (
            observation.get("kind") != spec["kind"]
            or observation.get("resolved_ip") != address
            or type(observation.get("port")) is not int
            or observation["port"] != spec["port"]
        ):
            raise ProbeError("Lambda observation does not match the requested endpoint", evidence)
        if (
            not isinstance(observation.get("outcome"), str)
            or observation["outcome"] not in outcomes
        ):
            raise ProbeError("Lambda returned an unknown outcome", evidence)
        elapsed = observation.get("elapsed_ms")
        if (
            isinstance(elapsed, bool)
            or not isinstance(elapsed, (int, float))
            or not math.isfinite(elapsed)
            or elapsed < 0
        ):
            raise ProbeError("Lambda returned invalid elapsed time", evidence)
        if "source_ip" in observation:
            try:
                if not isinstance(observation["source_ip"], str):
                    raise ValueError("non-string source")
                source = _address(observation["source_ip"])
                if source.version != _address(address).version:
                    raise ValueError("Source and destination address families disagree")
            except ValueError as error:
                raise ProbeError("Lambda returned an invalid source address", evidence) from error
        success = observation["outcome"] in {"connected", "tls_verified", "http_response"}
        if success and (
            "source_ip" not in observation
            or type(observation.get("source_port")) is not int
            or not 1 <= observation["source_port"] <= 65535
        ):
            raise ProbeError("Successful connection is missing source evidence", evidence)
        if (
            success
            and spec["tls"]
            and (
                not isinstance(observation.get("tls_version"), str)
                or not observation["tls_version"]
                or not isinstance(observation.get("certificate_sha256"), str)
                or len(observation["certificate_sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in observation["certificate_sha256"])
            )
        ):
            raise ProbeError("Successful TLS connection is missing certificate evidence", evidence)
        if observation["outcome"] == "http_response":
            if (
                type(observation.get("status")) is not int
                or not 100 <= observation["status"] <= 599
            ):
                raise ProbeError("Lambda returned an invalid HTTP status", evidence)
            if spec["body_contains"] is not None and any(
                type(observation.get(key)) is not bool for key in ("body_matches", "body_truncated")
            ):
                raise ProbeError("Lambda returned incomplete body evidence", evidence)

    def _finish(self, passed, message, evidence):
        # The deployment dict stays shared so cleanup status updates after exit.
        return self.selector._decorate(CheckResult(passed, message, evidence), {})


def one_shot(selector, kind, target, options):
    deployment = {key: value for key, value in options.items() if key in _DEPLOYMENT_OPTIONS}
    check_options = {key: value for key, value in options.items() if key not in _DEPLOYMENT_OPTIONS}
    session = ProbeSession(selector, **deployment)
    if kind == "dns":
        _dns_expectations(target, address_family=session.address_family, **check_options)
        with session:
            return session.dns(target, **check_options)
    spec = session._prepare(kind, target, address_family=session.address_family, **check_options)
    with session:
        return session._run(spec)


def _dns_expectations(
    host: str,
    *,
    expected_addresses: Sequence[str] | None = None,
    allowed_cidrs: Sequence[str] = (),
    max_addresses: int = 32,
    address_family: str = "ipv4",
):
    """Share validation between one-shot checks and an already-open session."""
    ProbeSession._prepare("tcp", host, max_addresses=max_addresses, address_family=address_family)
    if expected_addresses is None and not allowed_cidrs:
        raise ValueError("DNS assertions need expected_addresses or allowed_cidrs")
    expected = _addresses(expected_addresses)
    if expected is not None and any(
        _address(address).version not in _families(address_family) for address in expected
    ):
        raise ValueError("Expected addresses disagree with address_family")
    return expected, _networks(allowed_cidrs, "allowed_cidrs")
