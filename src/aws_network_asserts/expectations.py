"""English-like expectations over the existing synchronous checks.

Matchers describe checks. Only ``to()`` and ``not_to()`` evaluate them; neither
matcher construction nor collection declaration opens an AWS client.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from .accounts import validate_account_id
from .builder import (
    EndpointRule,
    EniRule,
    ResourceRule,
    RouteTableRule,
    SubnetRule,
    TransitGatewayRouteTableRule,
    TransitGatewayRule,
    VpcRule,
    _id,
)
from .checks import _stability_limits, wait_for
from .checks import consistently as check_consistently
from .errors import UnsupportedCheckError, _attach_evidence
from .path_evidence import require_resource_path, validate_components
from .probe_session import ProbeSession, _dns_expectations
from .reachability import _ipv4_host, _port, _resource, qualify_endpoint
from .result import CheckResult
from .routes import _requested_network, _validate_via


def _text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def _freeze(value):
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, dict):
        raise TypeError("Matcher options must be scalar values or sequences, not dictionaries")
    return value


def _options(values):
    return tuple(sorted((key, _freeze(value)) for key, value in values.items()))


def _identity(subject) -> dict[str, Any]:
    if isinstance(subject, _Population):
        return {"resources": [_identity(item) for item in subject.subjects]}
    if isinstance(subject, ProbeSession):
        return {
            **_identity(subject.selector),
            "source_kind": getattr(subject, "transport", "lambda"),
        }
    scope = subject.tgw if isinstance(subject, TransitGatewayRouteTableRule) else subject
    return {
        "resource_id": subject.route_table_id
        if isinstance(subject, TransitGatewayRouteTableRule)
        else subject.resource_id,
        "account_id": scope.account_id,
        "region": scope.region,
        "label": getattr(subject, "label", None),
    }


def _name(subject) -> str:
    if isinstance(subject, str):
        return subject
    if isinstance(subject, _Population):
        return f"discovered resources ({len(subject.subjects)})"
    identity = _identity(subject)
    name = identity["resource_id"]
    if identity["label"]:
        name = f"{identity['label']} ({name})"
    if identity.get("source_kind") == "lambda":
        name = f"Lambda probe from {name}"
    elif identity.get("source_kind") == "ssm":
        name = f"SSM probe from {name}"
    scope = "/".join(value for value in (identity["account_id"], identity["region"]) if value)
    return f"{name} [{scope}]"


def _supported(subject) -> bool:
    return isinstance(subject, (ResourceRule, TransitGatewayRouteTableRule, ProbeSession))


def _partition(subject) -> str:
    if isinstance(subject, ProbeSession):
        subject = subject.selector
    scope = subject.tgw if isinstance(subject, TransitGatewayRouteTableRule) else subject
    return scope.builder.clients.session.get_partition_for_region(scope.region)


def _source_key(subject) -> tuple[Any, ...]:
    identity = _identity(subject)
    identifier = identity["resource_id"]
    account, region = identity["account_id"], identity["region"]
    partition = _partition(subject)
    if isinstance(subject, EndpointRule):
        _resource(identifier, region, partition=partition)
        qualify_endpoint(
            identifier, account_id=subject.account_id, region=region, partition=partition
        )
    if isinstance(subject, EndpointRule) and identifier.startswith("arn:"):
        parts = identifier.split(":", 5)
        partition, account, region, identifier = (
            parts[1],
            parts[4],
            parts[3],
            parts[5].partition("/")[2],
        )
    return account, region, identifier, identity.get("source_kind"), partition


class _Matcher:
    grouped = False

    def __bool__(self):
        raise TypeError("A matcher is not an assertion; use expect(subject).to(matcher)")

    def _ready(self, negated):
        pass

    def _subject(self, subject):
        raise NotImplementedError

    def _evaluate(self, subject, negated):
        raise NotImplementedError

    def _expand(self):
        return (self,)

    def _counts(self):
        return 1, 0

    def _case_info(self, subject):
        return {"source": _identity(subject), "description": self.description}

    def eventually(
        self, *, timeout: float = 60.0, interval: float = 2.0, max_attempts: int = 20
    ) -> _Eventually:
        """Wait on fresh conclusive results; evaluation errors still propagate."""
        if isinstance(self, (_Eventually, _Consistently)):
            raise ValueError("Configure one convergence budget per matcher")
        return _Eventually(self, timeout, interval, max_attempts)

    def consistently(self, *, checks: int = 5, interval: float = 2.0) -> _Consistently:
        """Require every fresh observation to succeed; timing wrappers cannot stack."""
        if isinstance(self, (_Eventually, _Consistently)):
            raise ValueError(
                "Configure one timing budget per matcher; timing wrappers cannot stack"
            )
        return _Consistently(self, checks, interval)


@dataclass(frozen=True)
class _Eventually(_Matcher):
    matcher: _Matcher
    timeout: float
    interval: float
    max_attempts: int

    def __post_init__(self):
        for name in ("timeout", "interval"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"{name} must be positive and finite")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 100:
            raise ValueError("max_attempts must be between 1 and 100")

    @property
    def description(self):
        return (
            f"{self.matcher.description} within {self.timeout:g}s "
            f"(at most {self.max_attempts} checks)"
        )

    def _ready(self, negated):
        self.matcher._ready(negated)

    def _subject(self, subject):
        self.matcher._subject(subject)

    @property
    def grouped(self):
        return self.matcher.grouped

    def _expand(self):
        return tuple(replace(self, matcher=item) for item in self.matcher._expand())

    def _counts(self):
        checks, analyses = self.matcher._counts()
        return checks * self.max_attempts, analyses * self.max_attempts

    def _case_info(self, subject):
        return self.matcher._case_info(subject)

    def _evaluate(self, subject, negated):
        return wait_for(
            lambda: self.matcher._evaluate(subject, negated),
            timeout=self.timeout,
            interval=self.interval,
            max_attempts=self.max_attempts,
        )


@dataclass(frozen=True)
class _Consistently(_Matcher):
    matcher: _Matcher
    checks: int
    interval: float

    def __post_init__(self):
        _stability_limits(self.checks, self.interval)

    @property
    def grouped(self):
        return self.matcher.grouped

    @property
    def description(self):
        return f"{self.matcher.description} consistently for {self.checks} checks"

    def _ready(self, negated):
        self.matcher._ready(negated)

    def _subject(self, subject):
        self.matcher._subject(subject)

    def _expand(self):
        return tuple(replace(self, matcher=item) for item in self.matcher._expand())

    def _counts(self):
        checks, analyses = self.matcher._counts()
        return checks * self.checks, analyses * self.checks

    def _case_info(self, subject):
        return self.matcher._case_info(subject)

    def _evaluate(self, subject, negated):
        return check_consistently(
            lambda: self.matcher._evaluate(subject, negated),
            checks=self.checks,
            interval=self.interval,
        )


@dataclass(frozen=True)
class _Every:
    subjects: tuple[Any, ...]

    def __bool__(self):
        raise TypeError("A source collection is not an assertion; use expect(every(...)).to(...)")


@dataclass(frozen=True)
class _Population:
    subjects: tuple[Any, ...]


def _resource_population(values, *, expected=False):
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise TypeError("A resource population must be a finite sequence of scoped selectors")
    values = tuple(values)
    if expected and not values:
        raise ValueError("Declare a nonempty expected resource population")
    if any(not isinstance(item, (ResourceRule, TransitGatewayRouteTableRule)) for item in values):
        raise TypeError("Resource populations require scoped resource selectors")
    keys = tuple(_source_key(item) for item in values)
    for account, region, _, _, _ in keys:
        if not account or not region:
            raise ValueError("Resource populations need an explicit account and region")
        validate_account_id(account)
    if expected and len(set(keys)) != len(keys):
        raise ValueError("Expected resource populations must contain distinct resources")
    return values, keys


@dataclass(frozen=True)
class _ContainResources(_Matcher):
    resources: tuple[Any, ...]

    def __post_init__(self):
        _resource_population(self.resources, expected=True)

    @property
    def description(self):
        return "contain exactly resources " + ", ".join(_name(item) for item in self.resources)

    def _subject(self, subject):
        if not isinstance(subject, _Population):
            raise TypeError("contain_exactly_resources() requires a discovered selector sequence")
        _resource_population(subject.subjects)

    def _evaluate(self, subject, negated):
        actual, keys = _resource_population(subject.subjects)
        _, expected = _resource_population(self.resources, expected=True)
        missing = [
            _identity(item)
            for item, key in zip(self.resources, expected, strict=True)
            if key not in keys
        ]
        unexpected = [
            _identity(item) for item, key in zip(actual, keys, strict=True) if key not in expected
        ]
        duplicates = len(keys) != len(set(keys))
        matched = not missing and not unexpected and not duplicates
        return _negative(
            CheckResult(
                matched,
                f"Resource population: expected {len(expected)}, discovered {len(keys)}; "
                f"missing={len(missing)}, unexpected={len(unexpected)}, duplicates={duplicates}",
                {
                    "expected": [_identity(item) for item in self.resources],
                    "actual": [_identity(item) for item in actual],
                    "missing": missing,
                    "unexpected": unexpected,
                    "duplicates": duplicates,
                },
            ),
            negated,
        )


def contain_exactly_resources(
    *resources: ResourceRule | TransitGatewayRouteTableRule,
) -> _ContainResources:
    """Compare an observed population with explicit, nonempty scoped declarations."""
    return _ContainResources(resources)


def every(subjects: Sequence[Any]) -> _Every:
    """Declare a finite, nonempty source collection; discovery remains explicit."""
    if isinstance(subjects, (str, bytes)) or not isinstance(subjects, Sequence) or not subjects:
        raise ValueError("every() needs a nonempty finite sequence of source selectors")
    subjects = tuple(subjects)
    if any(not _supported(subject) for subject in subjects):
        raise TypeError("every() accepts resource selectors and explicit probe sessions")
    identities = [_source_key(subject) for subject in subjects]
    if any(not account or not region for account, region, _, _, _ in identities):
        raise ValueError(
            "every() needs sources with an explicit account and region; select an account "
            "or use an account-qualified endpoint ARN"
        )
    if len(set(identities)) != len(identities):
        raise ValueError("every() needs distinct source identities")
    return _Every(subjects)


@dataclass(frozen=True)
class Expectation:
    subject: Any

    def __bool__(self):
        raise TypeError("An expectation is incomplete; call to() or not_to()")

    def to(self, matcher: _Matcher, *, max_ra_analyses: int | None = None) -> CheckResult:
        return self._check(matcher, False, max_ra_analyses)

    def not_to(self, matcher: _Matcher, *, max_ra_analyses: int | None = None) -> CheckResult:
        return self._check(matcher, True, max_ra_analyses)

    def _prepare(self, matcher, negated):
        if not isinstance(matcher, _Matcher):
            raise TypeError("to() and not_to() require a network matcher")
        matcher._ready(negated)
        subjects = self.subject.subjects if isinstance(self.subject, _Every) else (self.subject,)
        cases = tuple((subject, check) for subject in subjects for check in matcher._expand())
        for subject, check in cases:
            check._subject(subject)
        return subjects, cases

    def _plan(self, matcher, negated, subjects, cases):
        return {
            "description": matcher.description,
            "negated": negated,
            "source_count": len(subjects),
            "case_count": len(cases),
            "max_checks": sum(check._counts()[0] for _, check in cases),
            "max_ra_analyses": sum(check._counts()[1] for _, check in cases),
            "cases": [
                {
                    **check._case_info(subject),
                    "max_checks": check._counts()[0],
                    "max_ra_analyses": check._counts()[1],
                }
                for subject, check in cases
            ],
        }

    def plan(self, matcher: _Matcher, *, negated: bool = False) -> dict[str, Any]:
        """Preview finite cases and an analysis upper bound without evaluating checks."""
        if type(negated) is not bool:
            raise ValueError("negated must be a boolean")
        subjects, cases = self._prepare(matcher, negated)
        return self._plan(matcher, negated, subjects, cases)

    def _check(self, matcher, negated, max_ra_analyses):
        if max_ra_analyses is not None and (
            type(max_ra_analyses) is not int or max_ra_analyses < 0
        ):
            raise ValueError("max_ra_analyses must be a nonnegative integer")
        subjects, cases = self._prepare(matcher, negated)
        plan = self._plan(matcher, negated, subjects, cases)
        if max_ra_analyses is not None and plan["max_ra_analyses"] > max_ra_analyses:
            raise ValueError(
                f"RA analysis upper bound {plan['max_ra_analyses']} exceeds "
                f"max_ra_analyses={max_ra_analyses}"
            )
        grouped = isinstance(self.subject, _Every) or matcher.grouped
        results = []
        for subject, check in cases:
            try:
                result = check._evaluate(subject, negated)
                if not isinstance(result, CheckResult) or type(result.passed) is not bool:
                    raise TypeError("A matcher must evaluate to a conclusive CheckResult")
            except BaseException as error:
                if grouped:
                    _attach_evidence(
                        error,
                        {
                            "expected_count": len(cases),
                            "evaluated_count": len(results),
                            "sources": [_identity(item) for item in subjects],
                            "results": list(results),
                            "failed_source": _identity(subject),
                            "failed_case": check._case_info(subject),
                            "plan": plan,
                        },
                        "coverage_evidence",
                    )
                raise
            description = (
                f"Expected {_name(subject)} {'not ' if negated else ''}to {check.description}"
            )
            results.append(
                CheckResult(
                    result.passed,
                    f"{description}\n{result.message}",
                    {
                        **result.evidence,
                        "case": check._case_info(subject),
                        "expectation": {
                            "source": _identity(subject),
                            "description": check.description,
                            "negated": negated,
                        },
                    },
                )
            )
        if grouped:
            failed = [result for result in results if not result.passed]
            result = CheckResult(
                not failed,
                f"Every declared case: {len(results) - len(failed)}/{len(results)} passed"
                + ("\n" + "\n".join(item.message for item in failed) if failed else ""),
                {
                    "expected_count": len(cases),
                    "evaluated_count": len(results),
                    "sources": [_identity(subject) for subject in subjects],
                    "results": results,
                    "plan": plan,
                },
            )
        else:
            result = results[0]
        if not result:
            error = AssertionError(result.message)
            _attach_evidence(error, result.evidence)
            _attach_evidence(error, result, "result")
            raise error
        return result


def expect(subject: Any) -> Expectation:
    """Start an assertion without evaluating or deploying anything."""
    if isinstance(subject, Sequence) and not isinstance(subject, (str, bytes)):
        subject = _Population(tuple(subject))
    if not isinstance(subject, (_Every, _Population)) and not _supported(subject):
        raise TypeError("expect() needs a resource selector, explicit probe session or every(...)")
    return Expectation(subject)


@dataclass(frozen=True)
class _Reach(_Matcher):
    destination: str | EndpointRule
    protocol: str = "tcp"
    port: int | None = 443
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    required: tuple[str, ...] = ()
    forbidden: tuple[str, ...] = ()

    def __post_init__(self):
        if isinstance(self.destination, EndpointRule):
            _resource(self.destination.resource_id, self.destination.region)
        elif isinstance(self.destination, str):
            if self.destination.startswith("arn:") or "-" in self.destination:
                parts = self.destination.split(":", 5)
                region = (
                    parts[3]
                    if self.destination.startswith("arn:") and len(parts) == 6
                    else "unscoped"
                )
                _resource(self.destination, region)
            else:
                _ipv4_host(self.destination, "destination")
        else:
            raise TypeError(
                "reach() needs an endpoint selector, resource ID/ARN or one IPv4 address"
            )
        if self.protocol not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp")
        _port(self.port, "port")
        _port(self.source_port, "source_port")
        for name in ("source_ip", "destination_ip"):
            if getattr(self, name) is not None:
                _ipv4_host(getattr(self, name), name)
        if (
            isinstance(self.destination, str)
            and not self.destination.startswith("arn:")
            and "-" not in self.destination
            and self.destination_ip is not None
            and _ipv4_host(self.destination, "destination")
            != _ipv4_host(self.destination_ip, "destination_ip")
        ):
            raise ValueError("destination and destination_ip specify different IP addresses")
        for value in (*self.required, *self.forbidden):
            _text(value, "path component")
        if set(self.required) & set(self.forbidden):
            raise ValueError("A component cannot be both required and forbidden")
        if self.required or self.forbidden:
            destination = (
                self.destination.resource_id
                if isinstance(self.destination, EndpointRule)
                else self.destination
            )
            require_resource_path(destination)
            arns = [
                item
                for item in (destination, *self.required, *self.forbidden)
                if item.startswith("arn:")
            ]
            arn_parts = arns[0].split(":", 5) if arns else ()
            region = (
                self.destination.region
                if isinstance(self.destination, EndpointRule)
                else arn_parts[3]
                if len(arn_parts) == 6
                else "unscoped"
            )
            validate_components(self.required, "through", region)
            validate_components(self.forbidden, "avoiding", region)

    @property
    def description(self):
        text = f"reach {_name(self.destination)} over {self.protocol.upper()}/{self.port}"
        if self.required:
            text += f" through {', '.join(self.required)}"
        if self.forbidden:
            text += f" avoiding {', '.join(self.forbidden)}"
        return text

    def over_tcp(self, port: int) -> _Reach:
        return replace(self, protocol="tcp", port=port)

    def over_udp(self, port: int) -> _Reach:
        return replace(self, protocol="udp", port=port)

    def at_address(self, address: str) -> _Reach:
        return replace(self, destination_ip=address)

    def from_address(self, address: str) -> _Reach:
        return replace(self, source_ip=address)

    def from_port(self, port: int) -> _Reach:
        return replace(self, source_port=port)

    def through(self, component: str) -> _Reach:
        return replace(self, required=(*self.required, _text(component, "path component")))

    def avoiding(self, component: str) -> _Reach:
        return replace(self, forbidden=(*self.forbidden, _text(component, "path component")))

    def _ready(self, negated):
        if negated and (self.required or self.forbidden):
            raise UnsupportedCheckError("Negated reachability cannot carry path constraints")

    def _subject(self, subject):
        if not isinstance(subject, EndpointRule):
            raise TypeError("reach() requires an endpoint source, such as an ENI or instance")
        partition = subject.builder.clients.session.get_partition_for_region(subject.region)
        qualify_endpoint(
            subject.resource_id,
            account_id=subject.account_id,
            region=subject.region,
            partition=partition,
        )
        destination, account = self.destination, subject.account_id
        if isinstance(destination, EndpointRule):
            if destination.region != subject.region:
                raise UnsupportedCheckError("Reachability Analyzer endpoints must share one region")
            if (
                destination.account_id is None
                and not destination.resource_id.startswith("arn:")
                and subject.builder.config_mode != "off"
            ):
                raise ValueError("Select an explicit destination account")
            account, destination = destination.account_id, destination.resource_id
        elif destination.startswith("arn:"):
            account = None
        qualify_endpoint(
            destination,
            account_id=account,
            region=subject.region,
            partition=partition,
            allow_ip=True,
        )
        validate_components(self.required, "through", subject.region, partition=partition)
        validate_components(self.forbidden, "avoiding", subject.region, partition=partition)

    def _counts(self):
        return 1, 1

    def _case_info(self, subject):
        destination = (
            _identity(self.destination)
            if isinstance(self.destination, EndpointRule)
            else self.destination
        )
        return {
            "source": _identity(subject),
            "destination": destination,
            "protocol": self.protocol,
            "port": self.port,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
        }

    def _evaluate(self, subject, negated):
        options = {
            "protocol": self.protocol,
            "port": self.port,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
        }
        if self.required:
            options["through"] = self.required
        if self.forbidden:
            options["avoiding"] = self.forbidden
        check = subject.cannot_reach if negated else subject.can_reach
        return check(self.destination, **options)


def reach(destination: str | EndpointRule) -> _Reach:
    return _Reach(destination)


@dataclass(frozen=True)
class _ReachEach(_Matcher):
    destinations: tuple[EndpointRule, ...]
    packet: _Reach
    ports: tuple[int, ...] = (443,)
    grouped = True

    def __post_init__(self):
        _resource_population(self.destinations, expected=True)
        if any(not isinstance(item, EndpointRule) for item in self.destinations):
            raise TypeError("reach_each() needs scoped endpoint selectors")
        if not self.ports or len(set(self.ports)) != len(self.ports):
            raise ValueError("Declare a nonempty collection of distinct destination ports")
        for port in self.ports:
            _port(port, "port")
            if port is None:
                raise ValueError("reach_each() requires explicit destination ports")
        # Validate every packet description before an assertion can run.
        self._expand()

    @property
    def description(self):
        return (
            f"reach each of {len(self.destinations)} destinations "
            f"over {self.packet.protocol.upper()} "
            f"on ports {', '.join(map(str, self.ports))}"
        )

    def _ready(self, negated):
        if negated:
            raise UnsupportedCheckError(
                "Negating reach_each() is ambiguous; declare individual modeled denials"
            )

    def _expand(self):
        return tuple(
            replace(self.packet, destination=destination, port=port)
            for destination in self.destinations
            for port in self.ports
        )

    def over_tcp(self, *ports: int) -> _ReachEach:
        return replace(self, packet=replace(self.packet, protocol="tcp"), ports=ports)

    def over_udp(self, *ports: int) -> _ReachEach:
        return replace(self, packet=replace(self.packet, protocol="udp"), ports=ports)

    def at_address(self, address: str) -> _ReachEach:
        return replace(self, packet=self.packet.at_address(address))

    def from_address(self, address: str) -> _ReachEach:
        return replace(self, packet=self.packet.from_address(address))

    def from_port(self, port: int) -> _ReachEach:
        return replace(self, packet=self.packet.from_port(port))

    def through(self, component: str) -> _ReachEach:
        return replace(self, packet=self.packet.through(component))

    def avoiding(self, component: str) -> _ReachEach:
        return replace(self, packet=self.packet.avoiding(component))


def reach_each(destinations: Sequence[EndpointRule]) -> _ReachEach:
    """Require each explicitly scoped endpoint, expanding one check per destination/port."""
    values, _ = _resource_population(destinations, expected=True)
    if any(not isinstance(item, EndpointRule) for item in values):
        raise TypeError("reach_each() needs scoped endpoint selectors")
    return _ReachEach(values, _Reach(values[0]))


@dataclass(frozen=True)
class _Route(_Matcher):
    destination: str
    target: str | None = None

    def __post_init__(self):
        _requested_network(self.destination)
        _validate_via(self.target)

    @property
    def description(self):
        return f"have a route to {self.destination}" + (
            f" via {self.target}" if self.target else ""
        )

    def via(self, target: str) -> _Route:
        return replace(self, target=target)

    def _ready(self, negated):
        network = _requested_network(self.destination)
        if negated and network.prefixlen != network.max_prefixlen:
            raise UnsupportedCheckError(
                "Negated route checks require one host address; incomplete CIDR coverage "
                "does not prove route absence"
            )

    def _subject(self, subject):
        if not isinstance(subject, (SubnetRule, RouteTableRule, TransitGatewayRouteTableRule)):
            raise TypeError("have_route_to() requires a subnet or route table source")

    def _evaluate(self, subject, negated):
        return _negative(subject.has_route_to(self.destination, via=self.target), negated)


def have_route_to(destination: str) -> _Route:
    return _Route(destination)


def _negative(result, negated):
    if not isinstance(result, CheckResult) or type(result.passed) is not bool:
        raise TypeError("A matcher must evaluate to a conclusive CheckResult")
    return CheckResult(not result.passed, result.message, result.evidence) if negated else result


@dataclass(frozen=True)
class _Relationship(_Matcher):
    operation: str
    description: str
    arguments: tuple[Any, ...] = ()

    def _subject(self, subject):
        accepted = {
            "is_recorded": ResourceRule,
            "in_subnet": EniRule,
            "in_vpc": EniRule,
            "has_peering_with": VpcRule,
            "has_attachment": TransitGatewayRule,
            "has_association": TransitGatewayRouteTableRule,
            "has_appliance_mode": TransitGatewayRule,
        }[self.operation]
        if not isinstance(subject, accepted):
            raise TypeError(f"{self.operation} requires a {accepted.__name__} source")
        if self.operation == "has_appliance_mode" and subject.account_id is None:
            raise ValueError("Select the TGW owner's account before checking appliance mode")

    def _evaluate(self, subject, negated):
        return _negative(getattr(subject, self.operation)(*self.arguments), negated)


def be_recorded() -> _Relationship:
    return _Relationship("is_recorded", "be recorded in Config")


def be_in_subnet(subnet_id: str) -> _Relationship:
    _id(subnet_id, "subnet-")
    return _Relationship("in_subnet", f"be in subnet {subnet_id}", (subnet_id,))


def be_in_vpc(vpc_id: str) -> _Relationship:
    _id(vpc_id, "vpc-")
    return _Relationship("in_vpc", f"be in VPC {vpc_id}", (vpc_id,))


def be_peered_with(other: str | VpcRule) -> _Relationship:
    if isinstance(other, str):
        _id(other, "vpc-")
    elif not isinstance(other, VpcRule):
        raise TypeError("be_peered_with() needs a VPC selector or VPC ID")
    return _Relationship("has_peering_with", f"be peered with {_name(other)}", (other,))


def have_attachment(vpc_id: str) -> _Relationship:
    _id(vpc_id, "vpc-")
    return _Relationship("has_attachment", f"have an attachment to {vpc_id}", (vpc_id,))


def have_association(attachment_id: str) -> _Relationship:
    _id(attachment_id, "tgw-attach-")
    return _Relationship(
        "has_association", f"have an association with {attachment_id}", (attachment_id,)
    )


def have_appliance_mode(vpc_id: str) -> _Relationship:
    _id(vpc_id, "vpc-")
    return _Relationship(
        "has_appliance_mode", f"have appliance mode enabled for {vpc_id}", (vpc_id,)
    )


@dataclass(frozen=True)
class _FirewallEndpoints(_Matcher):
    firewall_arn: str
    subnets: tuple[tuple[str, str], ...]

    @property
    def description(self):
        layout = ", ".join(f"{zone}: {subnet}" for zone, subnet in self.subnets)
        return f"have ready endpoints for {self.firewall_arn} in {layout}"

    def _ready(self, negated):
        if negated:
            raise UnsupportedCheckError(
                "An incomplete endpoint layout does not prove no inspection"
            )

    def _subject(self, subject):
        if not isinstance(subject, VpcRule):
            raise TypeError("have_firewall_endpoints() requires a VPC source")
        from .inspection import validate_firewall_request

        validate_firewall_request(subject, self.firewall_arn, dict(self.subnets))

    def _evaluate(self, subject, negated):
        return subject.has_firewall_endpoints(self.firewall_arn, subnets_by_az=dict(self.subnets))


def have_firewall_endpoints(
    firewall_arn: str, *, subnets_by_az: Mapping[str, str]
) -> _FirewallEndpoints:
    _text(firewall_arn, "firewall_arn")
    if not isinstance(subnets_by_az, Mapping) or not subnets_by_az:
        raise ValueError("Declare a nonempty mapping of Availability Zones to firewall subnets")
    subnets = tuple(subnets_by_az.items())
    for zone, subnet in subnets:
        _text(zone, "Availability Zone")
        _id(subnet, "subnet-")
    if len({subnet for _, subnet in subnets}) != len(subnets):
        raise ValueError("Each Availability Zone needs a distinct firewall subnet")
    return _FirewallEndpoints(firewall_arn, subnets)


@dataclass(frozen=True)
class _BidirectionalRoutes(_Matcher):
    destination: str
    source: str
    return_table: SubnetRule | RouteTableRule | TransitGatewayRouteTableRule
    via: str | None
    return_via: str | None

    @property
    def description(self):
        return f"have forward routes to {self.destination} and return routes to {self.source}"

    def _ready(self, negated):
        if negated:
            raise UnsupportedCheckError("Incomplete paired routes do not prove route absence")

    def _subject(self, subject):
        if isinstance(subject, TransitGatewayRouteTableRule):
            if not isinstance(self.return_table, TransitGatewayRouteTableRule):
                raise TypeError("TGW paired routes need a TGW return table")
            if _source_key(subject.tgw) != _source_key(self.return_table.tgw):
                raise ValueError("Forward and return tables must belong to the same scoped TGW")
            for target in (self.via, self.return_via):
                if target is not None:
                    _id(target, "tgw-attach-")
        elif isinstance(subject, (SubnetRule, RouteTableRule)):
            if not isinstance(self.return_table, (SubnetRule, RouteTableRule)):
                raise TypeError("VPC paired routes need a subnet or VPC return table")
            if subject.region != self.return_table.region:
                raise ValueError("Paired routes must stay in one region")
        else:
            raise TypeError("have_bidirectional_routes() requires a subnet or route table")

    def _evaluate(self, subject, negated):
        return subject.has_bidirectional_routes(
            self.destination,
            source=self.source,
            return_table=self.return_table,
            via=self.via,
            return_via=self.return_via,
        )


def have_bidirectional_routes(
    destination: str,
    *,
    source: str,
    return_table: SubnetRule | RouteTableRule | TransitGatewayRouteTableRule,
    via: str | None = None,
    return_via: str | None = None,
) -> _BidirectionalRoutes:
    if _requested_network(destination).version != _requested_network(source, "source").version:
        raise ValueError("Forward and return route ranges must use the same address family")
    if not isinstance(return_table, (SubnetRule, RouteTableRule, TransitGatewayRouteTableRule)):
        raise TypeError("return_table must be a subnet or route table selector")
    _validate_via(via)
    _validate_via(return_via)
    return _BidirectionalRoutes(destination, source, return_table, via, return_via)


@dataclass(frozen=True)
class _Propagation(_Matcher):
    table_id: str
    vpc_id: str | None = None

    def __post_init__(self):
        _id(self.table_id, "tgw-rtb-")
        if self.vpc_id is not None:
            _id(self.vpc_id, "vpc-")

    @property
    def description(self):
        return f"propagate routes from {self.vpc_id} into {self.table_id}"

    def from_vpc(self, vpc_id: str) -> _Propagation:
        return replace(self, vpc_id=vpc_id)

    def _ready(self, negated):
        if self.vpc_id is None:
            raise ValueError("Complete propagate_to(...).from_vpc(vpc_id) before evaluation")

    def _subject(self, subject):
        if not isinstance(subject, TransitGatewayRule):
            raise TypeError("propagate_to() requires a transit gateway source")

    def _evaluate(self, subject, negated):
        return _negative(subject.propagates(self.table_id).from_vpc(self.vpc_id), negated)


def propagate_to(table_id: str) -> _Propagation:
    return _Propagation(table_id)


@dataclass(frozen=True)
class _Protocol(_Matcher):
    kind: str
    target: str
    options: tuple[tuple[str, Any], ...] = ()

    def __post_init__(self):
        ProbeSession._prepare(self.kind, self.target, **dict(self.options))

    @property
    def description(self):
        options = dict(self.options)
        verb = {
            "tcp": "connect to",
            "tls": "establish verified TLS with",
            "http": options.get("http_method", "GET"),
        }[self.kind]
        text = f"{verb} {self.target}"
        if self.kind != "http":
            text += f" on port {options.get('port', 443)}"
        if "expected_statuses" in options:
            text += f" returning HTTP {', '.join(map(str, options['expected_statuses']))}"
        if options.get("body_contains") is not None:
            text += f" containing {options['body_contains']!r}"
        return text

    def with_options(self, **options) -> _Protocol:
        return replace(self, options=_options({**dict(self.options), **options}))

    def over_tcp(self, port: int) -> _Protocol:
        if self.kind != "tcp":
            raise TypeError("over_tcp() belongs to connect_to()")
        return self.with_options(port=port)

    def returning_status(self, *statuses: int) -> _Protocol:
        if self.kind != "http":
            raise TypeError("returning_status() belongs to get()")
        return self.with_options(expected_statuses=statuses)

    def containing(self, text: str) -> _Protocol:
        if self.kind != "http":
            raise TypeError("containing() belongs to get()")
        return self.with_options(body_contains=text)

    def for_every_address(self) -> _Protocol:
        return self.with_options(address_mode="all")

    def _ready(self, negated):
        if negated:
            raise UnsupportedCheckError("A failed observed connection cannot prove isolation")

    def _subject(self, subject):
        if not isinstance(subject, ProbeSession):
            raise TypeError("Observed matchers require an explicit probe_session() context")
        options = dict(self.options)
        family = subject._check_family(options.pop("address_family", None))
        subject._prepare(self.kind, self.target, address_family=family, **options)

    def _evaluate(self, subject, negated):
        return getattr(subject, self.kind)(self.target, **dict(self.options))


def get(url: str, **options: Any) -> _Protocol:
    return _Protocol("http", url, _options(options))


def connect_to(host: str, **options: Any) -> _Protocol:
    return _Protocol("tcp", host, _options(options))


def establish_tls(host: str, **options: Any) -> _Protocol:
    return _Protocol("tls", host, _options(options))


@dataclass(frozen=True)
class _DNS(_Matcher):
    host: str
    options: tuple[tuple[str, Any], ...] = ()

    def __post_init__(self):
        options = dict(self.options)
        allowed = {"expected_addresses", "allowed_cidrs", "max_addresses", "address_family"}
        if unknown := options.keys() - allowed:
            raise TypeError(f"Unknown DNS options: {', '.join(sorted(unknown))}")
        ProbeSession._prepare(
            "tcp",
            self.host,
            **{
                key: value
                for key, value in options.items()
                if key in {"max_addresses", "address_family"}
            },
        )
        if "expected_addresses" in options or "allowed_cidrs" in options:
            _dns_expectations(self.host, **options)

    @property
    def description(self):
        options = dict(self.options)
        text = f"resolve {self.host}"
        if options.get("expected_addresses") is not None:
            text += f" to {', '.join(options['expected_addresses'])}"
        if options.get("allowed_cidrs"):
            text += f" within {', '.join(options['allowed_cidrs'])}"
        return text

    def with_options(self, **options) -> _DNS:
        return replace(self, options=_options({**dict(self.options), **options}))

    def to_addresses(self, *addresses: str) -> _DNS:
        return self.with_options(expected_addresses=addresses)

    def within_cidrs(self, *cidrs: str) -> _DNS:
        return self.with_options(allowed_cidrs=cidrs)

    def _ready(self, negated):
        if negated:
            raise UnsupportedCheckError("Negated DNS observations are not isolation checks")
        _dns_expectations(self.host, **dict(self.options))

    def _subject(self, subject):
        if not isinstance(subject, ProbeSession):
            raise TypeError("resolve() requires an explicit probe_session() context")
        options = dict(self.options)
        family = subject._check_family(options.pop("address_family", None))
        _dns_expectations(self.host, address_family=family, **options)

    def _evaluate(self, subject, negated):
        return subject.dns(self.host, **dict(self.options))


def resolve(host: str, **options: Any) -> _DNS:
    return _DNS(host, _options(options))
