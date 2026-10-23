"""Explicit coverage, convergence, and healthy controls for conclusive isolation."""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from ipaddress import IPv4Address
from types import MappingProxyType
from typing import Any

from .accounts import validate_account_id
from .errors import NetworkAssertionError, _attach_evidence
from .reachability import _INCONCLUSIVE_CODES, _explanation_codes
from .result import CheckResult


class CoverageError(NetworkAssertionError):
    def __init__(self, message: str, evidence: dict[str, Any]):
        super().__init__(message)
        self.evidence = evidence


@dataclass(frozen=True)
class CoverageCase:
    name: str
    account_id: str
    region: str
    source_id: str
    destination: str
    port: int | None = 443
    kind: str = "tcp"
    availability_zone: str | None = None

    def __post_init__(self):
        validate_account_id(self.account_id)
        for field in ("name", "region", "source_id", "destination"):
            if not isinstance(getattr(self, field), str) or not getattr(self, field).strip():
                raise ValueError(f"Coverage {field} must be nonempty")
        if self.kind not in {"tcp", "tls", "http", "dns", "ra"}:
            raise ValueError("Coverage kind must be tcp, tls, http, dns, or ra")
        if self.kind == "dns":
            if self.port is not None:
                raise ValueError("DNS coverage uses port=None")
        elif type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("Coverage port must be between 1 and 65535")
        if self.availability_zone is not None and (
            not isinstance(self.availability_zone, str) or not self.availability_zone.strip()
        ):
            raise ValueError("availability_zone must be nonempty when declared")


class CoverageMatrix:
    """Require every declared case and verify observations match their labels."""

    def __init__(self, cases: Sequence[CoverageCase]):
        cases = tuple(cases)
        if not cases or any(not isinstance(case, CoverageCase) for case in cases):
            raise ValueError("Declare a nonempty collection of CoverageCase objects")
        declared = {case.name: case for case in cases}
        if len(declared) != len(cases):
            raise ValueError("Coverage case names must be unique")
        self._cases = MappingProxyType(declared)
        self._results: dict[str, CheckResult] = {}
        self._errors: dict[str, str] = {}

    @property
    def cases(self) -> Mapping[str, CoverageCase]:
        """Keep the original declarations when checking for complete coverage."""
        return self._cases

    def __bool__(self):
        raise TypeError("Call CoverageMatrix.check() to require complete coverage")

    def record(self, case: CoverageCase | str, result: CheckResult) -> None:
        name = case.name if isinstance(case, CoverageCase) else case
        if name not in self.cases or (isinstance(case, CoverageCase) and self.cases[name] != case):
            raise ValueError("Result does not belong to a declared coverage case")
        if name in self._results:
            raise ValueError(f"Coverage case {name} already has a result")
        if not isinstance(result, CheckResult) or type(result.passed) is not bool:
            raise TypeError("Coverage requires an evaluated CheckResult")
        expected = self.cases[name]
        evidence = result.evidence
        source = evidence.get("source_context", evidence)
        source_id = source.get("subnet_id", evidence.get("resource_id"))
        if (
            evidence.get("transport") == "ssm"
            or source.get("transport") == "ssm"
            or evidence.get("method") in {"ssm_tcp", "ssm_tls", "ssm_http", "ssm_dns"}
        ):
            source_id = source.get("instance_id") if source.get("kind") == "instance" else None
            if (
                evidence.get("resource_id", source_id) != source_id
                or evidence.get("transport", "ssm") != "ssm"
                or source.get("transport", "ssm") != "ssm"
            ):
                source_id = None
        actual = {
            "account_id": source.get("account_id"),
            "region": source.get("region"),
            "source_id": source_id,
            "availability_zone": source.get("availability_zone"),
            "destination": evidence.get("target", evidence.get("destination")),
            "port": evidence.get("port"),
            "kind": evidence.get("kind"),
        }
        if expected.kind == "ra":
            request = evidence.get("request", {})
            packet = request.get("FilterAtSource", {})
            ports = packet.get("DestinationPortRange", {})
            actual.update(
                kind="ra",
                port=ports.get("FromPort")
                if ports.get("FromPort") == ports.get("ToPort")
                else None,
            )
        for field in (
            "account_id",
            "region",
            "source_id",
            "destination",
            "port",
            "kind",
            "availability_zone",
        ):
            if field == "availability_zone" and expected.availability_zone is None:
                continue
            if actual[field] != getattr(expected, field):
                raise CoverageError(
                    f"Coverage {name} has mismatched/missing {field}",
                    {
                        "expected": asdict(expected),
                        "actual": actual,
                        "result": result.to_dict(),
                    },
                )
        self._results[name] = result
        self._errors.pop(name, None)

    def report(self) -> dict[str, Any]:
        return {
            "expected_count": len(self.cases),
            "evaluated_count": len(self._results),
            "missing": [name for name in self.cases if name not in self._results],
            "cases": [
                {
                    "case": asdict(case),
                    "result": self._results[name].to_dict() if name in self._results else None,
                    "error": self._errors.get(name),
                }
                for name, case in self.cases.items()
            ],
        }

    def check(self) -> CheckResult:
        report = self.report()
        if report["missing"]:
            raise CoverageError(f"Coverage is incomplete: {', '.join(report['missing'])}", report)
        passed = all(result.passed for result in self._results.values())
        return CheckResult(
            passed,
            f"Coverage: {sum(result.passed for result in self._results.values())}"
            f"/{len(self.cases)} passed",
            report,
        )

    def run(self, check: Callable[[CoverageCase], CheckResult]) -> CheckResult:
        for name, case in self.cases.items():
            if name in self._results:
                continue
            try:
                self.record(case, check(case))
            except Exception as error:
                self._errors[name] = f"{type(error).__name__}: {error}"
                _attach_evidence(error, self.report(), "coverage_evidence")
                raise
        return self.check()


def _stability_limits(checks: int, interval: float) -> None:
    if type(checks) is not int or not 1 <= checks <= 100:
        raise ValueError("checks must be between 1 and 100")
    if (
        isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not math.isfinite(interval)
        or interval <= 0
    ):
        raise ValueError("interval must be positive and finite")


def consistently(
    check: Callable[[], CheckResult], *, checks: int = 5, interval: float = 2.0
) -> CheckResult:
    """Require a finite run of fresh successes, stopping at the first mismatch.

    This samples stability; it cannot establish uninterrupted availability
    between observations. Errors propagate with the partial sample intact.
    """
    _stability_limits(checks, interval)
    observations = []
    for index in range(checks):
        try:
            if index:
                time.sleep(interval)
            result = check()
            if not isinstance(result, CheckResult) or type(result.passed) is not bool:
                raise TypeError("consistently callback must return a conclusive CheckResult")
        except BaseException as error:
            _attach_evidence(
                error,
                {
                    "checks_required": checks,
                    "evaluated_count": len(observations),
                    "results": observations,
                },
                "stability_evidence",
            )
            raise
        observations.append(result)
        if not result.passed or index + 1 == checks:
            break
    last = observations[-1]
    return CheckResult(
        last.passed,
        f"Stability sample: {len(observations)}/{checks} checks; {last.message}",
        {
            **last.evidence,
            "stability": {
                "checks_required": checks,
                "evaluated_count": len(observations),
                "results": observations,
            },
        },
    )


def wait_for(
    check: Callable[[], CheckResult],
    *,
    timeout: float = 60.0,
    interval: float = 2.0,
    max_attempts: int = 20,
) -> CheckResult:
    """Wait on fresh, conclusive checks; exceptions propagate without retries.

    This is a convergence check, not an availability measurement. The deadline
    bounds sleeps/repetition, not an individual SDK request or callback.
    """
    for name, value in (("timeout", timeout), ("interval", interval)):
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(f"{name} must be positive and finite")
    if type(max_attempts) is not int or not 1 <= max_attempts <= 100:
        raise ValueError("max_attempts must be between 1 and 100")
    deadline = time.monotonic() + timeout
    observations = []
    for index in range(max_attempts):
        result = check()
        if not isinstance(result, CheckResult):
            raise TypeError("wait_for callback must return CheckResult")
        observations.append(result)
        if result:
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0 or index + 1 == max_attempts:
            break
        time.sleep(min(interval, remaining))
        if time.monotonic() >= deadline:
            break
    last = observations[-1]
    return CheckResult(
        bool(last),
        f"Convergence after {len(observations)} checks: {last.message}",
        {
            **last.evidence,
            "convergence": [result.to_dict() for result in observations],
        },
    )


def isolation_with_control(
    isolation: Callable[[], CheckResult],
    *,
    positive_control: Callable[[], CheckResult],
) -> CheckResult:
    """Require a healthy observed endpoint and a conclusive, matching RA denial.

    The RA check must use an explicit destination IPv4 (or destination_ip filter)
    and one TCP port so the control can be bound to the same endpoint. A failed
    control is a missing prerequisite, never a passing isolation check.
    """
    control = positive_control()
    if not isinstance(control, CheckResult) or not control:
        raise NetworkAssertionError("Isolation control did not establish a healthy endpoint")
    if control.evidence.get("method") not in {
        "lambda_tcp",
        "lambda_tls",
        "lambda_http",
        "ssm_tcp",
        "ssm_tls",
        "ssm_http",
    }:
        raise NetworkAssertionError("Isolation needs an observed TCP/TLS/HTTP positive control")
    denied = isolation()
    if not isinstance(denied, CheckResult):
        raise TypeError("isolation callback must return CheckResult")
    evidence = denied.evidence
    analysis = evidence.get("analysis", {})
    if analysis.get("Status") != "succeeded" or type(analysis.get("NetworkPathFound")) is not bool:
        raise NetworkAssertionError("Isolation requires a conclusive RA result")
    if _INCONCLUSIVE_CODES.intersection(_explanation_codes(analysis)):
        raise NetworkAssertionError("Isolation analysis contains inconclusive explanations")
    request = evidence.get("request", {})
    packet = request.get("FilterAtSource", {})
    target = packet.get("DestinationAddress", evidence.get("destination"))
    try:
        address = str(IPv4Address(str(target).removesuffix("/32")))
    except ValueError as error:
        raise ValueError("RA isolation needs an explicit destination IPv4 address") from error
    ports = packet.get("DestinationPortRange", {})
    port = ports.get("FromPort")
    if request.get("Protocol") != "tcp" or type(port) is not int or port != ports.get("ToPort"):
        raise ValueError("RA isolation must select one TCP destination port")
    if "attempts" in control.evidence:
        observed = any(
            attempt.get("passed") is True and attempt.get("address") == address
            for attempt in control.evidence["attempts"]
        )
        healthy = observed and any(
            item.get("passed") is True and item.get("address") == address
            for item in control.evidence.get("address_results", [])
        )
        control_port = control.evidence.get("port")
    else:
        observation = control.evidence.get("observation", {})
        healthy = (
            observation.get("outcome") == "connected" and observation.get("resolved_ip") == address
        )
        control_port = observation.get("port")
    if not healthy or control_port != port:
        raise NetworkAssertionError(
            "Positive control does not match the isolated endpoint and port"
        )
    if denied.passed != (analysis["NetworkPathFound"] is False):
        raise NetworkAssertionError("Isolation callback must use cannot_reach(), not can_reach()")
    return CheckResult(
        denied.passed,
        f"Healthy control verified; {denied.message}",
        {
            **evidence,
            "positive_control": control.to_dict(),
        },
    )
