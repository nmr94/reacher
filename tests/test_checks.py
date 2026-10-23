"""Coverage and controls reject unevaluated or mislabeled evidence."""

from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from aws_network_asserts import (
    CheckResult,
    CoverageCase,
    CoverageError,
    CoverageMatrix,
    NetworkAssertionError,
    isolation_with_control,
    wait_for,
)
from aws_network_asserts.checks import consistently

ACCOUNT = "111111111111"


def case(name="app-a", **kwargs):
    return CoverageCase(name, ACCOUNT, "eu-west-2", "subnet-1", "service.example", **kwargs)


def result(passed=True, **changes):
    evidence = {
        "kind": "tcp",
        "target": "service.example",
        "port": 443,
        "source_context": {
            "account_id": ACCOUNT,
            "region": "eu-west-2",
            "subnet_id": "subnet-1",
            "availability_zone": "eu-west-2a",
        },
    }
    return CheckResult(passed, "observed", {**evidence, **changes})


def test_matrix_requires_all_declared_cases_including_failed_ones():
    matrix = CoverageMatrix([case("a"), case("b")])
    with pytest.raises(TypeError):
        bool(matrix)
    matrix.record("a", result())
    with pytest.raises(CoverageError, match="incomplete") as caught:
        matrix.check()
    assert caught.value.evidence["missing"] == ["b"]
    matrix.record("b", result(False))
    summary = matrix.check()
    assert not summary
    assert summary.evidence["evaluated_count"] == 2
    assert summary.evidence["missing"] == []


@pytest.mark.parametrize(
    "field,value",
    [("kind", "http"), ("port", 80), ("target", "other.example"), ("source_context", {})],
)
def test_matrix_rejects_mislabeled_results(field, value):
    matrix = CoverageMatrix([case()])
    with pytest.raises(CoverageError, match="mismatched/missing"):
        matrix.record("app-a", result(**{field: value}))
    assert matrix.report()["evaluated_count"] == 0


def test_matrix_verifies_declared_az():
    matrix = CoverageMatrix([case(availability_zone="eu-west-2b")])
    with pytest.raises(CoverageError, match="availability_zone"):
        matrix.record("app-a", result())


def test_matrix_run_preserves_original_error_and_partial_report():
    matrix = CoverageMatrix([case("a"), case("b")])
    failure = RuntimeError("AWS unavailable")
    callback = Mock(side_effect=[result(), failure])
    with pytest.raises(RuntimeError) as caught:
        matrix.run(callback)
    assert caught.value is failure
    assert caught.value.coverage_evidence["evaluated_count"] == 1
    assert "RuntimeError" in matrix.report()["cases"][1]["error"]


def test_matrix_resume_does_not_repeat_recorded_checks():
    matrix = CoverageMatrix([case("a"), case("b")])
    matrix.record("a", result())
    callback = Mock(return_value=result())
    assert matrix.run(callback)
    callback.assert_called_once_with(case("b"))
    with pytest.raises(ValueError, match="already"):
        matrix.record("b", result())


@pytest.mark.parametrize("cases", [[], [case("a"), case("a")]])
def test_empty_or_duplicate_coverage_is_invalid(cases):
    with pytest.raises(ValueError):
        CoverageMatrix(cases)


def test_ra_coverage_uses_actual_packet_port():
    expected = CoverageCase("ra", ACCOUNT, "eu-west-2", "eni-1", "10.1.2.3", kind="ra")
    matrix = CoverageMatrix([expected])
    matrix.record(
        expected,
        CheckResult(
            True,
            "reachable",
            {
                "account_id": ACCOUNT,
                "region": "eu-west-2",
                "resource_id": "eni-1",
                "destination": "10.1.2.3",
                "request": {
                    "FilterAtSource": {"DestinationPortRange": {"FromPort": 443, "ToPort": 443}}
                },
            },
        ),
    )
    assert matrix.check()


def test_convergence_repeats_fresh_conclusive_checks_and_preserves_observations(monkeypatch):
    monkeypatch.setattr("aws_network_asserts.checks.time.monotonic", Mock(return_value=0))
    sleep = Mock()
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", sleep)
    check = Mock(side_effect=[result(False), result(False), result()])
    passed = wait_for(check, max_attempts=3)
    assert passed
    assert check.call_count == 3
    assert len(passed.evidence["convergence"]) == 3
    assert sleep.call_count == 2


def test_convergence_bounded_and_never_retries_unknown_errors(monkeypatch):
    monkeypatch.setattr("aws_network_asserts.checks.time.monotonic", Mock(return_value=0))
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", Mock())
    callback = Mock(return_value=result(False))
    assert not wait_for(callback, max_attempts=2)
    assert callback.call_count == 2
    failed = Mock(side_effect=NetworkAssertionError("unknown"))
    with pytest.raises(NetworkAssertionError, match="unknown"):
        wait_for(failed)
    failed.assert_called_once()


def test_convergence_deadline_bounds_sleeps(monkeypatch):
    monkeypatch.setattr("aws_network_asserts.checks.time.monotonic", Mock(side_effect=[0, 9, 10]))
    sleep = Mock()
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", sleep)
    callback = Mock(return_value=result(False))
    assert not wait_for(callback, timeout=10, interval=2)
    callback.assert_called_once()
    sleep.assert_called_once_with(1)


@pytest.mark.parametrize(
    "options",
    [{"timeout": True}, {"interval": 0}, {"max_attempts": 101}, {"timeout": float("inf")}],
)
def test_bad_convergence_limits_do_not_invoke_callback(options):
    callback = Mock()
    with pytest.raises(ValueError):
        wait_for(callback, **options)
    callback.assert_not_called()


def healthy():
    return result(
        method="lambda_tls",
        attempts=[{"passed": True, "address": "10.1.2.3"}],
        address_results=[{"address": "10.1.2.3", "passed": True}],
    )


def denied(passed=True, found=False, **changes):
    return CheckResult(
        passed,
        "RA denial",
        {
            "destination": "10.1.2.3",
            "request": {
                "Protocol": "tcp",
                "FilterAtSource": {"DestinationPortRange": {"FromPort": 443, "ToPort": 443}},
            },
            "analysis": {"Status": "succeeded", "NetworkPathFound": found},
            **changes,
        },
    )


def test_isolation_requires_healthy_matching_observed_control():
    callback = Mock(return_value=denied())
    verified = isolation_with_control(callback, positive_control=healthy)
    assert verified
    assert verified.to_dict()["evidence"]["positive_control"]["passed"]
    callback.assert_called_once()


def test_unhealthy_control_never_runs_isolation():
    callback = Mock()
    with pytest.raises(NetworkAssertionError, match="healthy"):
        isolation_with_control(callback, positive_control=lambda: result(False))
    callback.assert_not_called()


@pytest.mark.parametrize("isolated", [denied(False, True), denied(True, False)])
def test_control_does_not_invert_ra_semantics(isolated):
    result = isolation_with_control(lambda: isolated, positive_control=healthy)
    assert result.passed is isolated.passed


@pytest.mark.parametrize(
    "isolated",
    [
        denied(analysis={"Status": "failed", "NetworkPathFound": False}),
        denied(
            analysis={
                "Status": "succeeded",
                "NetworkPathFound": False,
                "Explanations": [{"ExplanationCode": "NO_PATH"}],
            }
        ),
        denied(
            request={
                "Protocol": "udp",
                "FilterAtSource": {"DestinationPortRange": {"FromPort": 443, "ToPort": 443}},
            }
        ),
        denied(False, False),
        denied(destination="10.1.2.4"),
    ],
)
def test_unknown_or_mismatched_isolation_never_passes(isolated):
    with pytest.raises((NetworkAssertionError, ValueError)):
        isolation_with_control(lambda: isolated, positive_control=healthy)


def test_legacy_tcp_observation_can_be_a_control():
    control = CheckResult(
        True,
        "connected",
        {
            "method": "lambda_tcp",
            "observation": {"outcome": "connected", "resolved_ip": "10.1.2.3", "port": 443},
        },
    )
    assert isolation_with_control(denied, positive_control=lambda: control)


def test_json_snapshot_handles_dates_nested_results_and_captures_cleanup_now():
    deployment = {"cleanup": "pending"}
    inner = result(deployment=deployment)
    outer = CheckResult(
        True, "both", {"result": inner, "capture": datetime(2026, 10, 22, tzinfo=timezone.utc)}
    )
    first = outer.to_dict()
    deployment["cleanup"] = "deleted"
    assert first["evidence"]["result"]["evidence"]["deployment"]["cleanup"] == "pending"
    assert outer.to_dict()["evidence"]["result"]["evidence"]["deployment"]["cleanup"] == "deleted"
    assert first["evidence"]["capture"] == "2026-10-22T00:00:00+00:00"


def test_isolation_control_must_meet_target_address_sampling_threshold():
    # address_mode=any: the overall control passes because another address is
    # healthy, while our isolation target got one success but missed its threshold.
    control = result(
        method="lambda_tls",
        port=443,
        attempts=[{"address": "10.1.2.3", "passed": True}, {"address": "10.1.2.4", "passed": True}],
        address_results=[
            {"address": "10.1.2.3", "passed": False},
            {"address": "10.1.2.4", "passed": True},
        ],
    )
    with pytest.raises(NetworkAssertionError, match="does not match"):
        isolation_with_control(denied, positive_control=lambda: control)


def test_matrix_preserves_callback_error_with_readonly_report_attribute():
    class UserError(RuntimeError):
        @property
        def coverage_evidence(self):
            return "user evidence"

    error = UserError("original")
    with pytest.raises(UserError) as caught:
        CoverageMatrix([case()]).run(Mock(side_effect=error))
    assert caught.value is error


def test_coverage_declarations_cannot_be_removed_to_hide_missing_cases():
    matrix = CoverageMatrix([case("a"), case("b")])
    matrix.record("a", result())
    with pytest.raises(TypeError):
        del matrix.cases["b"]
    with pytest.raises(AttributeError):
        matrix.cases = {}
    with pytest.raises(CoverageError, match="incomplete"):
        matrix.check()


def test_consistently_requires_every_fresh_sample_and_retains_cleanup(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", sleep)
    cleanup = {"cleanup": "pending"}
    samples = [CheckResult(True, str(index), {"deployment": cleanup}) for index in range(3)]
    check = Mock(side_effect=samples)
    observed = consistently(check, checks=3, interval=0.5)
    assert observed
    assert check.call_count == 3
    assert sleep.call_count == 2
    assert observed.evidence["stability"]["results"] == samples
    cleanup["cleanup"] = "deleted"
    assert (
        observed.evidence["stability"]["results"][0].evidence["deployment"]["cleanup"] == "deleted"
    )


def test_consistently_cannot_retry_a_false_sample_into_success(monkeypatch):
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", Mock())
    check = Mock(side_effect=[result(), result(False), result()])
    observed = consistently(check, checks=3)
    assert not observed
    assert check.call_count == 2
    assert observed.evidence["stability"]["evaluated_count"] == 2


def test_consistently_preserves_native_errors_and_partial_non_json_evidence(monkeypatch):
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", Mock())
    error = NetworkAssertionError("unknown state")
    error.evidence = {"original": True}
    first = CheckResult(True, "first passed", {"raw": b"bytes"})
    check = Mock(side_effect=[first, error])
    with pytest.raises(NetworkAssertionError) as caught:
        consistently(check, checks=3)
    assert caught.value is error
    assert error.evidence == {"original": True}
    assert error.stability_evidence["results"] == [first]
    assert check.call_count == 2


@pytest.mark.parametrize(
    "options",
    [{"checks": 0}, {"checks": True}, {"checks": 101}, {"interval": 0}, {"interval": float("inf")}],
)
def test_consistently_rejects_invalid_budgets_before_observation(options):
    check = Mock()
    with pytest.raises(ValueError):
        consistently(check, **options)
    check.assert_not_called()


@pytest.mark.parametrize("passed", [None, 1, "unknown"])
def test_consistently_rejects_inconclusive_results(passed):
    with pytest.raises(TypeError, match="conclusive"):
        consistently(lambda: CheckResult(passed, "invalid"))


def ssm_result(kind="tcp", *, include_subnet=True, source_changes=None, **changes):
    context = {
        "kind": "instance",
        "transport": "ssm",
        "instance_id": "i-0123456789abcdef0",
        "account_id": ACCOUNT,
        "region": "eu-west-2",
        "availability_zone": "eu-west-2a",
        **({"subnet_id": "subnet-1"} if include_subnet else {}),
        **(source_changes or {}),
    }
    return result(
        kind=kind,
        method=f"ssm_{kind}",
        transport="ssm",
        resource_id="i-0123456789abcdef0",
        port=None if kind == "dns" else 443,
        source_context=context,
        **changes,
    )


@pytest.mark.parametrize("kind", ["tcp", "tls", "http", "dns"])
@pytest.mark.parametrize("include_subnet", [True, False])
def test_ssm_coverage_uses_the_instance_identity_for_single_and_multiple_subnets(
    kind, include_subnet
):
    expected = CoverageCase(
        "instance-service",
        ACCOUNT,
        "eu-west-2",
        "i-0123456789abcdef0",
        "service.example",
        kind=kind,
        port=None if kind == "dns" else 443,
    )
    matrix = CoverageMatrix([expected])
    matrix.record(expected, ssm_result(kind, include_subnet=include_subnet))
    assert matrix.check()


@pytest.mark.parametrize(
    "source_changes,changes",
    [
        ({"instance_id": None}, {}),
        ({"instance_id": "i-other"}, {}),
        ({"kind": "workload_representative"}, {}),
        ({}, {"resource_id": "i-other"}),
        ({}, {"transport": "lambda"}),
    ],
)
def test_missing_or_contradictory_ssm_identity_cannot_fill_an_instance_coverage_case(
    source_changes, changes
):
    expected = CoverageCase(
        "instance-service", ACCOUNT, "eu-west-2", "i-0123456789abcdef0", "service.example"
    )
    matrix = CoverageMatrix([expected])
    observed = ssm_result(source_changes=source_changes)
    observed = CheckResult(True, observed.message, {**observed.evidence, **changes})
    with pytest.raises(CoverageError, match="source_id"):
        matrix.record(expected, observed)
    assert matrix.report()["evaluated_count"] == 0


def test_an_ssm_instance_result_does_not_fill_a_subnet_identity_case():
    matrix = CoverageMatrix([case()])
    with pytest.raises(CoverageError, match="source_id"):
        matrix.record("app-a", ssm_result())


@pytest.mark.parametrize("kind", ["tcp", "tls", "http"])
def test_ssm_observations_can_supply_a_matching_healthy_isolation_control(kind):
    control = ssm_result(
        kind,
        attempts=[{"passed": True, "address": "10.1.2.3"}],
        address_results=[{"address": "10.1.2.3", "passed": True}],
    )
    isolation = Mock(return_value=denied())
    checked = isolation_with_control(isolation, positive_control=lambda: control)
    assert checked
    assert checked.evidence["positive_control"]["evidence"]["method"] == f"ssm_{kind}"
    isolation.assert_called_once()


@pytest.mark.parametrize("problem", ["port", "address", "threshold"])
def test_ssm_control_must_still_establish_the_same_address_port_and_sample_threshold(problem):
    control = ssm_result(
        "tls",
        attempts=[{"passed": True, "address": "10.1.2.3"}],
        address_results=[{"address": "10.1.2.3", "passed": True}],
    )
    evidence = control.evidence
    if problem == "port":
        evidence["port"] = 444
    elif problem == "address":
        evidence["attempts"][0]["address"] = "10.1.2.4"
    else:
        evidence["address_results"][0]["passed"] = False
    with pytest.raises(NetworkAssertionError, match="does not match"):
        isolation_with_control(denied, positive_control=lambda: control)


@pytest.mark.parametrize("method", ["ssm_dns", "ssm_command", "ssm_unknown"])
def test_an_ssm_command_or_dns_success_cannot_supply_connection_health(method):
    control = CheckResult(True, "not a connection", {"method": method})
    isolation = Mock()
    with pytest.raises(NetworkAssertionError, match="observed TCP/TLS/HTTP"):
        isolation_with_control(isolation, positive_control=lambda: control)
    isolation.assert_not_called()
