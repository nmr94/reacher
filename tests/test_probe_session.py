"""Protocol batches and sampling with real botocore request validation."""

import io
import json
from unittest.mock import Mock
from uuid import UUID
from zipfile import ZipFile

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from test_probe import ACCOUNT, GROUP, NAME, OPTIONS, REGION, SUBNET, create, delete, session, state

from aws_network_asserts import ProbeError, RuleBuilder, WriteNotAllowedError, probe
from aws_network_asserts.probe_session import ProbeSession


@pytest.fixture
def batch_cloud(monkeypatch):
    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with (
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("ec2", REGION)) as ec2,
        Stubber(rule.clients.client("lambda", REGION)) as functions,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        ec2.add_response(
            "describe_subnets",
            {
                "Subnets": [
                    {
                        "SubnetId": SUBNET,
                        "State": "available",
                        "OwnerId": ACCOUNT,
                        "VpcId": "vpc-1",
                        "AvailabilityZone": "eu-west-2a",
                    }
                ]
            },
            {"SubnetIds": [SUBNET]},
        )
        yield rule.subnet(SUBNET), functions, ec2
        for stub in (sts, ec2, functions):
            stub.assert_no_pending_responses()


def response(stub, request, observation, **kwargs):
    stream = io.BytesIO(json.dumps(observation).encode())
    stub.add_response(
        "invoke",
        {"StatusCode": 200, "Payload": stream, **kwargs},
        {
            "FunctionName": NAME,
            "InvocationType": "RequestResponse",
            "LogType": "None",
            "Payload": json.dumps(request).encode(),
        },
    )
    return stream


def dns(stub, addresses=("10.1.2.3",), host="service.example"):
    return response(
        stub,
        {"kind": "dns", "host": host},
        {"kind": "dns", "addresses": list(addresses), "dns_ms": 1},
    )


def observation(kind="tcp", address="10.1.2.3", **changes):
    item = {
        "kind": kind,
        "resolved_ip": address,
        "port": 443,
        "elapsed_ms": 5,
        "source_ip": "10.0.1.10",
        "source_port": 45000,
        "outcome": {"tcp": "connected", "tls": "tls_verified", "http": "http_response"}[kind],
    }
    if kind in {"tls", "http"}:
        item.update(tls_version="TLSv1.3", certificate_sha256="a" * 64)
    if kind == "http":
        item.update(status=200, body_matches=True, body_truncated=False)
    return {**item, **changes}


def packet(stub, spec, address="10.1.2.3", **changes):
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
    return response(stub, request, observation(spec["kind"], address, port=spec["port"], **changes))


def test_one_deployment_multiple_fresh_checks_cleanup_and_json(batch_cloud):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    streams = []
    checks = [
        ("tcp", "service.example", {}),
        ("tls", "service.example", {}),
        ("http", "https://service.example/health", {"body_contains": "ready"}),
    ]
    for kind, target, options in checks:
        streams.append(dns(stub))
        streams.append(packet(stub, ProbeSession._prepare(kind, target, **options)))
    streams.append(dns(stub))
    delete(stub)
    results = []
    with subnet.probe_session(
        **OPTIONS, source_kind="workload_representative", expected_source_cidrs=["10.0.1.0/24"]
    ) as batch:
        for kind, target, options in checks:
            results.append(getattr(batch, kind)(target, **options))
        results.append(batch.dns("service.example", expected_addresses=["10.1.2.3"]))
        assert all(results)
        assert results[0].evidence["deployment"]["cleanup"] == "pending"
    for result in results:
        evidence = result.to_dict()["evidence"]
        assert evidence["deployment"]["cleanup"] == "deleted"
        assert evidence["source_context"]["kind"] == "workload_representative"
        assert evidence["source_context"]["availability_zone"] == "eu-west-2a"
        assert evidence["source_context"]["security_group_ids"] == [GROUP]
    assert all(stream.closed for stream in streams)
    with pytest.raises(RuntimeError, match="active"):
        batch.tcp("service.example")
    with pytest.raises(RuntimeError, match="more than once"):
        batch.__enter__()


@pytest.mark.parametrize("mode,passed", [("all", False), ("any", True), ("first", True)])
def test_dns_coverage_modes_are_explicit(batch_cloud, mode, passed):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    dns(stub, ["10.1.2.3", "10.1.2.4"])
    spec = ProbeSession._prepare("tcp", "service.example", address_mode=mode)
    packet(stub, spec)
    if mode != "first":
        packet(stub, spec, "10.1.2.4", outcome="refused")
    delete(stub)
    with subnet.probe_session(**OPTIONS) as batch:
        result = batch.tcp("service.example", address_mode=mode)
    assert bool(result) is passed


def test_threshold_is_per_address_and_latency_is_measured(batch_cloud, monkeypatch):
    subnet, stub, _ = batch_cloud
    sleep = Mock()
    monkeypatch.setattr("aws_network_asserts.probe_session.time.sleep", sleep)
    create(stub)
    state(stub)
    dns(stub, ["10.1.2.3", "10.1.2.4"])
    spec = ProbeSession._prepare(
        "tcp", "service.example", attempts=3, successes_required=2, max_latency_ms=10, interval=0.1
    )
    for address in ("10.1.2.3", "10.1.2.4"):
        for elapsed in (5, 20, 5):
            packet(stub, spec, address, elapsed_ms=elapsed)
    delete(stub)
    with subnet.probe_session(**OPTIONS) as batch:
        result = batch.tcp(
            "service.example", attempts=3, successes_required=2, max_latency_ms=10, interval=0.1
        )
    assert result
    assert [item["successes"] for item in result.evidence["address_results"]] == [2, 2]
    assert len(result.evidence["attempts"]) == 6
    assert sleep.call_count == 4


@pytest.mark.parametrize("addresses", [[], ["10.0.0.1", "10.0.0.1"], ["::1"], [{}]])
def test_bad_dns_is_error_and_cleanup_has_serializable_error_evidence(batch_cloud, addresses):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    dns(stub, addresses)
    delete(stub)
    with pytest.raises(ProbeError) as caught:
        subnet.probe_tls("service.example", **OPTIONS)
    evidence = caught.value.evidence
    assert evidence["cleanup"] == "deleted"
    assert "failed_check" in evidence
    json.dumps(evidence)


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "http"},
        {"outcome": "connected"},
        {"elapsed_ms": -1},
        {"source_ip": None},
        {"source_port": True},
        {"certificate_sha256": "invalid"},
    ],
)
def test_malformed_tls_observations_raise(batch_cloud, change):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    dns(stub)
    spec = ProbeSession._prepare("tls", "service.example")
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
    response(stub, {**request, "resolved_ip": "10.1.2.3"}, {**observation("tls"), **change})
    delete(stub)
    with pytest.raises(ProbeError):
        subnet.probe_tls("service.example", **OPTIONS)


@pytest.mark.parametrize(
    "changes,passed",
    [
        ({"status": 503}, False),
        ({"body_matches": False}, False),
        ({"body_matches": True, "body_truncated": True}, True),
    ],
)
def test_http_status_and_body_predicates(batch_cloud, changes, passed):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    dns(stub)
    packet(
        stub,
        ProbeSession._prepare("http", "https://service.example/", body_contains="ready"),
        **changes,
    )
    delete(stub)
    assert (
        bool(subnet.probe_http("https://service.example/", **OPTIONS, body_contains="ready"))
        is passed
    )


def test_truncated_body_cannot_prove_absence(batch_cloud):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    dns(stub)
    packet(
        stub,
        ProbeSession._prepare("http", "https://service.example/", body_contains="ready"),
        body_matches=False,
        body_truncated=True,
    )
    delete(stub)
    with pytest.raises(ProbeError, match="absence is unknown"):
        subnet.probe_http("https://service.example/", **OPTIONS, body_contains="ready")


@pytest.mark.parametrize(
    "expected,allowed,passed",
    [
        (["10.1.2.3"], [], True),
        (["10.1.2.4"], [], False),
        (None, ["10.0.0.0/8"], True),
        (None, ["192.168.0.0/16"], False),
    ],
)
def test_dns_expectations(batch_cloud, expected, allowed, passed):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    dns(stub)
    delete(stub)
    result = subnet.probe_dns(
        "service.example", **OPTIONS, expected_addresses=expected, allowed_cidrs=allowed
    )
    assert bool(result) is passed


def test_invoke_permission_error_preserved_and_cleanup_runs(batch_cloud):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    stub.add_client_error("invoke", service_error_code="AccessDeniedException")
    delete(stub)
    with pytest.raises(ClientError) as caught:
        subnet.probe_tls("service.example", **OPTIONS)
    assert caught.value.evidence["cleanup"] == "deleted"


def test_cancelled_observation_read_closes_stream_and_deletes_function(batch_cloud):
    interrupt = KeyboardInterrupt("observation read interrupted")

    class InterruptedStream(io.BytesIO):
        def read(self, *args):
            raise interrupt

    subnet, stub, _ = batch_cloud
    stream = InterruptedStream()
    create(stub)
    state(stub)
    stub.add_response("invoke", {"StatusCode": 200, "Payload": stream})
    delete(stub)
    with pytest.raises(KeyboardInterrupt) as caught:
        subnet.probe_tls("service.example", **OPTIONS)
    assert caught.value is interrupt
    assert stream.closed
    assert interrupt.evidence["cleanup"] == "deleted"


@pytest.mark.parametrize(
    "method,target,options",
    [
        ("probe_tls", "service.example", {"attempts": 0}),
        ("probe_tls", "service.example", {"read_timeout": 10}),
        ("probe_http", "https://u:p@service.example", {}),
        ("probe_http", "https://service.example", {"http_method": "POST"}),
        ("probe_http", "https://service.example", {"http_method": "HEAD", "body_contains": "x"}),
        ("probe_dns", "service.example", {}),
        ("probe_dns", "service.example", {"expected_addresses": []}),
    ],
)
def test_validation_happens_before_deployment(method, target, options, monkeypatch):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("No AWS"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(ValueError):
        getattr(rule.subnet(SUBNET), method)(target, **OPTIONS, **options)
    client.assert_not_called()


@pytest.mark.parametrize(
    "method,target,options",
    [
        ("tcp", "service.example", {"expected_statuses": [200]}),
        ("tcp", "service.example", {"body_contains": "ready"}),
        ("tcp", "service.example", {"http_method": "GET"}),
        ("tcp", "service.example", {"max_body_bytes": 4096}),
        ("tcp", "service.example", {"read_timeout": 3.0}),
        ("tcp", "service.example", {"server_hostname": "service.example"}),
        ("tcp", "service.example", {"ca_pem": "unused"}),
        ("probe_tls", "service.example", {"expected_statuses": [200]}),
        ("probe_tls", "service.example", {"body_contains": "ready"}),
        ("probe_tls", "service.example", {"http_method": "GET"}),
        ("probe_tls", "service.example", {"max_body_bytes": 4096}),
        ("probe_http", "http://service.example", {"server_hostname": "service.example"}),
        ("probe_http", "http://service.example", {"ca_pem": "unused"}),
    ],
)
def test_criteria_a_protocol_cannot_evaluate_are_rejected_before_any_aws_call(
    method, target, options, monkeypatch
):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("No AWS"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(ValueError, match="only appl"):
        if method == "tcp":
            rule.subnet(SUBNET).probe_session(**OPTIONS).tcp(target, **options)
        else:
            getattr(rule.subnet(SUBNET), method)(target, **OPTIONS, **options)
    client.assert_not_called()


def test_session_rejects_unused_criteria_before_invocation_and_still_cleans_up(batch_cloud):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    delete(stub)
    with pytest.raises(ValueError, match="only apply to HTTP"):
        with subnet.probe_session(**OPTIONS) as batch:
            batch.tls("service.example", body_contains="ready")
    assert batch.evidence["cleanup"] == "deleted"


@pytest.mark.parametrize("method", ["probe_tls", "probe_http", "probe_dns", "probe_session"])
def test_all_new_deployments_require_explicit_permission(method):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with pytest.raises(WriteNotAllowedError):
        getattr(rule.subnet(SUBNET), method)(*(() if method == "probe_session" else ("x",)))


def test_representative_source_rejects_synthetic_group():
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with pytest.raises(ValueError, match="supplied workload"):
        rule.subnet(SUBNET).probe_session(
            **{**OPTIONS, "security_group_ids": None},
            auto_create_security_group=True,
            source_kind="workload_representative",
        )


def test_application_archive_contains_self_contained_modules():
    with ZipFile(io.BytesIO(probe._package(application=True))) as archive:
        assert set(archive.namelist()) == {"probe_handler.py", "application_handler.py"}
        for name in archive.namelist():
            compile(archive.read(name), name, "exec")


@pytest.mark.parametrize("source,passed", [("10.0.1.10", True), ("10.0.2.10", False)])
def test_source_cidr_expectation_and_tcp_wrapper(batch_cloud, source, passed):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    dns(stub)
    packet(stub, ProbeSession._prepare("tcp", "service.example"), source_ip=source)
    delete(stub)
    result = subnet.probe_tcp("service.example", **OPTIONS, expected_source_cidrs=["10.0.1.0/24"])
    assert bool(result) is passed
    assert result.evidence["source_context"]["kind"] == "synthetic"


def test_batch_refreshes_context_for_every_terminal_check(batch_cloud, monkeypatch):
    subnet, stub, _ = batch_cloud
    original = type(subnet)._context
    calls = []

    def context(selector):
        calls.append(selector.resource_id)
        return {**original(selector), "capture_sequence": len(calls)}

    monkeypatch.setattr(type(subnet), "_context", context)
    create(stub)
    state(stub)
    dns(stub)
    packet(stub, ProbeSession._prepare("tcp", "service.example"))
    dns(stub)
    packet(stub, ProbeSession._prepare("tcp", "service.example"))
    delete(stub)
    with subnet.probe_session(**OPTIONS) as batch:
        first = batch.tcp("service.example")
        second = batch.tcp("service.example")
    assert first.evidence["capture_sequence"] == 2
    assert second.evidence["capture_sequence"] == 3


def test_check_config_error_preserves_original_and_deletes_batch(batch_cloud, monkeypatch):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    delete(stub)
    with pytest.raises(RuntimeError, match="Config unavailable") as caught:
        with subnet.probe_session(**OPTIONS) as batch:
            monkeypatch.setattr(
                type(subnet), "_context", Mock(side_effect=RuntimeError("Config unavailable"))
            )
            batch.tls("service.example")
    assert caught.value.evidence["cleanup"] == "deleted"


@pytest.mark.parametrize(
    "options", [{"attempts": True}, {"interval": False}, {"expected_source_cidrs": None}]
)
def test_invalid_sampling_values_cannot_bypass_legacy_dispatch(options):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with pytest.raises(ValueError):
        rule.subnet(SUBNET).probe_tcp("service.example", **OPTIONS, **options)


def test_automatic_role_and_group_batch_cleanup_order(monkeypatch):
    from test_probe_role import ROLE_ARN, put, role_create, role_delete
    from test_probe_security_group import VPC, group_create, group_delete, subnet, visible

    monkeypatch.setattr(probe, "uuid4", lambda: UUID(int=0))
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with (
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("lambda", REGION)) as functions,
        Stubber(rule.clients.client("ec2", REGION)) as ec2,
        Stubber(rule.clients.client("iam", REGION)) as iam,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        # Discovery for source evidence consumes all pages before any creation.
        ec2.add_response(
            "describe_subnets", {"Subnets": [], "NextToken": "next"}, {"SubnetIds": [SUBNET]}
        )
        ec2.add_response(
            "describe_subnets",
            {
                "Subnets": [
                    {
                        "SubnetId": SUBNET,
                        "State": "available",
                        "OwnerId": "222222222222",
                        "VpcId": VPC,
                        "AvailabilityZone": "eu-west-2a",
                    }
                ]
            },
            {"SubnetIds": [SUBNET], "NextToken": "next"},
        )
        subnet(ec2, OwnerId="222222222222")
        group_create(ec2)
        visible(ec2)
        role_create(iam)
        put(iam)
        create(functions, execution_role_arn=ROLE_ARN)
        state(functions)
        dns(functions)
        packet(functions, ProbeSession._prepare("tls", "service.example"))
        delete(functions)
        group_delete(ec2)
        role_delete(iam)
        calls = []
        for client, events in (
            (functions.client, ("DeleteFunction",)),
            (ec2.client, ("DeleteSecurityGroup",)),
            (iam.client, ("DeleteRolePolicy", "DeleteRole")),
        ):
            for operation in events:
                client.meta.events.register(
                    f"before-parameter-build.*.{operation}",
                    lambda model, **kwargs: calls.append(model.name),
                )
        with rule.subnet(SUBNET).probe_session(
            allow_write=True, auto_create_execution_role=True, auto_create_security_group=True
        ) as batch:
            result = batch.tls("service.example")
        assert result
        lifecycle = result.evidence["deployment"]
        assert lifecycle["temporary_role"]["cleanup"] == "deleted"
        assert lifecycle["temporary_security_group"]["cleanup"] == "deleted"
        assert result.evidence["source_context"]["subnet_owner_id"] == "222222222222"
        assert calls == ["DeleteFunction", "DeleteSecurityGroup", "DeleteRolePolicy", "DeleteRole"]
        for stub in (sts, functions, ec2, iam):
            stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "url",
    [
        "https://service.example:0/",
        "https://ser\tvice.example/",
        "\nhttps://service.example/",
        "https://service.example/health\nx",
        "https://service.example/health x",
        "\x00https://service.example/",
    ],
)
def test_http_target_is_never_silently_changed_before_deployment(url, monkeypatch):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("No AWS calls"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(ValueError):
        rule.subnet(SUBNET).probe_http(url, **OPTIONS)
    client.assert_not_called()


def test_literal_dns_target_cannot_resolve_to_different_destination(batch_cloud):
    subnet, stub, _ = batch_cloud
    create(stub)
    state(stub)
    dns(stub, ["10.1.2.4"], host="10.1.2.3")
    delete(stub)
    with pytest.raises(ProbeError, match="IPv4 literal") as caught:
        subnet.probe_tls("10.1.2.3", **OPTIONS)
    assert caught.value.evidence["cleanup"] == "deleted"


@pytest.mark.parametrize("url", ["https://@service.example/", "https://:@service.example/"])
def test_empty_userinfo_is_still_rejected_before_deployment(url):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with pytest.raises(ValueError, match="without credentials"):
        rule.subnet(SUBNET).probe_http(url, **OPTIONS)
