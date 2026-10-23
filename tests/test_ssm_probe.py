"""Offline SSM contracts, bound runtime evidence and honest instance-source checks."""

import json
import platform
from unittest.mock import Mock
from uuid import UUID

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber
from test_probe import ACCOUNT, REGION, session
from test_probe_session import observation
from test_workload_probes import ENI, INSTANCE, ZONE, interface, reservation

from aws_network_asserts import ProbeError, ProbeTimeoutError, RuleBuilder, WriteNotAllowedError
from aws_network_asserts.errors import CleanupWarning
from aws_network_asserts.probe_session import ProbeSession
from aws_network_asserts.ssm_probe import SsmProbeSession, _digest, _json, _script

NONCE = str(UUID(int=0))
COMMAND = str(UUID(int=1))
SECOND_COMMAND = str(UUID(int=2))


@pytest.fixture
def cloud(monkeypatch):
    from aws_network_asserts import ssm_probe

    monkeypatch.setattr(ssm_probe, "uuid4", lambda: UUID(int=0))
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    with (
        Stubber(rule.clients.client("sts", REGION)) as sts,
        Stubber(rule.clients.client("ec2", REGION)) as ec2,
        Stubber(rule.clients.client("ssm", REGION)) as ssm,
    ):
        sts.add_response("get_caller_identity", {"Account": ACCOUNT}, {})
        yield rule.instance(INSTANCE), ec2, ssm
        for stub in (sts, ec2, ssm):
            stub.assert_no_pending_responses()


def source(
    ec2, ssm, *, instance_changes=None, interface_changes=None, node_changes=None, interfaces=None
):
    interfaces = (
        [{**interface(), **(interface_changes or {})}] if interfaces is None else interfaces
    )
    item = reservation()
    item["Instances"][0]["Placement"] = {"AvailabilityZone": ZONE}
    item["Instances"][0]["NetworkInterfaces"] = [
        {"NetworkInterfaceId": row["NetworkInterfaceId"]} for row in interfaces
    ]
    item["Instances"][0].update(instance_changes or {})
    ec2.add_response("describe_instances", {"Reservations": [item]}, {"InstanceIds": [INSTANCE]})
    ec2.add_response(
        "describe_network_interfaces",
        {"NetworkInterfaces": interfaces},
        {"NetworkInterfaceIds": sorted(row["NetworkInterfaceId"] for row in interfaces)},
    )
    ssm.add_response(
        "describe_instance_information",
        {
            "InstanceInformationList": [
                {
                    "InstanceId": INSTANCE,
                    "ResourceType": "EC2Instance",
                    "PlatformType": "Linux",
                    "PingStatus": "Online",
                    **(node_changes or {}),
                }
            ]
        },
        {"Filters": [{"Key": "InstanceIds", "Values": [INSTANCE]}]},
    )


def envelope(probe, request, result, **changes):
    return {
        "version": 1,
        "nonce": NONCE,
        "handler_sha256": _digest(probe._source),
        "request_sha256": _digest(_json(request)),
        "runtime": {"platform": "Linux", "python": [3, 12, 0], "effective_uid": 0},
        "temporary_files": "not_created",
        "observation": result,
        **changes,
    }


def send(ssm, probe, request, *, command_id=COMMAND, response_changes=None, retries=None):
    parameters = {
        "commands": [_script(probe._source, request, NONCE, probe.execution_timeout)],
        "executionTimeout": [str(probe.execution_timeout)],
    }
    ssm.add_response(
        "send_command",
        {
            "Command": {
                "CommandId": command_id,
                "InstanceIds": [INSTANCE],
                "DocumentName": "AWS-RunShellScript",
                "Parameters": parameters,
                **(response_changes or {}),
            },
            **({"ResponseMetadata": {"RetryAttempts": retries}} if retries is not None else {}),
        },
        {
            "InstanceIds": [INSTANCE],
            "DocumentName": "AWS-RunShellScript",
            "Parameters": parameters,
            "TimeoutSeconds": 60,
            "Comment": f"aws-network-asserts {NONCE}",
            "CloudWatchOutputConfig": {"CloudWatchOutputEnabled": False},
        },
    )


def invocation(ssm, *, command_id=COMMAND, status="Success", output="", **changes):
    ssm.add_response(
        "get_command_invocation",
        {
            "CommandId": command_id,
            "InstanceId": INSTANCE,
            "DocumentName": "AWS-RunShellScript",
            "Status": status,
            "ResponseCode": 0,
            "StandardOutputContent": output,
            "StandardErrorContent": "",
            **changes,
        },
        {"CommandId": command_id, "InstanceId": INSTANCE},
    )


def packet_request(kind="tcp", target="service.example", **options):
    spec = ProbeSession._prepare(kind, target, **options)
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
    request["resolved_ip"] = "10.1.2.3"
    return request


@pytest.mark.parametrize("kind", ["tcp", "tls", "http"])
def test_instance_protocol_uses_bound_ssm_output_and_actual_source(cloud, kind):
    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector.named("application"), allow_write=True)
    for _ in range(2):
        source(ec2, ssm)
    dns_request = {"kind": "dns", "host": "service.example"}
    dns_result = {"kind": "dns", "addresses": ["10.1.2.3"], "dns_ms": 1}
    send(ssm, probe, dns_request)
    invocation(ssm, output=json.dumps(envelope(probe, dns_request, dns_result)))
    target = "https://service.example/health" if kind == "http" else "service.example"
    request = packet_request(kind, target)
    source(ec2, ssm)
    send(ssm, probe, request, command_id=SECOND_COMMAND)
    invocation(
        ssm,
        command_id=SECOND_COMMAND,
        output=json.dumps(envelope(probe, request, observation(kind))),
    )
    with probe:
        result = getattr(probe, kind)(target)
    assert result, result.message
    assert result.evidence["method"] == f"ssm_{kind}"
    assert result.evidence["transport"] == "ssm"
    assert result.evidence["source_context"]["host_firewall_tested"] is True
    assert result.evidence["source_context"]["execution_runtime"]["effective_uid"] == 0
    assert (
        result.evidence["attempts"][0]["observation"]["source_interface"]["network_interface_id"]
        == ENI
    )
    assert [row["command_id"] for row in result.evidence["commands"]] == [COMMAND, SECOND_COMMAND]
    assert result.evidence["deployment"]["cleanup"]["commands"] == "terminal"
    assert "application" in result.message
    json.dumps(result.to_dict())
    with pytest.raises(RuntimeError, match="more than once"):
        probe.__enter__()


def test_dns_uses_the_same_protocol_validation(cloud):
    selector, ec2, ssm = cloud
    probe = selector.ssm_probe_session(allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    request = {"kind": "dns", "host": "service.example"}
    result = {"kind": "dns", "addresses": ["10.1.2.3"], "dns_ms": 1}
    send(ssm, probe, request)
    invocation(ssm, output=json.dumps(envelope(probe, request, result)))
    with probe:
        checked = probe.dns("service.example", allowed_cidrs=["10.0.0.0/8"])
    assert checked
    assert checked.evidence["method"] == "ssm_dns"


@pytest.mark.parametrize("allowed", [False, None, "true", 1])
def test_write_gate_precedes_all_clients_and_reads(allowed, monkeypatch):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("No AWS calls"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(WriteNotAllowedError):
        SsmProbeSession(rule.instance(INSTANCE), allow_write=allowed)
    client.assert_not_called()


@pytest.mark.parametrize(
    "options",
    [
        {"command_timeout": 0},
        {"execution_timeout": True},
        {"poll_interval": 0},
        {"address_family": "bad"},
        {"shell": "echo unsafe"},
    ],
)
def test_invalid_session_options_are_local_errors(options, monkeypatch):
    rule = RuleBuilder(session=session(), config_mode="off", account_id=ACCOUNT)
    client = Mock(side_effect=AssertionError("No AWS calls"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises((ValueError, TypeError)):
        SsmProbeSession(rule.instance(INSTANCE), allow_write=True, **options)
    client.assert_not_called()


@pytest.mark.parametrize(
    "change",
    [
        {"PingStatus": "ConnectionLost"},
        {"PlatformType": "Windows"},
        {"ResourceType": "ManagedInstance"},
        {"InstanceId": "i-00000000000000000"},
        {"SourceId": "i-other"},
    ],
)
def test_unmanaged_offline_or_wrong_node_never_receives_commands(cloud, change):
    selector, ec2, ssm = cloud
    source(ec2, ssm, node_changes=change)
    with pytest.raises(ProbeError, match="online Linux"):
        with SsmProbeSession(selector, allow_write=True):
            pytest.fail("Invalid source must not enter")


def test_source_drift_fails_before_send_and_never_mutates_the_instance(cloud):
    selector, ec2, ssm = cloud
    source(ec2, ssm)
    item = reservation()
    item["Instances"][0]["Placement"] = {"AvailabilityZone": ZONE}
    ec2.add_response("describe_instances", {"Reservations": [item]}, {"InstanceIds": [INSTANCE]})
    ec2.add_response(
        "describe_network_interfaces",
        {"NetworkInterfaces": [{**interface(), "Groups": [{"GroupId": "sg-other"}]}]},
        {"NetworkInterfaceIds": [ENI]},
    )
    with pytest.raises(ProbeError, match="source changed"):
        with SsmProbeSession(selector, allow_write=True) as probe:
            probe.tcp("service.example")


@pytest.mark.parametrize(
    "change",
    [
        {"nonce": "stale"},
        {"handler_sha256": "0" * 64},
        {"request_sha256": "0" * 64},
        {"temporary_files": "left_over"},
        {"runtime": {"platform": "Linux", "python": [3, 9, 1], "effective_uid": 0}},
        {"observation": "connected"},
    ],
)
def test_successful_command_without_bound_probe_evidence_is_an_error(cloud, change):
    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    request = {"kind": "dns", "host": "service.example"}
    send(ssm, probe, request)
    result = {"kind": "dns", "addresses": ["10.1.2.3"], "dns_ms": 1}
    invocation(ssm, output=json.dumps(envelope(probe, request, result, **change)))
    with pytest.raises(ProbeError, match="confirm this probe"):
        with probe:
            probe.dns("service.example", expected_addresses=["10.1.2.3"])


@pytest.mark.parametrize(
    "output,changes",
    [
        ("", {}),
        ("{", {}),
        ("x" * 20000, {}),
        ("{}", {"StandardErrorContent": "truncated output"}),
        ("{}", {"ResponseCode": 1}),
        ("{}", {"Status": "Failed"}),
    ],
)
def test_missing_malformed_truncated_or_failed_output_never_counts_as_reachability(
    cloud, output, changes
):
    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    request = {"kind": "dns", "host": "service.example"}
    send(ssm, probe, request)
    invocation(ssm, output=output, **changes)
    with pytest.raises(ProbeError):
        with probe:
            probe.dns("service.example", expected_addresses=["10.1.2.3"])


def test_eventual_consistency_is_retried_within_the_poll_budget(cloud, monkeypatch):
    from aws_network_asserts import ssm_probe

    selector, ec2, ssm = cloud
    monkeypatch.setattr(ssm_probe.time, "sleep", lambda _: None)
    probe = SsmProbeSession(selector, allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    request = {"kind": "dns", "host": "service.example"}
    send(ssm, probe, request)
    ssm.add_client_error(
        "get_command_invocation",
        "InvocationDoesNotExist",
        expected_params={"CommandId": COMMAND, "InstanceId": INSTANCE},
    )
    result = {"kind": "dns", "addresses": ["10.1.2.3"], "dns_ms": 1}
    invocation(ssm, output=json.dumps(envelope(probe, request, result)))
    with probe:
        assert probe.dns("service.example", expected_addresses=["10.1.2.3"])


def test_poll_timeout_cancels_only_the_confirmed_command_and_keeps_unknown_stop_evidence(
    cloud, monkeypatch
):
    from aws_network_asserts import ssm_probe

    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    request = {"kind": "dns", "host": "service.example"}
    send(ssm, probe, request)
    times = iter([0, 61, 62, 62])
    monkeypatch.setattr(ssm_probe.time, "monotonic", lambda: next(times))
    ssm.add_response("cancel_command", {}, {"CommandId": COMMAND, "InstanceIds": [INSTANCE]})
    invocation(ssm, status="Cancelled")
    with (
        pytest.warns(CleanupWarning, match="best effort"),
        pytest.raises(ProbeTimeoutError) as caught,
    ):
        with probe:
            probe.dns("service.example", expected_addresses=["10.1.2.3"])
    command = caught.value.evidence["commands"][0]
    assert command["cancellation"] == "requested"
    assert command["cleanup"] == "terminal_after_cancellation"
    assert command["process_stop_confirmed"] is False


def test_protocol_specific_options_fail_before_sending_commands(cloud):
    selector, ec2, ssm = cloud
    source(ec2, ssm)
    with SsmProbeSession(selector, allow_write=True) as probe:
        with pytest.raises(ValueError, match="only apply"):
            probe.tcp("service.example", expected_statuses=[200])


def test_fixed_script_encodes_user_values_and_never_creates_probe_files(monkeypatch, capsys):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    request = {"kind": "dns", "host": "x'; touch /tmp/should-not-exist; $(echo unsafe)\n"}
    script = _script(b"def handler(event, context):\n    return event\n", request, NONCE, 30)
    assert request["host"] not in script
    assert "tempfile" not in script
    python = "\n".join(script.splitlines()[1:-1])
    exec(compile(python, "<fixed-ssm-script>", "exec"), {})
    result = json.loads(capsys.readouterr().out)
    assert result["observation"] == request
    assert result["temporary_files"] == "not_created"


def test_oversized_command_fails_locally():
    with pytest.raises(ValueError, match="48000"):
        _script(b"# fixed handler", {"data": "x" * 48000}, NONCE, 30)


def test_unconfirmed_target_identity_is_never_canceled_by_an_untrusted_id(cloud):
    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    request = {"kind": "dns", "host": "service.example"}
    send(ssm, probe, request, response_changes={"InstanceIds": ["i-00000000000000000"]})
    with pytest.warns(CleanupWarning, match="creation is unconfirmed"), pytest.raises(ProbeError):
        with probe:
            probe.dns("service.example", expected_addresses=["10.1.2.3"])
    assert probe.evidence["cleanup"]["commands"] == "unconfirmed"
    assert probe.evidence["commands"][0]["cleanup"] == "send_unconfirmed"


def test_native_poll_error_survives_failed_cancellation_and_warning_promotion(cloud):
    import warnings

    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    request = {"kind": "dns", "host": "service.example"}
    send(ssm, probe, request)
    ssm.add_client_error(
        "get_command_invocation",
        "AccessDeniedException",
        expected_params={"CommandId": COMMAND, "InstanceId": INSTANCE},
    )
    ssm.add_client_error(
        "cancel_command",
        "AccessDeniedException",
        expected_params={"CommandId": COMMAND, "InstanceIds": [INSTANCE]},
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error", CleanupWarning)
        with pytest.raises(ClientError, match="GetCommandInvocation") as caught:
            with probe:
                probe.dns("service.example", expected_addresses=["10.1.2.3"])
    assert caught.value.evidence["deployment"]["cleanup"]["commands"] == "unconfirmed"
    assert probe.evidence["commands"][0]["cancellation"] == "unconfirmed"


def test_multi_interface_source_does_not_claim_one_subnet_or_group_set(cloud):
    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True)
    secondary = interface()
    secondary.update(
        NetworkInterfaceId="eni-0123456789abcdef1",
        SubnetId="subnet-other",
        PrivateIpAddress="10.0.2.10",
        PrivateIpAddresses=[{"PrivateIpAddress": "10.0.2.10"}],
        Groups=[{"GroupId": "sg-other"}],
    )
    source(ec2, ssm, interfaces=[interface(), secondary])
    source(ec2, ssm, interfaces=[interface(), secondary])
    request = {"kind": "dns", "host": "service.example"}
    result = {"kind": "dns", "addresses": ["10.1.2.3"], "dns_ms": 1}
    send(ssm, probe, request)
    invocation(ssm, output=json.dumps(envelope(probe, request, result)))
    with probe:
        checked = probe.dns("service.example", expected_addresses=["10.1.2.3"])
    context = checked.evidence["source_context"]
    assert len(context["network_interfaces"]) == 2
    assert "subnet_id" not in context
    assert "security_group_ids" not in context


def test_dual_dns_requires_both_native_and_observed_families(cloud):
    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True, address_family="dual")
    changes = {"Ipv6Addresses": [{"Ipv6Address": "2001:db8:1::10"}]}
    source(ec2, ssm, interface_changes=changes)
    source(ec2, ssm, interface_changes=changes)
    request = {"kind": "dns", "host": "service.example", "address_family": "dual"}
    result = {"kind": "dns", "addresses": ["10.1.2.3", "2001:db8:2::10"], "dns_ms": 1}
    send(ssm, probe, request)
    invocation(ssm, output=json.dumps(envelope(probe, request, result)))
    with probe:
        checked = probe.dns("service.example", allowed_cidrs=["10.0.0.0/8", "2001:db8::/32"])
    assert checked
    assert checked.evidence["address_family"] == "dual"


@pytest.mark.parametrize("outcome", ["refused", "connected"])
def test_failed_connection_is_false_but_a_foreign_successful_source_is_an_error(cloud, outcome):
    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    dns_request = {"kind": "dns", "host": "service.example"}
    dns_result = {"kind": "dns", "addresses": ["10.1.2.3"], "dns_ms": 1}
    send(ssm, probe, dns_request)
    invocation(ssm, output=json.dumps(envelope(probe, dns_request, dns_result)))
    source(ec2, ssm)
    request = packet_request()
    send(ssm, probe, request, command_id=SECOND_COMMAND)
    observed = observation(outcome=outcome)
    if outcome == "connected":
        observed["source_ip"] = "10.99.99.99"
    invocation(
        ssm, command_id=SECOND_COMMAND, output=json.dumps(envelope(probe, request, observed))
    )
    with probe:
        if outcome == "connected":
            with pytest.raises(ProbeError, match="current instance ENI"):
                probe.tcp("service.example")
        else:
            checked = probe.tcp("service.example")
            assert not checked
            assert checked.evidence["attempts"][0]["observation"]["outcome"] == "refused"
    assert probe.evidence["cleanup"]["commands"] == "terminal"


@pytest.mark.parametrize("problem", ["foreign-owner", "missing-owner", "stopped"])
def test_unverified_ec2_instance_never_reaches_ssm_discovery_or_commands(cloud, problem):
    selector, ec2, _ = cloud
    item = reservation()
    item["Instances"][0]["Placement"] = {"AvailabilityZone": ZONE}
    if problem == "foreign-owner":
        item["OwnerId"] = "222222222222"
    elif problem == "missing-owner":
        del item["OwnerId"]
    else:
        item["Instances"][0]["State"]["Name"] = "stopped"
    ec2.add_response("describe_instances", {"Reservations": [item]}, {"InstanceIds": [INSTANCE]})
    with pytest.raises(RuntimeError):
        with SsmProbeSession(selector, allow_write=True):
            pytest.fail("Invalid instance must not enter")


def test_wrong_poll_identity_cancels_the_confirmed_owned_command_only(cloud):
    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    request = {"kind": "dns", "host": "service.example"}
    send(ssm, probe, request)
    invocation(ssm, InstanceId="i-00000000000000000")
    ssm.add_response("cancel_command", {}, {"CommandId": COMMAND, "InstanceIds": [INSTANCE]})
    invocation(ssm, status="Cancelled")
    with pytest.warns(CleanupWarning), pytest.raises(ProbeError, match="identity or status"):
        with probe:
            probe.dns("service.example", expected_addresses=["10.1.2.3"])
    assert probe.evidence["commands"][0]["cleanup"] == "terminal_after_cancellation"


def test_session_requires_the_explicit_owner_before_creating_clients(monkeypatch):
    rule = RuleBuilder(session=session(), config_mode="off")
    client = Mock(side_effect=AssertionError("No AWS calls"))
    monkeypatch.setattr(rule.clients.session, "client", client)
    with pytest.raises(ValueError, match="account"):
        rule.instance(INSTANCE).ssm_probe_session(allow_write=True)
    client.assert_not_called()


@pytest.mark.parametrize("body_error", [False, True])
def test_retried_send_keeps_unknown_earlier_commands_visible_after_returned_success(
    cloud, body_error
):
    import warnings

    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    request = {"kind": "dns", "host": "service.example"}
    result = {"kind": "dns", "addresses": ["10.1.2.3"], "dns_ms": 1}
    send(ssm, probe, request, retries=1)
    invocation(ssm, output=json.dumps(envelope(probe, request, result)))
    original = RuntimeError("Original session body error")
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("error" if body_error else "always", CleanupWarning)
        if body_error:
            with pytest.raises(RuntimeError) as caught:
                with probe:
                    assert probe.dns("service.example", expected_addresses=["10.1.2.3"])
                    raise original
            assert caught.value is original
        else:
            with probe:
                assert probe.dns("service.example", expected_addresses=["10.1.2.3"])
            assert any(item.category is CleanupWarning for item in recorded)
    record = probe.evidence["commands"][0]
    assert record["sdk_retry_attempts"] == 1
    assert record["earlier_commands_unconfirmed"] is True
    assert record["cleanup"] == "terminal"
    assert "cancellation" not in record
    assert probe.evidence["cleanup"]["commands"] == "unconfirmed"
    assert probe.evidence["cleanup"]["earlier_commands_unconfirmed"] is True


@pytest.mark.parametrize("field", ["CommandId", "InstanceId"])
def test_cancellation_poll_must_confirm_both_command_and_instance_and_preserve_timeout(
    cloud, monkeypatch, field
):
    import warnings

    from aws_network_asserts import ssm_probe

    selector, ec2, ssm = cloud
    probe = SsmProbeSession(selector, allow_write=True)
    source(ec2, ssm)
    source(ec2, ssm)
    request = {"kind": "dns", "host": "service.example"}
    send(ssm, probe, request)
    times = iter([0, 61, 62, 62])
    monkeypatch.setattr(ssm_probe.time, "monotonic", lambda: next(times))
    ssm.add_response("cancel_command", {}, {"CommandId": COMMAND, "InstanceIds": [INSTANCE]})
    foreign = SECOND_COMMAND if field == "CommandId" else "i-00000000000000000"
    invocation(ssm, status="Cancelled", **{field: foreign})
    with warnings.catch_warnings():
        warnings.simplefilter("error", CleanupWarning)
        with pytest.raises(ProbeTimeoutError, match="polling deadline"):
            with probe:
                probe.dns("service.example", expected_addresses=["10.1.2.3"])
    record = probe.evidence["commands"][0]
    assert record["command_id"] == COMMAND
    assert record["cleanup"] == "unconfirmed"
    assert "identity or status" in record["cancellation_error"]
    assert probe.evidence["cleanup"]["commands"] == "unconfirmed"
