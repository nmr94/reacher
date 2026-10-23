"""Matcher composition, native assertion semantics and finite-source coverage."""

from dataclasses import FrozenInstanceError
from unittest.mock import Mock

import boto3
import pytest
from botocore.stub import ANY, Stubber

from aws_network_asserts import AnalysisError, CheckResult, RuleBuilder, UnsupportedCheckError
from aws_network_asserts.builder import EndpointRule, SubnetRule, TransitGatewayRule
from aws_network_asserts.expectations import (
    be_in_subnet,
    be_in_vpc,
    be_peered_with,
    be_recorded,
    connect_to,
    contain_exactly_resources,
    establish_tls,
    every,
    expect,
    get,
    have_association,
    have_attachment,
    have_route_to,
    propagate_to,
    reach,
    reach_each,
    resolve,
)
from aws_network_asserts.probe_session import ProbeSession

ACCOUNT = "111111111111"
REGION = "eu-west-2"
SOURCE = "eni-0123456789abcdef0"
SECOND = "eni-0123456789abcdef1"
TARGET = "10.47.1.10"


@pytest.fixture
def rule():
    session = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION
    )
    return RuleBuilder(session=session, account_id=ACCOUNT, config_mode="off")


def make_probe(rule, *, address_family="ipv4", subnet_id="subnet-source"):
    return rule.subnet(subnet_id).probe_session(
        allow_write=True,
        execution_role_arn=f"arn:aws:iam::{ACCOUNT}:role/Probe",
        security_group_ids=["sg-source"],
        address_family=address_family,
    )


@pytest.fixture
def probe(rule):
    return make_probe(rule)


def test_reachability_matchers_evaluate_fresh_and_negation_calls_cannot_reach(rule, monkeypatch):
    positive = Mock(return_value=CheckResult(True, "modeled path exists"))
    negative = Mock(return_value=CheckResult(True, "conclusive modeled denial"))
    monkeypatch.setattr(EndpointRule, "can_reach", positive)
    monkeypatch.setattr(EndpointRule, "cannot_reach", negative)
    source = rule.eni(SOURCE)
    matcher = reach(TARGET).over_tcp(5432).from_address("10.1.1.10").from_port(45000)
    expectation = expect(source)
    assert positive.call_count == negative.call_count == 0
    assert expectation.to(matcher)
    assert expectation.to(matcher)
    assert expectation.not_to(matcher)
    assert positive.call_count == 2
    negative.assert_called_once_with(
        TARGET,
        protocol="tcp",
        port=5432,
        source_ip="10.1.1.10",
        destination_ip=None,
        source_port=45000,
    )


def test_path_constraints_are_passed_to_the_positive_check_only(rule, monkeypatch):
    check = Mock(return_value=CheckResult(True, "path matches"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    matcher = reach(rule.eni(SECOND)).over_udp(53).at_address(TARGET)
    constrained = matcher.through("tgw-hub").avoiding("igw-public")
    expect(rule.eni(SOURCE)).to(constrained)
    assert check.call_args.kwargs["through"] == ("tgw-hub",)
    assert check.call_args.kwargs["avoiding"] == ("igw-public",)
    assert check.call_args.kwargs["destination_ip"] == TARGET
    check.reset_mock()
    with pytest.raises(UnsupportedCheckError, match="path constraints"):
        expect(rule.eni(SOURCE)).not_to(constrained)
    check.assert_not_called()
    assert matcher.required == matcher.forbidden == ()


def test_eventually_retries_fresh_false_results_then_asserts_success(rule, monkeypatch):
    check = Mock(side_effect=[CheckResult(False, "not ready"), CheckResult(True, "ready")])
    sleep = Mock()
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", sleep)
    matcher = reach(TARGET).over_tcp(5432).eventually(timeout=60, interval=2, max_attempts=3)
    assert check.call_count == sleep.call_count == 0
    result = expect(rule.eni(SOURCE)).to(matcher)
    assert result
    assert check.call_count == 2
    sleep.assert_called_once_with(2)
    assert [item["passed"] for item in result.evidence["convergence"]] == [False, True]


def test_eventually_does_not_retry_native_errors(rule, monkeypatch):
    error = AnalysisError("unsupported component")
    check = Mock(side_effect=error)
    sleep = Mock()
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", sleep)
    with pytest.raises(AnalysisError) as caught:
        expect(rule.eni(SOURCE)).to(reach(TARGET).eventually())
    assert caught.value is error
    assert check.call_count == 1
    sleep.assert_not_called()


def test_eventually_exhaustion_asserts_after_all_allowed_checks(rule, monkeypatch):
    check = Mock(return_value=CheckResult(False, "still blocked"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", Mock())
    with pytest.raises(AssertionError, match="still blocked") as caught:
        expect(rule.eni(SOURCE)).to(reach(TARGET).eventually(max_attempts=3))
    assert check.call_count == 3
    assert len(caught.value.evidence["convergence"]) == 3


@pytest.mark.parametrize("options", [{"timeout": False}, {"interval": 0}, {"max_attempts": True}])
def test_eventually_validates_limits_before_evaluation(options):
    with pytest.raises(ValueError):
        reach(TARGET).eventually(**options)


def test_nested_convergence_cannot_multiply_the_declared_attempt_budget():
    with pytest.raises(ValueError, match="one convergence budget"):
        reach(TARGET).eventually(max_attempts=3).eventually(max_attempts=3)


def test_immutable_options_do_not_follow_the_callers_mutable_lists():
    statuses = [200, 202]
    initial = get("https://api.example/health", expected_statuses=statuses)
    statuses.append(500)
    changed = initial.returning_status(204)
    assert dict(initial.options)["expected_statuses"] == (200, 202)
    assert dict(changed.options)["expected_statuses"] == (204,)
    with pytest.raises(FrozenInstanceError):
        changed.target = "https://another.example"


@pytest.mark.parametrize(
    "factory",
    [
        lambda rule: expect(rule.eni(SOURCE)),
        lambda rule: reach(TARGET),
        lambda rule: have_route_to("10.47.0.0/16"),
        lambda rule: propagate_to("tgw-rtb-test"),
        lambda rule: resolve("api.example"),
        lambda rule: every([rule.eni(SOURCE)]),
    ],
)
def test_incomplete_expressions_cannot_be_truth_tested(rule, factory):
    with pytest.raises(TypeError):
        bool(factory(rule))


@pytest.mark.parametrize("subjects", [[], (), "eni-source", {"source": "eni-source"}, [None]])
def test_every_rejects_empty_and_invalid_declarations(subjects):
    with pytest.raises((ValueError, TypeError)):
        every(subjects)


def test_every_snapshots_sources_and_rejects_duplicate_scoped_identities(rule):
    subjects = [rule.eni(SOURCE)]
    declared = every(subjects)
    subjects.append(rule.eni(SECOND))
    assert len(declared.subjects) == 1
    with pytest.raises(ValueError, match="distinct"):
        every([rule.eni(SOURCE), rule.eni(SOURCE)])
    other = rule.in_account("222222222222").eni(SOURCE)
    assert len(every([rule.eni(SOURCE), other]).subjects) == 2


def test_every_rejects_typed_id_and_arn_aliases_of_one_source(rule):
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:network-interface/{SOURCE}"
    with pytest.raises(ValueError, match="distinct"):
        every([rule.eni(SOURCE), rule.resource(arn)])


def test_every_matches_explicit_arn_scope_to_an_unscoped_arn_source(rule):
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:network-interface/{SOURCE}"
    unscoped = RuleBuilder(session=rule.clients.session, config_mode="off")
    with pytest.raises(ValueError, match="distinct"):
        every([rule.eni(SOURCE), unscoped.resource(arn)])


@pytest.mark.parametrize("include_arn_alias", [False, True])
def test_every_rejects_bare_unscoped_sources_before_they_can_inflate_coverage(
    rule, include_arn_alias
):
    unscoped = RuleBuilder(session=rule.clients.session, config_mode="off")
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:network-interface/{SOURCE}"
    sources = [unscoped.eni(SOURCE)]
    if include_arn_alias:
        sources.append(unscoped.resource(arn))
    with pytest.raises(ValueError, match="explicit account and region"):
        every(sources)
    assert len(every([unscoped.resource(arn)]).subjects) == 1


def test_single_unscoped_expectation_remains_supported(rule, monkeypatch):
    unscoped = RuleBuilder(session=rule.clients.session, config_mode="off")
    check = Mock(return_value=CheckResult(True, "modeled path"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    assert expect(unscoped.eni(SOURCE)).to(reach(TARGET))
    check.assert_called_once()


def test_every_retains_distinct_owners_when_normalizing_endpoint_arns(rule):
    other = rule.in_account("222222222222")
    arn = f"arn:aws:ec2:{REGION}:222222222222:network-interface/{SOURCE}"
    assert len(every([rule.eni(SOURCE), other.resource(arn)]).subjects) == 2


def test_every_evaluates_all_conclusive_failures_and_preserves_all_results(rule, monkeypatch):
    calls = []

    def check(subject, destination, **options):
        calls.append(subject.resource_id)
        return CheckResult(subject.resource_id == SECOND, f"checked {subject.resource_id}")

    monkeypatch.setattr(EndpointRule, "can_reach", check)
    with pytest.raises(AssertionError) as caught:
        expect(every([rule.eni(SOURCE), rule.eni(SECOND)])).to(reach(TARGET))
    assert calls == [SOURCE, SECOND]
    evidence = caught.value.evidence
    assert evidence["expected_count"] == evidence["evaluated_count"] == 2
    assert [item.passed for item in evidence["results"]] == [False, True]


def test_every_native_errors_keep_the_original_object_and_its_evidence(rule, monkeypatch):
    error = AnalysisError("unsupported component")
    error.evidence = {"analysis_id": "nia-original"}
    check = Mock(side_effect=[CheckResult(True, "first denied"), error])
    monkeypatch.setattr(EndpointRule, "cannot_reach", check)
    with pytest.raises(AnalysisError) as caught:
        expect(every([rule.eni(SOURCE), rule.eni(SECOND)])).not_to(reach(TARGET))
    assert caught.value is error
    assert error.evidence == {"analysis_id": "nia-original"}
    assert error.coverage_evidence["evaluated_count"] == 1
    assert error.coverage_evidence["expected_count"] == 2
    assert error.coverage_evidence["failed_source"]["resource_id"] == SECOND


def test_every_diagnostic_serialization_cannot_replace_a_native_error(rule, monkeypatch):
    error = AnalysisError("unsupported component")
    error.evidence = {"analysis_id": "nia-original"}
    first = CheckResult(True, "first checked", {"binary_diagnostic": b"raw"})
    check = Mock(side_effect=[first, error])
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    with pytest.raises(AnalysisError) as caught:
        expect(every([rule.eni(SOURCE), rule.eni(SECOND)])).to(reach(TARGET))
    assert caught.value is error
    assert error.evidence == {"analysis_id": "nia-original"}
    assert error.coverage_evidence["evaluated_count"] == 1
    assert error.coverage_evidence["results"][0].evidence["binary_diagnostic"] == b"raw"


def test_every_error_retains_live_cleanup_evidence_of_prior_sources(rule, monkeypatch):
    deployment = {"cleanup": "pending"}
    first = CheckResult(True, "first checked", {"deployment": deployment})
    error = AnalysisError("second check unsupported")
    monkeypatch.setattr(EndpointRule, "can_reach", Mock(side_effect=[first, error]))
    with pytest.raises(AnalysisError) as caught:
        expect(every([rule.eni(SOURCE), rule.eni(SECOND)])).to(reach(TARGET))
    deployment["cleanup"] = "deleted"
    assert (
        caught.value.coverage_evidence["results"][0].evidence["deployment"]["cleanup"] == "deleted"
    )


def test_all_subject_types_are_checked_before_any_collection_evaluation(rule, monkeypatch):
    check = Mock(side_effect=AssertionError("No evaluation"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    with pytest.raises(TypeError, match="endpoint source"):
        expect(every([rule.eni(SOURCE), rule.subnet("subnet-other")])).to(reach(TARGET))
    check.assert_not_called()


def test_route_negative_inverts_only_a_conclusive_route_result(rule, monkeypatch):
    check = Mock(return_value=CheckResult(False, "no route for sample"))
    monkeypatch.setattr(SubnetRule, "has_route_to", check)
    result = expect(rule.subnet("subnet-source")).not_to(have_route_to("198.51.100.1/32"))
    assert result
    check.assert_called_once_with("198.51.100.1/32", via=None)
    error = RuntimeError("AccessDenied")
    check.side_effect = error
    with pytest.raises(RuntimeError) as caught:
        expect(rule.subnet("subnet-source")).not_to(have_route_to("198.51.100.1/32"))
    assert caught.value is error


@pytest.mark.parametrize("destination", ["10.47.0.0/16", "2001:db8::/64"])
def test_negative_cidr_route_claim_is_rejected_before_api_calls(rule, monkeypatch, destination):
    check = Mock(side_effect=AssertionError("No API"))
    monkeypatch.setattr(SubnetRule, "has_route_to", check)
    with pytest.raises(UnsupportedCheckError, match="one host address"):
        expect(rule.subnet("subnet-source")).not_to(have_route_to(destination))
    check.assert_not_called()


def test_negative_host_route_with_target_describes_only_the_selected_target(rule, monkeypatch):
    check = Mock(
        return_value=CheckResult(False, "sample routes via igw-other, expected nat-egress")
    )
    monkeypatch.setattr(SubnetRule, "has_route_to", check)
    result = expect(rule.subnet("subnet-source")).not_to(
        have_route_to("198.51.100.1/32").via("nat-egress")
    )
    assert "not to have a route to 198.51.100.1/32 via nat-egress" in result.message
    assert "igw-other" in result.message
    check.assert_called_once_with("198.51.100.1/32", via="nat-egress")


@pytest.mark.parametrize(
    "target", [" nat-egress", "nat-egress\n", "nat-\x00egress", "nat-\u200begress"]
)
def test_malformed_route_targets_cannot_produce_a_passing_negative(rule, monkeypatch, target):
    check = Mock(return_value=CheckResult(False, "wrong target"))
    monkeypatch.setattr(SubnetRule, "has_route_to", check)
    with pytest.raises(ValueError, match="whitespace/control"):
        matcher = have_route_to("198.51.100.1/32").via(target)
        expect(rule.subnet("subnet-source")).not_to(matcher)
    check.assert_not_called()


@pytest.mark.parametrize("negated", [False, True])
@pytest.mark.parametrize(
    "resource_type,identifier",
    [
        ("natgateway", "nat-egress"),
        ("transit-gateway", "tgw-hub"),
        ("internet-gateway", "igw-egress"),
    ],
)
def test_ec2_route_arn_aliases_are_rejected_during_matcher_composition(
    rule, monkeypatch, negated, resource_type, identifier
):
    check = Mock(return_value=CheckResult(False, "literal ARN does not match native ID"))
    monkeypatch.setattr(SubnetRule, "has_route_to", check)
    expectation = expect(rule.subnet("subnet-source"))
    assertion = expectation.not_to if negated else expectation.to
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:{resource_type}/{identifier}"
    with pytest.raises(UnsupportedCheckError, match="native EC2 target ID"):
        assertion(have_route_to("198.51.100.1/32").via(arn))
    check.assert_not_called()


@pytest.mark.parametrize(
    "matcher",
    [
        get("https://api.example/health").returning_status(200).containing("ready"),
        connect_to("api.example").over_tcp(5432),
        establish_tls("api.example"),
        resolve("api.example").within_cidrs("10.0.0.0/8"),
    ],
)
def test_observed_negatives_are_rejected_without_invocation(probe, matcher, monkeypatch):
    for method in ("http", "tcp", "tls", "dns"):
        monkeypatch.setattr(ProbeSession, method, Mock(side_effect=AssertionError("No invocation")))
    with pytest.raises(UnsupportedCheckError):
        expect(probe).not_to(matcher)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: connect_to("api.example", expected_statuses=[200]),
        lambda: connect_to("api.example").with_options(body_contains="ready"),
        lambda: connect_to("api.example", http_method="GET"),
        lambda: connect_to("api.example", max_body_bytes=4096),
        lambda: establish_tls("api.example", expected_statuses=[200]),
        lambda: establish_tls("api.example").with_options(body_contains="ready"),
        lambda: connect_to("api.example", read_timeout=3),
        lambda: connect_to("api.example", server_hostname="tls.example"),
        lambda: get("http://api.example", server_hostname="tls.example"),
    ],
)
def test_protocol_inapplicable_matcher_options_are_rejected_before_observation(
    probe, monkeypatch, factory
):
    methods = {method: Mock() for method in ("tcp", "tls", "http")}
    for method, check in methods.items():
        monkeypatch.setattr(ProbeSession, method, check)
    with pytest.raises(ValueError):
        factory()
    for check in methods.values():
        check.assert_not_called()


def test_observed_matchers_reuse_an_explicit_probe_without_deploying(rule, probe, monkeypatch):
    http = Mock(return_value=CheckResult(True, "healthy HTTP response"))
    dns = Mock(return_value=CheckResult(True, "expected DNS answer"))
    monkeypatch.setattr(ProbeSession, "http", http)
    monkeypatch.setattr(ProbeSession, "dns", dns)
    expected = get("https://api.example/health").returning_status(200).containing("ready")
    expect(probe).to(expected.for_every_address())
    http.assert_called_once_with(
        "https://api.example/health",
        address_mode="all",
        body_contains="ready",
        expected_statuses=(200,),
    )
    expect(probe).to(resolve("api.example").to_addresses(TARGET).within_cidrs("10.47.0.0/16"))
    dns.assert_called_once_with(
        "api.example", allowed_cidrs=("10.47.0.0/16",), expected_addresses=(TARGET,)
    )
    with pytest.raises(TypeError, match="explicit probe_session"):
        expect(rule.subnet("subnet-source")).to(expected)


def test_dns_matcher_omits_unset_optional_predicates_without_losing_the_result(probe, monkeypatch):
    observation = CheckResult(True, "expected DNS answer", {"resolved_addresses": [TARGET]})
    dns = Mock(return_value=observation)
    monkeypatch.setattr(ProbeSession, "dns", dns)
    result = expect(probe).to(
        resolve("api.example", expected_addresses=None, allowed_cidrs=["10.47.0.0/16"])
    )
    assert result
    assert result.evidence["resolved_addresses"] == [TARGET]
    assert "within 10.47.0.0/16" in result.message
    assert " to None" not in result.message
    dns.assert_called_once_with(
        "api.example", expected_addresses=None, allowed_cidrs=("10.47.0.0/16",)
    )


def test_unset_http_body_option_does_not_advertise_an_assertion(probe, monkeypatch):
    monkeypatch.setattr(ProbeSession, "http", Mock(return_value=CheckResult(True, "healthy")))
    result = expect(probe).to(get("https://api.example/health", body_contains=None))
    assert "containing None" not in result.message


def test_observed_matchers_forward_family_and_the_exact_connection_constraints(rule, monkeypatch):
    probe = make_probe(rule, address_family="ipv6")
    http = Mock(return_value=CheckResult(True, "healthy IPv6 response"))
    monkeypatch.setattr(ProbeSession, "http", http)
    matcher = get(
        "https://[2001:db8::10]/health",
        address_family="ipv6",
        expected_addresses=["2001:db8::10"],
        allowed_destination_cidrs=["2001:db8::/64"],
    )
    expect(probe).to(matcher)
    http.assert_called_once_with(
        "https://[2001:db8::10]/health",
        address_family="ipv6",
        expected_addresses=("2001:db8::10",),
        allowed_destination_cidrs=("2001:db8::/64",),
    )


def test_expectation_error_keeps_live_cleanup_evidence(probe, monkeypatch):
    deployment = {"cleanup": "pending"}
    http = Mock(return_value=CheckResult(False, "service is unhealthy", {"deployment": deployment}))
    monkeypatch.setattr(ProbeSession, "http", http)
    with pytest.raises(AssertionError) as caught:
        expect(probe).to(get("https://api.example/health"))
    deployment["cleanup"] = "deleted"
    assert caught.value.evidence["deployment"]["cleanup"] == "deleted"


def test_failure_messages_include_names_without_hiding_resource_identity(rule, monkeypatch):
    check = Mock(return_value=CheckResult(False, "No route in rtb-database"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    source = rule.eni(SOURCE).named("application")
    destination = rule.eni(SECOND).named("database")
    with pytest.raises(AssertionError) as caught:
        expect(source).to(reach(destination).over_tcp(5432))
    assert f"application ({SOURCE}) [{ACCOUNT}/{REGION}]" in str(caught.value)
    assert f"database ({SECOND}) [{ACCOUNT}/{REGION}]" in str(caught.value)
    assert "No route in rtb-database" in str(caught.value)
    assert caught.value.result.evidence["expectation"]["source"]["label"] == "application"


@pytest.mark.parametrize(
    "factory",
    [
        lambda: reach("10.0.0.0/16"),
        lambda: reach(TARGET).over_tcp(True),
        lambda: reach(TARGET).through("tgw-hub").avoiding("tgw-hub"),
        lambda: reach("eni-destination").through("arn:broken"),
        lambda: have_route_to("not a CIDR"),
        lambda: get("https://user:password@api.example"),
        lambda: get("https://api.example").returning_status(),
        lambda: connect_to("api.example").with_options(attempts=0),
        lambda: resolve("api.example").to_addresses("not an address"),
        lambda: resolve("api.example").with_options(unrecognized=True),
    ],
)
def test_invalid_matchers_are_rejected_during_composition(factory):
    with pytest.raises((ValueError, TypeError, UnsupportedCheckError)):
        factory()


def test_incomplete_dns_and_propagation_matchers_cannot_evaluate(rule, probe, monkeypatch):
    dns = Mock(side_effect=AssertionError("No invocation"))
    propagation = Mock(side_effect=AssertionError("No API"))
    monkeypatch.setattr(ProbeSession, "dns", dns)
    monkeypatch.setattr(TransitGatewayRule, "propagates", propagation)
    with pytest.raises(ValueError, match="expected_addresses or allowed_cidrs"):
        expect(probe).to(resolve("api.example"))
    with pytest.raises(ValueError, match="from_vpc"):
        expect(rule.tgw("tgw-hub")).to(propagate_to("tgw-rtb-ingress"))
    dns.assert_not_called()
    propagation.assert_not_called()


@pytest.mark.parametrize(
    "selector,matcher,operation,arguments",
    [
        (lambda r: r.eni(SOURCE), be_recorded(), "is_recorded", ()),
        (lambda r: r.eni(SOURCE), be_in_subnet("subnet-source"), "in_subnet", ("subnet-source",)),
        (lambda r: r.eni(SOURCE), be_in_vpc("vpc-source"), "in_vpc", ("vpc-source",)),
        (
            lambda r: r.vpc("vpc-source"),
            be_peered_with("vpc-other"),
            "has_peering_with",
            ("vpc-other",),
        ),
        (
            lambda r: r.tgw("tgw-hub"),
            have_attachment("vpc-source"),
            "has_attachment",
            ("vpc-source",),
        ),
        (
            lambda r: r.tgw("tgw-hub").route_table("tgw-rtb-ingress"),
            have_association("tgw-attach-source"),
            "has_association",
            ("tgw-attach-source",),
        ),
    ],
)
def test_relationship_matchers_delegate_and_negate_only_conclusive_results(
    rule, monkeypatch, selector, matcher, operation, arguments
):
    subject = selector(rule)
    check = Mock(side_effect=[CheckResult(True, "matches"), CheckResult(False, "does not match")])
    monkeypatch.setattr(type(subject), operation, check)
    expect(subject).to(matcher)
    expect(subject).not_to(matcher)
    assert check.call_count == 2
    check.assert_called_with(*arguments)


def test_propagation_matcher_uses_the_existing_complete_propagation_builder(rule, monkeypatch):
    propagation = Mock()
    propagation.from_vpc.return_value = CheckResult(True, "propagation enabled")
    select = Mock(return_value=propagation)
    monkeypatch.setattr(TransitGatewayRule, "propagates", select)
    expect(rule.tgw("tgw-hub")).to(propagate_to("tgw-rtb-ingress").from_vpc("vpc-source"))
    select.assert_called_once_with("tgw-rtb-ingress")
    propagation.from_vpc.assert_called_once_with("vpc-source")
    with pytest.raises(ValueError):
        have_association("rtb-wrong-resource-type")


@pytest.mark.parametrize("found", [True, False])
@pytest.mark.parametrize("negated", [True, False])
def test_real_ra_matcher_request_and_cleanup_use_native_botocore_contracts(rule, found, negated):
    path = "nip-0123456789abcdef0"
    analysis = "nia-0123456789abcdef0"
    with Stubber(rule.analysis_ec2) as stub:
        stub.add_response(
            "create_network_insights_path",
            {"NetworkInsightsPath": {"NetworkInsightsPathId": path}},
            {
                "Source": f"arn:aws:ec2:{REGION}:{ACCOUNT}:network-interface/{SOURCE}",
                "Protocol": "tcp",
                "ClientToken": ANY,
                "FilterAtSource": {
                    "DestinationAddress": TARGET,
                    "DestinationPortRange": {"FromPort": 5432, "ToPort": 5432},
                },
            },
        )
        stub.add_response(
            "start_network_insights_analysis",
            {
                "NetworkInsightsAnalysis": {
                    "NetworkInsightsAnalysisId": analysis,
                    "NetworkInsightsPathId": path,
                    "Status": "succeeded",
                    "NetworkPathFound": found,
                }
            },
            {"NetworkInsightsPathId": path, "ClientToken": ANY},
        )
        stub.add_response(
            "delete_network_insights_analysis",
            {"NetworkInsightsAnalysisId": analysis},
            {"NetworkInsightsAnalysisId": analysis},
        )
        stub.add_response(
            "delete_network_insights_path",
            {"NetworkInsightsPathId": path},
            {"NetworkInsightsPathId": path},
        )
        assertion = expect(rule.eni(SOURCE)).not_to if negated else expect(rule.eni(SOURCE)).to
        if found != negated:
            result = assertion(reach(TARGET).over_tcp(5432))
        else:
            with pytest.raises(AssertionError) as caught:
                assertion(reach(TARGET).over_tcp(5432))
            result = caught.value.result
        assert result.passed is (found != negated)
        assert result.evidence["analysis_id"] == analysis
        assert result.evidence["cleanup"] == {"path": "deleted", "analysis": "deleted"}
        assert "TCP/5432" in result.message
        stub.assert_no_pending_responses()


def test_exact_population_matches_scoped_id_arn_aliases_and_snapshots_discovery(rule):
    arn = f"arn:aws:ec2:{REGION}:{ACCOUNT}:network-interface/{SOURCE}"
    discovered = [rule.resource(arn), rule.eni(SECOND)]
    expectation = expect(discovered)
    discovered.clear()
    result = expectation.to(contain_exactly_resources(rule.eni(SECOND), rule.eni(SOURCE)))
    assert result
    assert result.evidence["missing"] == result.evidence["unexpected"] == []


@pytest.mark.parametrize("actual", [(), (SOURCE,), (SOURCE, SOURCE), (SOURCE, "eni-unexpected")])
def test_exact_population_mismatches_are_false_even_when_discovery_is_empty(rule, actual):
    selectors = [rule.eni(identifier) for identifier in actual]
    with pytest.raises(AssertionError) as caught:
        expect(selectors).to(contain_exactly_resources(rule.eni(SOURCE), rule.eni(SECOND)))
    assert caught.value.result.passed is False
    assert len(caught.value.evidence["actual"]) == len(actual)


def test_exact_population_requires_known_scope_and_valid_unique_expectations(rule):
    with pytest.raises(ValueError, match="nonempty"):
        contain_exactly_resources()
    with pytest.raises(ValueError, match="distinct"):
        contain_exactly_resources(rule.eni(SOURCE), rule.eni(SOURCE).named("same source"))
    unscoped = RuleBuilder(session=rule.clients.session, config_mode="off")
    with pytest.raises(ValueError, match="explicit account"):
        contain_exactly_resources(unscoped.eni(SOURCE))
    with pytest.raises(ValueError, match="explicit account"):
        expect([unscoped.eni(SOURCE)]).to(contain_exactly_resources(rule.eni(SOURCE)))
    with pytest.raises(TypeError, match="scoped resource"):
        expect([None]).to(contain_exactly_resources(rule.eni(SOURCE)))


def test_reach_each_expands_every_source_destination_and_explicit_port(rule, monkeypatch):
    sources = [rule.eni(SOURCE), rule.eni(SECOND)]
    destinations = [rule.eni("eni-database1"), rule.eni("eni-database2")]
    calls = []

    def check(source, destination, **options):
        calls.append((source.resource_id, destination.resource_id, options["port"]))
        return CheckResult(options["port"] == 5432, "modeled check")

    monkeypatch.setattr(EndpointRule, "can_reach", check)
    with pytest.raises(AssertionError) as caught:
        expect(every(sources)).to(reach_each(destinations).over_tcp(5432, 6432))
    expected = {
        (source.resource_id, target.resource_id, port)
        for source in sources
        for target in destinations
        for port in (5432, 6432)
    }
    assert set(calls) == expected
    assert len(calls) == 8
    assert caught.value.evidence["expected_count"] == caught.value.evidence["evaluated_count"] == 8
    assert {item.evidence["case"]["port"] for item in caught.value.evidence["results"]} == {
        5432,
        6432,
    }


def test_reach_each_preserves_native_errors_with_partial_pair_evidence(rule, monkeypatch):
    error = AnalysisError("unknown component")
    error.evidence = {"analysis_id": "nia-original"}
    monkeypatch.setattr(
        EndpointRule, "can_reach", Mock(side_effect=[CheckResult(True, "first"), error])
    )
    destinations = [rule.eni("eni-database1"), rule.eni("eni-database2")]
    with pytest.raises(AnalysisError) as caught:
        expect(rule.eni(SOURCE)).to(reach_each(destinations).over_udp(53))
    assert caught.value is error
    assert error.evidence == {"analysis_id": "nia-original"}
    assert error.coverage_evidence["evaluated_count"] == 1
    assert error.coverage_evidence["failed_case"]["destination"]["resource_id"] == "eni-database2"
    assert error.coverage_evidence["failed_case"]["port"] == 53


def test_reach_each_preflights_the_last_destination_and_rejects_negation_before_calls(
    rule, monkeypatch
):
    check = Mock(return_value=CheckResult(True, "not called"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    destinations = [rule.eni(SECOND), rule.in_region("eu-west-1").eni("eni-database")]
    with pytest.raises(UnsupportedCheckError, match="one region"):
        expect(rule.eni(SOURCE)).to(reach_each(destinations))
    with pytest.raises(UnsupportedCheckError, match="ambiguous"):
        expect(rule.eni(SOURCE)).not_to(reach_each([rule.eni(SECOND)]))
    check.assert_not_called()


def test_reach_each_rejects_empty_duplicate_unscoped_and_invalid_port_declarations(rule):
    with pytest.raises(ValueError, match="nonempty"):
        reach_each([])
    with pytest.raises(ValueError, match="distinct"):
        reach_each([rule.eni(SECOND), rule.eni(SECOND)])
    unscoped = RuleBuilder(session=rule.clients.session, config_mode="off")
    with pytest.raises(ValueError, match="explicit account"):
        reach_each([unscoped.eni(SECOND)])
    initial = reach_each([rule.eni(SECOND)])
    for ports in [(), (5432, 5432), (True,), (None,)]:
        with pytest.raises(ValueError):
            initial.over_tcp(*ports)
    assert initial.ports == (443,)


@pytest.mark.parametrize("mode,factor", [("eventually", 3), ("consistently", 5)])
def test_planning_counts_all_pairs_ports_and_timing_without_evaluation(
    rule, monkeypatch, mode, factor
):
    check = Mock(return_value=CheckResult(True, "not called"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    monkeypatch.setattr(rule.clients, "client", Mock(side_effect=AssertionError("No AWS client")))
    matcher = reach_each([rule.eni("eni-database1"), rule.eni("eni-database2")]).over_tcp(
        5432, 6432
    )
    matcher = (
        matcher.eventually(max_attempts=3)
        if mode == "eventually"
        else matcher.consistently(checks=5)
    )
    expectation = expect(every([rule.eni(SOURCE), rule.eni(SECOND)]))
    plan = expectation.plan(matcher)
    assert plan["source_count"] == 2
    assert plan["case_count"] == 8
    assert plan["max_checks"] == plan["max_ra_analyses"] == 8 * factor
    with pytest.raises(ValueError, match="upper bound"):
        expectation.to(matcher, max_ra_analyses=8 * factor - 1)
    check.assert_not_called()


def test_analysis_budget_accepts_exact_bound_and_zero_cost_population_checks(rule, monkeypatch):
    check = Mock(return_value=CheckResult(True, "modeled allowed"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    assert expect(rule.eni(SOURCE)).to(reach(rule.eni(SECOND)), max_ra_analyses=1)
    assert expect([rule.eni(SOURCE)]).to(
        contain_exactly_resources(rule.eni(SOURCE)), max_ra_analyses=0
    )
    check.assert_called_once()
    for budget in (True, -1, 1.5):
        with pytest.raises(ValueError, match="nonnegative integer"):
            expect(rule.eni(SOURCE)).to(reach(rule.eni(SECOND)), max_ra_analyses=budget)


def test_stability_matcher_is_fresh_immutable_and_does_not_hide_false_results(rule, monkeypatch):
    check = Mock(
        side_effect=[
            CheckResult(True, "first"),
            CheckResult(False, "flapped"),
            CheckResult(True, "unused"),
        ]
    )
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", Mock())
    matcher = reach(TARGET).consistently(checks=3)
    with pytest.raises(AssertionError, match="flapped") as caught:
        expect(rule.eni(SOURCE)).to(matcher)
    assert check.call_count == 2
    assert caught.value.evidence["stability"]["evaluated_count"] == 2
    with pytest.raises(FrozenInstanceError):
        matcher.checks = 2


@pytest.mark.parametrize(
    "first,second",
    [
        ("eventually", "eventually"),
        ("consistently", "consistently"),
        ("eventually", "consistently"),
        ("consistently", "eventually"),
    ],
)
def test_timing_wrappers_cannot_stack_and_hide_intermittent_failures(first, second):
    matcher = getattr(reach(TARGET), first)()
    with pytest.raises(ValueError, match="one .* budget"):
        getattr(matcher, second)()


def test_protocol_matcher_identity_preserves_instance_transport(rule, monkeypatch):
    class InstanceProbe(ProbeSession):
        transport = "ssm"

    probe = object.__new__(InstanceProbe)
    probe.selector = rule.instance("i-application").named("application")
    probe.address_family = "ipv4"
    monkeypatch.setattr(InstanceProbe, "tcp", Mock(return_value=CheckResult(True, "connected")))
    result = expect(probe).to(connect_to(TARGET))
    assert "SSM probe from application (i-application)" in result.message
    assert result.evidence["expectation"]["source"]["resource_id"] == "i-application"
    assert result.evidence["expectation"]["source"]["source_kind"] == "ssm"
    assert expect(probe).plan(connect_to(TARGET))["max_ra_analyses"] == 0


def test_reach_each_preserves_packet_constraints_and_caller_destinations(rule, monkeypatch):
    destinations = [rule.eni(SECOND)]
    initial = reach_each(destinations)
    destinations.clear()
    matcher = (
        initial.over_udp(53)
        .from_address("10.1.1.10")
        .from_port(45000)
        .at_address(TARGET)
        .through("tgw-hub")
        .avoiding("igw-egress")
    )
    check = Mock(return_value=CheckResult(True, "path matches"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    assert expect(rule.eni(SOURCE)).to(matcher)
    check.assert_called_once_with(
        rule.eni(SECOND),
        protocol="udp",
        port=53,
        source_ip="10.1.1.10",
        source_port=45000,
        destination_ip=TARGET,
        through=("tgw-hub",),
        avoiding=("igw-egress",),
    )
    assert initial.ports == (443,)
    assert initial.packet.required == initial.packet.forbidden == ()


def test_planning_and_analysis_limit_make_no_native_sdk_requests(rule):
    matcher = reach_each([rule.eni(SECOND)]).consistently(checks=5)
    with Stubber(rule.analysis_ec2) as stub:
        plan = expect(rule.eni(SOURCE)).plan(matcher)
        assert plan["max_ra_analyses"] == 5
        with pytest.raises(ValueError, match="upper bound"):
            expect(rule.eni(SOURCE)).to(matcher, max_ra_analyses=4)
        stub.assert_no_pending_responses()


def test_stability_budgets_apply_to_every_expanded_pair(rule, monkeypatch):
    check = Mock(return_value=CheckResult(True, "path exists"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", Mock())
    matcher = (
        reach_each([rule.eni("eni-database1"), rule.eni("eni-database2")])
        .over_tcp(5432, 6432)
        .consistently(checks=3)
    )
    result = expect(every([rule.eni(SOURCE), rule.eni(SECOND)])).to(matcher, max_ra_analyses=24)
    assert result.evidence["evaluated_count"] == 8
    assert check.call_count == 24
    assert all(
        item.evidence["stability"]["evaluated_count"] == 3 for item in result.evidence["results"]
    )


def test_negated_stability_requires_a_conclusive_denial_on_each_observation(rule, monkeypatch):
    denied = Mock(side_effect=[CheckResult(True, "denied"), AnalysisError("unknown")])
    monkeypatch.setattr(EndpointRule, "cannot_reach", denied)
    monkeypatch.setattr("aws_network_asserts.checks.time.sleep", Mock())
    with pytest.raises(AnalysisError) as caught:
        expect(rule.eni(SOURCE)).not_to(reach(TARGET).consistently(checks=3))
    assert caught.value.stability_evidence["evaluated_count"] == 1
    assert denied.call_count == 2


def test_a_plan_cannot_describe_conflicting_literal_destination_filters(rule):
    with pytest.raises(ValueError, match="different IP addresses"):
        expect(rule.eni(SOURCE)).plan(reach(TARGET).at_address("10.47.1.20"))


@pytest.mark.parametrize("operation", ["assert", "plan", "expected", "every"])
def test_foreign_partition_arns_cannot_match_or_plan_an_exact_population(rule, operation):
    arn = f"arn:aws-cn:ec2:{REGION}:{ACCOUNT}:network-interface/{SOURCE}"
    with Stubber(rule.analysis_ec2) as stub:
        with pytest.raises(UnsupportedCheckError, match="partition"):
            if operation == "expected":
                contain_exactly_resources(rule.resource(arn))
            elif operation == "every":
                every([rule.resource(arn)])
            else:
                expectation = expect([rule.resource(arn)])
                matcher = contain_exactly_resources(rule.eni(SOURCE))
                if operation == "plan":
                    expectation.plan(matcher)
                else:
                    expectation.to(matcher)
        stub.assert_no_pending_responses()


def test_population_identity_preserves_the_valid_partition_for_each_session(rule):
    from aws_network_asserts.expectations import _source_key

    government = rule.in_region("us-gov-west-1")
    gov_arn = f"arn:aws-us-gov:ec2:us-gov-west-1:{ACCOUNT}:network-interface/{SOURCE}"
    assert _source_key(rule.eni(SOURCE))[-1] == "aws"
    assert _source_key(government.resource(gov_arn))[-1] == "aws-us-gov"
    assert expect([government.resource(gov_arn)]).to(
        contain_exactly_resources(government.eni(SOURCE))
    )


def test_wrong_partition_final_destination_rejects_before_any_case_evaluation(rule, monkeypatch):
    check = Mock(return_value=CheckResult(True, "not called"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    foreign = f"arn:aws-cn:ec2:{REGION}:{ACCOUNT}:network-interface/eni-foreign"
    with pytest.raises(UnsupportedCheckError, match="partition"):
        matcher = reach_each([rule.eni(SECOND), rule.resource(foreign)])
        expect(rule.eni(SOURCE)).plan(matcher)
        expect(rule.eni(SOURCE)).to(matcher)
    check.assert_not_called()


@pytest.mark.parametrize("constraint", ["through", "avoiding"])
def test_path_partition_constraints_are_validated_by_local_planning(rule, monkeypatch, constraint):
    check = Mock(return_value=CheckResult(True, "not called"))
    monkeypatch.setattr(EndpointRule, "can_reach", check)
    arn = f"arn:aws-cn:ec2:{REGION}:{ACCOUNT}:transit-gateway/tgw-hub"
    matcher = getattr(reach(rule.eni(SECOND)), constraint)(arn)
    with pytest.raises(ValueError, match="partition"):
        expect(rule.eni(SOURCE)).plan(matcher)
    with pytest.raises(ValueError, match="partition"):
        expect(rule.eni(SOURCE)).to(matcher)
    check.assert_not_called()


@pytest.mark.parametrize("kind", ["tcp", "tls", "http", "dns"])
def test_mixed_session_families_preflight_before_first_observation(rule, monkeypatch, kind):
    ipv6 = make_probe(rule, address_family="ipv6", subnet_id="subnet-ipv6")
    ipv4 = make_probe(rule, subnet_id="subnet-ipv4")
    checks = {
        name: Mock(return_value=CheckResult(True, "not called"))
        for name in ("tcp", "tls", "http", "dns")
    }
    for name, check in checks.items():
        monkeypatch.setattr(ProbeSession, name, check)
    matchers = {
        "tcp": connect_to("service.example", address_family="ipv6"),
        "tls": establish_tls("service.example", address_family="ipv6"),
        "http": get("https://service.example/health", address_family="ipv6"),
        "dns": resolve("service.example", address_family="ipv6").within_cidrs("2001:db8::/64"),
    }
    expectation = expect(every([ipv6, ipv4]))
    with pytest.raises(ValueError, match="disabled"):
        expectation.plan(matchers[kind])
    with pytest.raises(ValueError, match="disabled"):
        expectation.to(matchers[kind])
    for check in checks.values():
        check.assert_not_called()


@pytest.mark.parametrize("kind", ["tcp", "dns"])
def test_preflight_validates_inherited_family_against_static_address_expectations(
    rule, monkeypatch, kind
):
    ipv4 = make_probe(rule, subnet_id="subnet-ipv4")
    ipv6 = make_probe(rule, address_family="ipv6", subnet_id="subnet-ipv6")
    check = Mock(return_value=CheckResult(True, "not called"))
    monkeypatch.setattr(ProbeSession, kind, check)
    matcher = (
        connect_to("service.example", expected_addresses=[TARGET])
        if kind == "tcp"
        else resolve("service.example").to_addresses(TARGET)
    )
    with pytest.raises(ValueError, match="address_family"):
        expect(every([ipv4, ipv6])).to(matcher)
    check.assert_not_called()


def test_protocol_preflight_allows_a_dual_session_to_narrow_its_check(rule, monkeypatch):
    probe = make_probe(rule, address_family="dual")
    check = Mock(return_value=CheckResult(True, "healthy IPv6"))
    monkeypatch.setattr(ProbeSession, "tcp", check)
    assert expect(probe).to(connect_to("service.example", address_family="ipv6"))
    check.assert_called_once_with("service.example", address_family="ipv6")
