"""Validate AWS request shapes and isolation semantics without an AWS account."""

import warnings
from unittest.mock import Mock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import ANY, Stubber

from aws_network_asserts import reachability
from aws_network_asserts.errors import (
    AnalysisError,
    AnalysisTimeoutError,
    CleanupWarning,
    UnsupportedCheckError,
)
from aws_network_asserts.reachability import ReachabilityAnalyzer, qualify_endpoint

SOURCE = "eni-0123456789abcdef0"
DESTINATION = "eni-0fedcba9876543210"
PATH = "nip-0123456789abcdef0"
ANALYSIS = "nia-0123456789abcdef0"
REGION = "eu-west-2"


@pytest.fixture
def ra_client():
    return boto3.client(
        "ec2",
        region_name=REGION,
        endpoint_url="https://ec2.test.invalid",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def create(stub, **overrides):
    request = {
        "Source": SOURCE,
        "Protocol": "tcp",
        "FilterAtSource": {
            "DestinationAddress": "10.47.1.1",
            "DestinationPortRange": {"FromPort": 443, "ToPort": 443},
        },
        "ClientToken": ANY,
    }
    request.update(overrides)
    stub.add_response(
        "create_network_insights_path",
        {"NetworkInsightsPath": {"NetworkInsightsPathId": PATH}},
        request,
    )


def start(stub, *, status="succeeded", found=True, accounts=None, **fields):
    analysis = {
        "NetworkInsightsAnalysisId": ANALYSIS,
        "NetworkInsightsPathId": PATH,
        "Status": status,
        **fields,
    }
    if found is not None:
        analysis["NetworkPathFound"] = found
    request = {"NetworkInsightsPathId": PATH, "ClientToken": ANY}
    if accounts:
        request["AdditionalAccounts"] = accounts
    stub.add_response(
        "start_network_insights_analysis", {"NetworkInsightsAnalysis": analysis}, request
    )


def cleanup(stub, *, analysis=True):
    if analysis:
        stub.add_response(
            "delete_network_insights_analysis",
            {"NetworkInsightsAnalysisId": ANALYSIS},
            {"NetworkInsightsAnalysisId": ANALYSIS},
        )
    stub.add_response(
        "delete_network_insights_path",
        {"NetworkInsightsPathId": PATH},
        {"NetworkInsightsPathId": PATH},
    )


@pytest.mark.parametrize(
    ("identifier", "resource_type"),
    [
        (SOURCE, "network-interface"),
        ("tgw-0123456789abcdef0", "transit-gateway"),
        ("tgw-attach-0123456789abcdef0", "transit-gateway-attachment"),
        ("vpce-svc-0123456789abcdef0", "vpc-endpoint-service"),
    ],
)
def test_account_scope_qualifies_supported_endpoints(identifier, resource_type):
    assert qualify_endpoint(identifier, account_id="111111111111", region=REGION) == (
        f"arn:aws:ec2:{REGION}:111111111111:{resource_type}/{identifier}"
    )


@pytest.mark.parametrize(
    ("partition", "region"),
    [("aws-us-gov", "us-gov-west-1"), ("aws-cn", "cn-north-1")],
)
def test_endpoint_qualification_uses_selected_partition(partition, region):
    arn = f"arn:{partition}:ec2:{region}:111111111111:network-interface/{SOURCE}"
    assert (
        qualify_endpoint(SOURCE, account_id="111111111111", region=region, partition=partition)
        == arn
    )
    assert (
        qualify_endpoint(arn, account_id="111111111111", region=region, partition=partition) == arn
    )


@pytest.mark.parametrize("account", [None, "111111111111"])
def test_qualified_arn_must_use_the_requested_partition(account):
    arn = f"arn:aws-cn:ec2:{REGION}:111111111111:network-interface/{SOURCE}"
    with pytest.raises(UnsupportedCheckError, match="partition"):
        qualify_endpoint(arn, account_id=account, region=REGION, partition="aws")


def test_unscoped_endpoints_preserve_ids_and_explicit_foreign_arns():
    assert qualify_endpoint(SOURCE, account_id=None, region=REGION) == SOURCE
    arn = f"arn:aws:ec2:{REGION}:222222222222:network-interface/{DESTINATION}"
    assert qualify_endpoint(arn, account_id=None, region=REGION) == arn


def test_endpoint_arn_cannot_contradict_account_scope():
    arn = f"arn:aws:ec2:{REGION}:222222222222:network-interface/{DESTINATION}"
    with pytest.raises(ValueError, match="not the selected account 111111111111"):
        qualify_endpoint(arn, account_id="111111111111", region=REGION)


def test_endpoint_arn_cannot_cross_regions():
    arn = f"arn:aws:ec2:us-east-1:111111111111:network-interface/{SOURCE}"
    with pytest.raises(UnsupportedCheckError, match="both endpoints"):
        qualify_endpoint(arn, account_id="111111111111", region=REGION)


@pytest.mark.parametrize("account", ["123", "11111111111x", 111111111111, ""])
def test_endpoint_account_must_be_a_twelve_digit_string(account):
    with pytest.raises(ValueError):
        qualify_endpoint(SOURCE, account_id=account, region=REGION)


@pytest.mark.parametrize("partition", ["", None, "aws:ec2", " "])
def test_endpoint_partition_must_be_a_partition_name(partition):
    with pytest.raises(ValueError, match="partition"):
        qualify_endpoint(SOURCE, account_id="111111111111", region=REGION, partition=partition)


@pytest.mark.parametrize("address", ["10.47.1.1", "10.47.1.1/32"])
def test_qualification_preserves_ipv4_destination(address):
    assert (
        qualify_endpoint(address, account_id="111111111111", region=REGION, allow_ip=True)
        == "10.47.1.1"
    )


@pytest.mark.parametrize("address", ["10.47.1.1/24", "2001:db8::1", "2001:db8::1/128"])
def test_qualification_rejects_unsupported_destination_address_scopes(address):
    with pytest.raises(UnsupportedCheckError, match="one IPv4"):
        qualify_endpoint(address, account_id=None, region=REGION, allow_ip=True)


def test_account_scoped_source_and_destination_use_central_analysis(ra_client):
    source = qualify_endpoint(SOURCE, account_id="111111111111", region=REGION)
    destination = qualify_endpoint(DESTINATION, account_id="222222222222", region=REGION)
    with Stubber(ra_client) as stub:
        create(
            stub,
            Source=source,
            Destination=destination,
            FilterAtSource={"DestinationPortRange": {"FromPort": 443, "ToPort": 443}},
        )
        start(stub)
        cleanup(stub)
        assert ReachabilityAnalyzer(ra_client).check(source, destination)
        stub.assert_no_pending_responses()


def test_ipv4_slash32_request_and_evidence(ra_client):
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, WarningMessage="Review the forward traffic path")
        cleanup(stub)
        result = ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1/32")
        assert result
        assert result.evidence["analysis_id"] == ANALYSIS
        assert result.evidence["path_id"] == PATH
        assert result.evidence["analysis"]["NetworkPathFound"] is True
        assert result.evidence["destination"] == "10.47.1.1/32"
        assert "AWS warning" in result.message
        stub.assert_no_pending_responses()


def test_resource_destination_with_all_packet_fields_and_accounts(ra_client):
    arn = f"arn:aws:ec2:{REGION}:222222222222:network-interface/{DESTINATION}"
    with Stubber(ra_client) as stub:
        create(
            stub,
            Destination=arn,
            Protocol="udp",
            FilterAtSource={
                "SourceAddress": "10.0.1.10",
                "SourcePortRange": {"FromPort": 49152, "ToPort": 49152},
                "DestinationAddress": "10.47.1.1",
                "DestinationPortRange": {"FromPort": 53, "ToPort": 53},
            },
        )
        start(stub, accounts=["222222222222"])
        cleanup(stub)
        assert ReachabilityAnalyzer(ra_client).check(
            SOURCE,
            arn,
            protocol="UDP",
            port=53,
            source_ip="10.0.1.10/32",
            destination_ip="10.47.1.1",
            source_port=49152,
            additional_accounts=("222222222222",),
        )
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "expected,found,passes", [(True, False, False), (False, False, True), (False, True, False)]
)
def test_negative_results_require_a_conclusive_analysis(ra_client, expected, found, passes):
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, found=found, Explanations=[{"ExplanationCode": "ENI_SG_RULES_MISMATCH"}])
        cleanup(stub)
        result = ReachabilityAnalyzer(ra_client).check(
            SOURCE, "10.47.1.1", expect_reachable=expected
        )
        assert bool(result) is passes
        assert "ENI_SG_RULES_MISMATCH" in result.message
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "fields",
    [
        {"status": "failed", "found": None, "StatusMessage": "Permissions missing"},
        {"status": "succeeded", "found": None},
        {"status": "unknown", "found": None},
    ],
)
def test_error_never_satisfies_isolation_and_retains_evidence(ra_client, fields):
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, **fields)
        cleanup(stub)
        with pytest.raises(AnalysisError) as caught:
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1", expect_reachable=False)
        assert caught.value.evidence["analysis_id"] == ANALYSIS
        assert PATH in str(caught.value)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "code",
    [
        "UNKNOWN_RESOURCE",
        "NO_SOURCE_OR_DESTINATION",
        "NO_POSSIBLE_DESTINATION",
        "TGW_RTB_ROUTES_ARE_UNKNOWN",
        "UNKNOWN_DESTINATION",
        "UNKNOWN_PEERED_SGS",
        "UNSUPPORTED_COMPONENT",
        "UNASSOCIATED_COMPONENT",
        "IGW_NAT_REFLECTION",
        "NO_PATH",
    ],
)
def test_missing_or_unsupported_scope_never_satisfies_isolation(ra_client, code):
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, found=False, Explanations=[{"ExplanationCode": code}])
        cleanup(stub)
        with pytest.raises(AnalysisError, match=code):
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1", expect_reachable=False)
        stub.assert_no_pending_responses()


def test_running_analysis_is_polled(ra_client, monkeypatch):
    monkeypatch.setattr(reachability, "sleep", lambda _: None)
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, status="running", found=None)
        stub.add_response(
            "describe_network_insights_analyses",
            {
                "NetworkInsightsAnalyses": [
                    {
                        "NetworkInsightsAnalysisId": ANALYSIS,
                        "Status": "succeeded",
                        "NetworkPathFound": True,
                    }
                ]
            },
            {"NetworkInsightsAnalysisIds": [ANALYSIS]},
        )
        cleanup(stub)
        assert ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1")
        stub.assert_no_pending_responses()


def test_timeout_has_ids_and_attempts_cleanup(ra_client, monkeypatch):
    times = iter([0.0, 2.0])
    monkeypatch.setattr(reachability, "monotonic", lambda: next(times))
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, status="running", found=None)
        cleanup(stub)
        with pytest.raises(AnalysisTimeoutError, match=ANALYSIS) as caught:
            ReachabilityAnalyzer(ra_client, timeout=1).check(SOURCE, "10.47.1.1")
        assert caught.value.evidence["analysis"]["Status"] == "running"
        stub.assert_no_pending_responses()


def test_timeout_does_not_start_another_poll_after_sleep(ra_client, monkeypatch):
    times = iter([0.0, 0.0, 1.0])
    monkeypatch.setattr(reachability, "monotonic", lambda: next(times))
    delays = []
    monkeypatch.setattr(reachability, "sleep", delays.append)
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, status="running", found=None)
        cleanup(stub)
        with pytest.raises(AnalysisTimeoutError):
            ReachabilityAnalyzer(ra_client, timeout=1).check(SOURCE, "10.47.1.1")
        assert delays == [1.0]
        stub.assert_no_pending_responses()


def test_nested_inconclusive_explanations_are_not_ignored(ra_client):
    with Stubber(ra_client) as stub:
        create(stub)
        start(
            stub,
            found=False,
            ForwardPathComponents=[
                {
                    "SequenceNumber": 1,
                    "Explanations": [{"ExplanationCode": "UNKNOWN_RESOURCE"}],
                }
            ],
        )
        cleanup(stub)
        with pytest.raises(AnalysisError, match="UNKNOWN_RESOURCE"):
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1", expect_reachable=False)
        stub.assert_no_pending_responses()


def test_start_error_still_deletes_created_path(ra_client):
    with Stubber(ra_client) as stub:
        create(stub)
        stub.add_client_error(
            "start_network_insights_analysis",
            service_error_code="UnauthorizedOperation",
            expected_params={"NetworkInsightsPathId": PATH, "ClientToken": ANY},
        )
        cleanup(stub, analysis=False)
        with pytest.raises(ClientError, match="UnauthorizedOperation"):
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1", expect_reachable=False)
        stub.assert_no_pending_responses()


def test_polling_error_is_not_false_and_still_cleans_up(ra_client, monkeypatch):
    monkeypatch.setattr(reachability, "sleep", lambda _: None)
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, status="running", found=None)
        stub.add_client_error(
            "describe_network_insights_analyses",
            service_error_code="UnauthorizedOperation",
            expected_params={"NetworkInsightsAnalysisIds": [ANALYSIS]},
        )
        cleanup(stub)
        with pytest.raises(ClientError):
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1", expect_reachable=False)
        stub.assert_no_pending_responses()


def test_cleanup_failure_is_visible_and_other_cleanup_is_attempted(ra_client):
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub)
        stub.add_client_error(
            "delete_network_insights_analysis",
            service_error_code="IncorrectState",
            expected_params={"NetworkInsightsAnalysisId": ANALYSIS},
        )
        cleanup(stub, analysis=False)
        with pytest.warns(CleanupWarning, match=ANALYSIS):
            assert ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1")
        stub.assert_no_pending_responses()


def test_cleanup_warning_promoted_to_error_does_not_hide_original(ra_client, caplog):
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, status="failed", found=None, StatusMessage="Original failure")
        stub.add_client_error(
            "delete_network_insights_analysis",
            service_error_code="IncorrectState",
            expected_params={"NetworkInsightsAnalysisId": ANALYSIS},
        )
        cleanup(stub, analysis=False)
        with warnings.catch_warnings():
            warnings.simplefilter("error", CleanupWarning)
            with pytest.raises(AnalysisError, match="Original failure"):
                ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1")
        assert ANALYSIS in caplog.text
        stub.assert_no_pending_responses()


def test_keep_analysis_preserves_resources(ra_client):
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub)
        assert ReachabilityAnalyzer(ra_client, keep_analysis=True).check(SOURCE, "10.47.1.1")
        stub.assert_no_pending_responses()


def test_results_are_not_cached_across_checks(ra_client):
    analyzer = ReachabilityAnalyzer(ra_client)
    with Stubber(ra_client) as stub:
        for found in (True, False):
            create(stub)
            start(stub, found=found)
            cleanup(stub)
        assert analyzer.check(SOURCE, "10.47.1.1")
        assert not analyzer.check(SOURCE, "10.47.1.1")
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "source,destination",
    [
        (SOURCE, "10.47.1.0/24"),
        (SOURCE, "10.47.1.1/24"),
        (SOURCE, "2001:db8::1"),
        ("subnet-01234567", DESTINATION),
        ("tgw-rtb-01234567", DESTINATION),
        (SOURCE, "vpc-01234567"),
        (SOURCE, "arn:aws:ec2:us-east-1:123456789012:network-interface/eni-01234567"),
        ("arn:aws:ec2:us-east-1:123456789012:network-interface/eni-01234567", DESTINATION),
        (SOURCE, f"arn:aws:ec2:{REGION}:123456789012:subnet/subnet-01234567"),
        (SOURCE, f"arn:aws:ec2:{REGION}:123456789012:instance/eni-01234567"),
    ],
)
def test_unsupported_inputs_fail_before_creating_resources(ra_client, source, destination):
    with Stubber(ra_client):
        with pytest.raises(UnsupportedCheckError):
            ReachabilityAnalyzer(ra_client).check(source, destination)


@pytest.mark.parametrize(
    "options",
    [
        {"port": -1},
        {"port": 65536},
        {"port": True},
        {"port": "443"},
        {"source_port": 65536},
        {"protocol": "icmp"},
        {"protocol": None},
        {"source_ip": "not-an-address"},
        {"source_ip": 1},
        {"destination_ip": "10.1.1.2"},
        {"additional_accounts": "123456789012"},
        {"additional_accounts": ["bad-account"]},
        {"additional_accounts": ["１１１１１１１１１１１１"]},
    ],
)
def test_invalid_inputs_fail_before_creating_resources(ra_client, options):
    with Stubber(ra_client):
        with pytest.raises(ValueError):
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1", **options)


@pytest.mark.parametrize(
    "options",
    [
        {"timeout": 0},
        {"timeout": float("inf")},
        {"poll_interval": -1},
        {"poll_interval": float("nan")},
    ],
)
def test_invalid_polling_configuration(ra_client, options):
    with pytest.raises(ValueError):
        ReachabilityAnalyzer(ra_client, **options)


def test_untrusted_start_path_never_passes_or_deletes_unrelated_analysis(ra_client):
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, found=False, NetworkInsightsPathId="nip-unrelated")
        cleanup(stub, analysis=False)
        with pytest.raises(AnalysisError, match="path identity") as caught:
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1", expect_reachable=False)
        assert caught.value.evidence["analysis_id"] == ANALYSIS
        stub.assert_no_pending_responses()


def test_poll_cannot_switch_to_a_different_path(ra_client, monkeypatch):
    monkeypatch.setattr(reachability, "sleep", lambda _: None)
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, status="running", found=None)
        stub.add_response(
            "describe_network_insights_analyses",
            {
                "NetworkInsightsAnalyses": [
                    {
                        "NetworkInsightsAnalysisId": ANALYSIS,
                        "NetworkInsightsPathId": "nip-unrelated",
                        "Status": "succeeded",
                        "NetworkPathFound": True,
                    }
                ]
            },
            {"NetworkInsightsAnalysisIds": [ANALYSIS]},
        )
        cleanup(stub)
        with pytest.raises(AnalysisError, match="identity"):
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1")
        stub.assert_no_pending_responses()


def test_poll_consumes_every_page_before_claiming_one_matching_analysis(ra_client, monkeypatch):
    monkeypatch.setattr(reachability, "sleep", lambda _: None)
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, status="running", found=None)
        stub.add_response(
            "describe_network_insights_analyses",
            {"NetworkInsightsAnalyses": [], "NextToken": "next"},
            {"NetworkInsightsAnalysisIds": [ANALYSIS]},
        )
        stub.add_response(
            "describe_network_insights_analyses",
            {
                "NetworkInsightsAnalyses": [
                    {
                        "NetworkInsightsAnalysisId": ANALYSIS,
                        "NetworkInsightsPathId": PATH,
                        "Status": "succeeded",
                        "NetworkPathFound": True,
                    }
                ]
            },
            {"NetworkInsightsAnalysisIds": [ANALYSIS], "NextToken": "next"},
        )
        cleanup(stub)
        assert ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1")
        stub.assert_no_pending_responses()


def test_sdk_error_retains_diagnostics_for_created_ra_resources(ra_client):
    with Stubber(ra_client) as stub:
        create(stub)
        stub.add_client_error("start_network_insights_analysis", "UnauthorizedOperation")
        cleanup(stub, analysis=False)
        with pytest.raises(ClientError) as caught:
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1")
        assert caught.value.evidence["path_id"] == PATH
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("keep", ["False", "True", 0, 1, None])
def test_keep_analysis_requires_boolean_to_avoid_accidental_resource_retention(ra_client, keep):
    with pytest.raises(ValueError, match="keep_analysis must be a boolean"):
        ReachabilityAnalyzer(ra_client, keep_analysis=keep)


@pytest.mark.parametrize("field", ["FilterInArns", "FilterOutArns"])
@pytest.mark.parametrize("found", [False, True])
def test_unrequested_analysis_filters_never_change_the_reachability_claim(ra_client, field, found):
    with Stubber(ra_client) as stub:
        create(stub)
        start(
            stub,
            found=found,
            **{field: [f"arn:aws:ec2:{REGION}:111111111111:network-interface/{DESTINATION}"]},
        )
        cleanup(stub)
        with pytest.raises(AnalysisError, match="scope is unconfirmed") as caught:
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1", expect_reachable=found)
        assert caught.value.evidence["cleanup"] == {"analysis": "deleted", "path": "deleted"}
        stub.assert_no_pending_responses()


def test_unrequested_analysis_account_scope_cannot_pass_isolation(ra_client):
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub, found=False, AdditionalAccounts=["222222222222"])
        cleanup(stub)
        with pytest.raises(AnalysisError, match="account scope"):
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1", expect_reachable=False)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("kind", ["analysis", "path"])
@pytest.mark.parametrize("returned", [None, "unrelated"])
def test_missing_or_wrong_deletion_identity_is_visible_in_warning_and_evidence(
    ra_client, kind, returned
):
    parameters = {
        "analysis": ("delete_network_insights_analysis", "NetworkInsightsAnalysisId", ANALYSIS),
        "path": ("delete_network_insights_path", "NetworkInsightsPathId", PATH),
    }
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub)
        for resource in ("analysis", "path"):
            operation, parameter, identifier = parameters[resource]
            response = (
                ({} if returned is None else {parameter: returned})
                if resource == kind
                else {parameter: identifier}
            )
            stub.add_response(operation, response, {parameter: identifier})
        with pytest.warns(CleanupWarning, match="confirm the requested identity"):
            result = ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1")
        assert result
        assert result.evidence["cleanup"][kind] == "unconfirmed"
        other = "path" if kind == "analysis" else "analysis"
        assert result.evidence["cleanup"][other] == "deleted"
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("endpoint", ["source", "destination"])
def test_foreign_partition_endpoints_fail_before_analysis(ra_client, endpoint):
    arn = f"arn:aws-cn:ec2:{REGION}:111111111111:network-interface/{SOURCE}"
    endpoints = {"source": SOURCE, "destination": DESTINATION, endpoint: arn}
    with Stubber(ra_client) as stub:
        with pytest.raises(UnsupportedCheckError, match="partition"):
            ReachabilityAnalyzer(ra_client).check(**endpoints)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("field", ["ForwardPathComponents", "ReturnPathComponents"])
@pytest.mark.parametrize("found", [False, True])
@pytest.mark.parametrize(
    "detail",
    [
        "PATH_THROUGH_GWLB_NOT_CHECKED",
        "FIREWALL_UNSUPPORTED_HIGHER_PRIORITY_RULES",
        "ASSUMPTION_PRESERVE_CLIENT_IP_IS_ENABLED",
        "FUTURE_UNVERIFIED_DETAIL",
    ],
)
def test_unsupported_or_assumed_analysis_details_never_pass_a_predicate(
    ra_client, field, found, detail
):
    with Stubber(ra_client) as stub:
        create(stub)
        start(
            stub,
            found=found,
            **{
                field: [
                    {
                        "SequenceNumber": 1,
                        "AdditionalDetails": [{"AdditionalDetailType": detail}],
                    }
                ]
            },
        )
        cleanup(stub)
        with pytest.raises(AnalysisError, match="additional details") as caught:
            ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1", expect_reachable=found)
        assert caught.value.evidence["cleanup"] == {"analysis": "deleted", "path": "deleted"}
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("kind", ["analysis", "path"])
@pytest.mark.parametrize("interrupt_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("original_failure", [False, True])
@pytest.mark.parametrize("warnings_as_errors", [False, True])
def test_cleanup_cancellation_finishes_bookkeeping_and_preserves_the_right_error(
    ra_client, monkeypatch, kind, interrupt_type, original_failure, warnings_as_errors
):
    interrupt = interrupt_type("cleanup interrupted")
    original = AnalysisError("Original evaluation failure") if original_failure else None
    if original is not None:
        monkeypatch.setattr(reachability, "blocker_summaries", Mock(side_effect=original))
    parameters = {
        "analysis": ("delete_network_insights_analysis", "NetworkInsightsAnalysisId", ANALYSIS),
        "path": ("delete_network_insights_path", "NetworkInsightsPathId", PATH),
    }
    operation, parameter, identifier = parameters[kind]
    canceled = Mock(side_effect=interrupt)
    monkeypatch.setattr(ra_client, operation, canceled)
    with Stubber(ra_client) as stub:
        create(stub)
        start(stub)
        other = "path" if kind == "analysis" else "analysis"
        other_operation, other_parameter, other_id = parameters[other]
        stub.add_response(other_operation, {other_parameter: other_id}, {other_parameter: other_id})
        expected = original if original is not None else interrupt
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("error" if warnings_as_errors else "always", CleanupWarning)
            with pytest.raises(type(expected)) as caught:
                ReachabilityAnalyzer(ra_client).check(SOURCE, "10.47.1.1")
        assert caught.value is expected
        assert caught.value.evidence["path_id"] == PATH
        cleanup_evidence = caught.value.evidence["cleanup"]
        assert cleanup_evidence[kind] == "unconfirmed"
        assert cleanup_evidence[f"{kind}_error"] == "cleanup interrupted"
        assert cleanup_evidence[f"{kind}_interrupted"] is True
        assert cleanup_evidence[other] == "deleted"
        if not warnings_as_errors:
            assert any(item.category is CleanupWarning for item in recorded)
        canceled.assert_called_once_with(**{parameter: identifier})
        stub.assert_no_pending_responses()
