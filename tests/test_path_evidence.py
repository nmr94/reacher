"""Path intent is checked against complete native RA component evidence."""

from copy import deepcopy

import boto3
import pytest
from botocore.stub import Stubber
from test_reachability import DESTINATION, SOURCE, cleanup, create, start

from aws_network_asserts import AnalysisError, UnsupportedCheckError
from aws_network_asserts.reachability import ReachabilityAnalyzer

TGW = "tgw-0123456789abcdef0"
OTHER = "igw-0123456789abcdef0"
REGION = "eu-west-2"


def path_components():
    return [
        {"SequenceNumber": index, "Component": {"Id": resource}}
        for index, resource in enumerate((SOURCE, TGW, DESTINATION), 1)
    ]


@pytest.fixture
def analyzer():
    return ReachabilityAnalyzer(
        boto3.client(
            "ec2", region_name=REGION, aws_access_key_id="test", aws_secret_access_key="test"
        )
    )


def evaluate(analyzer, *, components=None, options=None, found=True, **analysis):
    with Stubber(analyzer.client) as stub:
        create(stub, Destination=DESTINATION)
        start(
            stub,
            found=found,
            ForwardPathComponents=path_components() if components is None else components,
            **analysis,
        )
        cleanup(stub)
        result = analyzer.check(
            SOURCE, DESTINATION, destination_ip="10.47.1.1", **(options or {"through": [TGW]})
        )
        stub.assert_no_pending_responses()
        return result


@pytest.mark.parametrize(
    "options,passed",
    [
        ({"through": [TGW]}, True),
        ({"through": [OTHER]}, False),
        ({"avoiding": [OTHER]}, True),
        ({"avoiding": [TGW]}, False),
        ({"through": [TGW], "avoiding": [OTHER]}, True),
    ],
)
def test_path_constraints_evaluate_complete_forward_hops(analyzer, options, passed):
    result = evaluate(analyzer, options=options)
    assert bool(result) is passed
    assert result.evidence["path_constraints"]["direction"] == "forward"


@pytest.mark.parametrize("change", ["empty", "missing-id", "sequence", "gap", "boundary", "arn"])
def test_incomplete_or_contradictory_path_evidence_raises_and_cleans_up(analyzer, change):
    rows = path_components()
    if change == "empty":
        rows.clear()
    elif change == "missing-id":
        rows[1]["Component"].clear()
    elif change == "sequence":
        rows[1]["SequenceNumber"] = 1
    elif change == "gap":
        rows[2]["SequenceNumber"] = 5
    elif change == "boundary":
        rows[-1]["Component"]["Id"] = "eni-00000000000000001"
    elif change == "arn":
        rows[1]["Component"]["Arn"] = f"arn:aws:ec2:{REGION}:111111111111:transit-gateway/{OTHER}"
    with Stubber(analyzer.client) as stub:
        create(stub, Destination=DESTINATION)
        start(stub, ForwardPathComponents=rows)
        cleanup(stub)
        with pytest.raises(AnalysisError) as caught:
            analyzer.check(SOURCE, DESTINATION, destination_ip="10.47.1.1", through=[TGW])
        assert caught.value.evidence["analysis_id"]
        stub.assert_no_pending_responses()


def test_arn_constraint_needs_matching_component_ownership(analyzer):
    arn = f"arn:aws:ec2:{REGION}:111111111111:transit-gateway/{TGW}"
    rows = path_components()
    with pytest.raises(AnalysisError, match="ARN ownership"):
        evaluate(analyzer, components=rows, options={"through": [arn]})
    rows[1]["Component"]["Arn"] = arn
    assert evaluate(analyzer, components=rows, options={"through": [arn]})


@pytest.mark.parametrize("constraint", ["through", "avoiding"])
@pytest.mark.parametrize(
    "component",
    [
        {
            "Id": TGW,
            "Arn": f"arn:aws:ec2:{REGION}:111111111111:network-interface/{TGW}",
        },
        {"Arn": f"arn:aws:ec2:{REGION}:111111111111:network-interface/{TGW}"},
        {
            "Id": TGW,
            "Arn": f"arn:aws:ec2:{REGION}:111111111111:transit-gateway/{OTHER}",
        },
        {
            "Id": TGW,
            "Arn": f"arn:aws:ec2:us-east-1:111111111111:transit-gateway/{TGW}",
        },
        {
            "Id": TGW,
            "Arn": f"arn:aws:ec2:{REGION}:111111111111:transit-gateway/tgw-00000000000000001",
        },
    ],
)
def test_contradictory_scoped_components_raise_instead_of_proving_absence_and_clean_up(
    analyzer, constraint, component
):
    arn = f"arn:aws:ec2:{REGION}:111111111111:transit-gateway/{TGW}"
    rows = path_components()
    rows[1]["Component"] = component
    with Stubber(analyzer.client) as stub:
        create(stub, Destination=DESTINATION)
        start(stub, ForwardPathComponents=rows)
        cleanup(stub)
        with pytest.raises(AnalysisError) as caught:
            analyzer.check(SOURCE, DESTINATION, destination_ip="10.47.1.1", **{constraint: [arn]})
        assert caught.value.evidence["analysis_id"]
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "resource_type,identifier",
    [
        ("network-interface", SOURCE),
        ("instance", "i-0123456789abcdef0"),
        ("internet-gateway", OTHER),
        ("transit-gateway", TGW),
        ("transit-gateway-attachment", "tgw-attach-0123456789abcdef0"),
        ("vpc-endpoint", "vpce-0123456789abcdef0"),
        ("vpc-endpoint-service", "vpce-svc-0123456789abcdef0"),
        ("vpc-peering-connection", "pcx-0123456789abcdef0"),
        ("natgateway", "nat-0123456789abcdef0"),
        ("vpn-gateway", "vgw-0123456789abcdef0"),
    ],
)
def test_valid_typed_component_arns_keep_scoped_path_intent(analyzer, resource_type, identifier):
    arn = f"arn:aws:ec2:{REGION}:111111111111:{resource_type}/{identifier}"
    rows = path_components()
    rows[1]["Component"] = {"Id": identifier, "Arn": arn}
    assert evaluate(analyzer, components=rows, options={"through": [arn]})
    assert not evaluate(analyzer, components=rows, options={"avoiding": [arn]})


@pytest.mark.parametrize("constraint", ["through", "avoiding"])
@pytest.mark.parametrize(
    "resource",
    [
        f"network-interface/{TGW}",
        f"transit-gateway/{SOURCE}",
        "transit-gateway/tgw-attach-0123456789abcdef0",
        "vpc-endpoint/vpce-svc-0123456789abcdef0",
        f"unknown-resource/{TGW}",
        f"transit-gateway/{TGW}/extra",
    ],
)
def test_mismatched_component_arn_types_are_rejected_before_sdk_requests(
    analyzer, constraint, resource
):
    arn = f"arn:aws:ec2:{REGION}:111111111111:{resource}"
    with Stubber(analyzer.client) as stub:
        with pytest.raises(ValueError, match="traffic components"):
            analyzer.check(SOURCE, DESTINATION, **{constraint: [arn]})
        stub.assert_no_pending_responses()


def test_route_metadata_is_not_counted_as_a_traversed_component(analyzer):
    rows = path_components()
    rows[1]["Component"]["Id"] = "vpce-0123456789abcdef0"
    rows[1]["RouteTableRoute"] = {"TransitGatewayId": TGW}
    assert not evaluate(analyzer, components=rows)


@pytest.mark.parametrize(
    "analysis",
    [
        {"WarningMessage": "Partial analysis"},
        {"Explanations": [{"ExplanationCode": "HIGHER_PRIORITY_ROUTE"}]},
    ],
)
def test_qualified_paths_cannot_pass_from_warned_or_explained_analysis(analyzer, analysis):
    with pytest.raises(AnalysisError):
        evaluate(analyzer, **analysis)


def test_blocked_path_fails_positive_intent_without_claiming_hop_coverage(analyzer):
    result = evaluate(analyzer, components=[], found=False)
    assert not result
    assert result.evidence["path_constraints"]["evaluated"] is False


@pytest.mark.parametrize(
    "options,error",
    [
        ({"through": TGW}, ValueError),
        ({"through": [TGW, TGW]}, ValueError),
        ({"through": [TGW], "avoiding": [TGW]}, ValueError),
        ({"through": [TGW], "expect_reachable": False}, ValueError),
        ({"avoiding": ["sg-0123456789abcdef0"]}, ValueError),
        ({"avoiding": ["tgw-rtb-0123456789abcdef0"]}, ValueError),
        ({"through": [f"arn:aws:ec2:us-east-1:111111111111:transit-gateway/{TGW}"]}, ValueError),
    ],
)
def test_invalid_path_intent_is_rejected_before_any_sdk_request(analyzer, options, error):
    with Stubber(analyzer.client) as stub:
        with pytest.raises(error):
            analyzer.check(SOURCE, DESTINATION, **options)
        stub.assert_no_pending_responses()


def test_ip_only_path_constraint_scope_is_explicitly_unsupported(analyzer):
    with Stubber(analyzer.client) as stub:
        with pytest.raises(UnsupportedCheckError, match="resource destination"):
            analyzer.check(SOURCE, "10.47.1.1", avoiding=[OTHER])
        stub.assert_no_pending_responses()


def test_blocker_reports_keep_reported_direction_resource_and_rule(analyzer):
    explanation = {
        "ExplanationCode": "ENI_SG_RULES_MISMATCH",
        "Direction": "ingress",
        "SecurityGroup": {
            "Id": "sg-0123456789abcdef0",
            "Arn": f"arn:aws:ec2:{REGION}:111111111111:security-group/sg-0123456789abcdef0",
        },
        "NetworkInterface": {"Id": DESTINATION},
        "SecurityGroupRule": {"Direction": "ingress", "Protocol": "tcp"},
    }
    rows = path_components()
    rows[-1]["Explanations"] = [deepcopy(explanation)]
    result = evaluate(analyzer, components=rows, options={"expect_reachable": False}, found=False)
    assert result
    summary = result.evidence["explanations"][0]
    assert summary["path_direction"] == "forward"
    assert summary["direction"] == "ingress"
    assert summary["reported"] == explanation
    assert "sg-0123456789abcdef0" in result.message
    assert "No security-group rule permits" in result.message


def test_unknown_explanation_is_retained_without_a_guessed_diagnosis(analyzer):
    result = evaluate(
        analyzer,
        options={"expect_reachable": False},
        found=False,
        Explanations=[{"ExplanationCode": "FUTURE_EXPLANATION"}],
    )
    summary = result.evidence["explanations"][0]
    assert summary["description"] == "AWS reported FUTURE_EXPLANATION"
    assert summary["direction"] == "unspecified"


def test_attached_instance_is_part_of_the_reported_traffic_path(analyzer):
    rows = path_components()
    instance = "i-0123456789abcdef0"
    rows[0]["AttachedTo"] = {"Id": instance}
    assert evaluate(analyzer, components=rows, options={"through": [instance]})
    assert not evaluate(analyzer, components=rows, options={"avoiding": [instance]})


@pytest.mark.parametrize(
    "arn",
    [
        f"foo:aws:ec2:{REGION}:111111111111:transit-gateway/{TGW}",
        f"arn:aws:ec2:us-east-1:111111111111:transit-gateway/{TGW}",
    ],
)
def test_malformed_or_foreign_region_component_arns_cannot_satisfy_intent(analyzer, arn):
    rows = path_components()
    rows[1]["Component"]["Arn"] = arn
    with pytest.raises(AnalysisError):
        evaluate(analyzer, components=rows)


def test_huge_sequence_number_is_rejected_without_expanding_a_range(analyzer):
    rows = path_components()
    rows[-1]["SequenceNumber"] = 10**18
    with pytest.raises(AnalysisError):
        evaluate(analyzer, components=rows)


@pytest.mark.parametrize(
    "code",
    [
        "ASSUMPTION_PRESERVE_CLIENT_IP_IS_DISABLED",
        "ASSUMPTION_PRESERVE_CLIENT_IP_IS_ENABLED",
        "MISSING_TARGET_GROUP_ATTRIBUTES",
        "FIREWALL_UNSUPPORTED_HIGHER_PRIORITY_RULE_GROUP_TYPE",
        "FIREWALL_UNSUPPORTED_HIGHER_PRIORITY_RULES",
        "FIREWALL_UNSUPPORTED_RULE_OPTIONS",
        "PATH_THROUGH_GWLB_NOT_CHECKED",
        "FUTURE_UNVERIFIED_PATH_DETAIL",
    ],
)
def test_omitted_or_assumed_forward_path_details_cannot_prove_avoidance(analyzer, code):
    rows = path_components()
    rows[1]["AdditionalDetails"] = [{"AdditionalDetailType": code}]
    with pytest.raises(AnalysisError, match="additional details"):
        evaluate(analyzer, components=rows, options={"avoiding": [OTHER]})


@pytest.mark.parametrize(
    "code",
    [
        "AVAILABILITY_ZONE_CROSSED",
        "UNIDIRECTIONAL_PATH_ANALYSIS_ONLY",
        "RESPONSE_RTB_HAS_NO_ROUTE_TO_TRANSIT_GATEWAY",
        "TRANSIT_GATEWAY_APPLIANCE_MODE_RECOMMENDED",
    ],
)
def test_informational_details_do_not_change_the_forward_only_claim(analyzer, code):
    rows = path_components()
    rows[1]["AdditionalDetails"] = [{"AdditionalDetailType": code}]
    assert evaluate(analyzer, components=rows)


@pytest.mark.parametrize("constraint", ["through", "avoiding"])
def test_one_hops_arn_cannot_supply_another_hops_missing_ownership(analyzer, constraint):
    requested = f"arn:aws:ec2:{REGION}:111111111111:transit-gateway/{TGW}"
    other_owner = f"arn:aws:ec2:{REGION}:222222222222:transit-gateway/{TGW}"
    rows = path_components()
    rows.insert(2, {"SequenceNumber": 3, "Component": {"Id": TGW, "Arn": other_owner}})
    rows[-1]["SequenceNumber"] = 4
    with pytest.raises(AnalysisError, match="ARN ownership"):
        evaluate(analyzer, components=rows, options={constraint: [requested]})


def test_firewall_name_matching_an_ec2_id_is_not_that_ec2_resource(analyzer):
    rows = path_components()
    rows[1]["Component"] = {"Arn": f"arn:aws:network-firewall:{REGION}:111111111111:firewall/{TGW}"}
    assert not evaluate(analyzer, components=rows, options={"through": [TGW]})
    assert evaluate(analyzer, components=rows, options={"avoiding": [TGW]})


@pytest.mark.parametrize("component", [{"Id": "unrecognized"}, {"Id": "eni-value\x00"}])
def test_unknown_native_hops_cannot_establish_complete_avoidance(analyzer, component):
    rows = path_components()
    rows[1]["Component"] = component
    with pytest.raises(AnalysisError, match="identity"):
        evaluate(analyzer, components=rows, options={"avoiding": [TGW]})


@pytest.mark.parametrize("field", ["AttachedTo", "TransitGateway", "ElasticLoadBalancerListener"])
def test_related_metadata_cannot_masquerade_as_an_eni_boundary(analyzer, field):
    rows = path_components()
    rows[-1]["Component"] = {"Id": "eni-other"}
    rows[-1][field] = {"Id": DESTINATION}
    with pytest.raises(AnalysisError, match="resource kind"):
        evaluate(analyzer, components=rows)


def test_configuration_objects_remain_valid_path_evidence(analyzer):
    rows = path_components()
    rows.insert(1, {"SequenceNumber": 2, "Component": {"Id": "acl-example"}})
    rows.insert(2, {"SequenceNumber": 3, "Component": {"Id": "sg-example"}})
    for index, row in enumerate(rows, 1):
        row["SequenceNumber"] = index
    assert evaluate(analyzer, components=rows)


@pytest.mark.parametrize(
    "component",
    [
        f"arn:aws-cn:ec2:{REGION}:111111111111:transit-gateway/{TGW}",
        f"arn:AWS:ec2:{REGION}:111111111111:transit-gateway/{TGW}",
        f"arn:aws:network-firewall:{REGION}:111111111111:firewall/",
        f"arn:aws:elasticloadbalancing:{REGION}:111111111111:listener/",
    ],
)
def test_invalid_partition_or_incomplete_service_arn_fails_before_sdk_requests(analyzer, component):
    with Stubber(analyzer.client) as stub:
        with pytest.raises(ValueError):
            analyzer.check(SOURCE, DESTINATION, avoiding=[component])
        stub.assert_no_pending_responses()


def test_native_foreign_partition_cannot_prove_scoped_avoidance(analyzer):
    rows = path_components()
    rows[1]["Component"]["Arn"] = f"arn:aws-cn:ec2:{REGION}:111111111111:transit-gateway/{TGW}"
    with pytest.raises(AnalysisError, match="partition"):
        evaluate(analyzer, components=rows, options={"avoiding": [OTHER]})
