"""Read an existing inspection layout and two explicitly selected route tables.

These are topology requirements. Other path segments, firewall rules and packet
inspection need their own checks. Both selected ingress tables use the validated
endpoint for INSPECTION_AZ; no route-table-to-AZ relationship is inferred here.
"""

import json

import pytest

from aws_network_asserts import (
    expect,
    have_appliance_mode,
    have_bidirectional_routes,
    have_firewall_endpoints,
)
from contrib.pytest_examples import aws_enabled

pytestmark = [
    pytest.mark.aws,
    pytest.mark.skipif(
        not aws_enabled(), reason="Use -p contrib.pytest_examples --run-aws to run AWS examples"
    ),
]


def test_the_declared_inspection_topology(rule, aws_value):
    tgw = aws_value("TRANSIT_GATEWAY")
    vpc = aws_value("INSPECTION_VPC_ID")
    firewall = aws_value("INSPECTION_FIREWALL_ARN")
    subnets = json.loads(aws_value("INSPECTION_SUBNETS_BY_AZ"))
    zone = aws_value("INSPECTION_AZ")
    if not isinstance(subnets, dict) or zone not in subnets:
        raise pytest.UsageError("INSPECTION_AZ must be declared in INSPECTION_SUBNETS_BY_AZ")
    ingress = rule.subnet(aws_value("INSPECTION_INGRESS_SUBNET"))
    return_ingress = rule.subnet(aws_value("INSPECTION_RETURN_SUBNET"))
    source = aws_value("SOURCE_CIDR")
    destination = aws_value("DESTINATION_CIDR")
    expect(rule.tgw(tgw)).to(have_appliance_mode(vpc))
    layout = expect(rule.vpc(vpc)).to(have_firewall_endpoints(firewall, subnets_by_az=subnets))
    endpoint = layout.evidence["firewall_status"]["SyncStates"][zone]["Attachment"]["EndpointId"]
    expect(ingress).to(
        have_bidirectional_routes(
            destination,
            source=source,
            return_table=return_ingress,
            via=endpoint,
            return_via=endpoint,
        )
    )
