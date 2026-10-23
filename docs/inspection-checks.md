# Check an inspection network's topology

Treat inspection as several separate requirements: attachment behavior, endpoint
placement, selected routes, modeled paths and observed traffic. The checks here
read existing resources. They do not deploy or change a firewall.

## Appliance mode and firewall placement

```python
from aws_network_asserts import expect, have_appliance_mode, have_firewall_endpoints

expect(network.tgw(tgw_id)).to(have_appliance_mode(inspection_vpc_id))
layout = expect(network.vpc(inspection_vpc_id)).to(
    have_firewall_endpoints(
        firewall_arn,
        subnets_by_az={"eu-west-2a": firewall_subnet_a, "eu-west-2b": firewall_subnet_b},
    )
)
```

Select the TGW owner's account for the first check and the firewall/VPC owner's
account for the second; these accounts can differ. The TGW check requires exactly
one available attachment for the requested VPC, with appliance mode enabled.

The firewall check verifies the selected VPC and each subnet's live owner, VPC,
AZ and state. It requires exactly the declared subnet/AZ layout, a ready firewall,
synchronized configuration and a distinct ready endpoint in each declared AZ.
An extra or missing AZ, a pending endpoint or a different layout fails. Unknown
states, missing identity evidence and API failures raise. Neither check examines
firewall rules or proves that traffic reaches the firewall.

Direct equivalents are `tgw.has_appliance_mode(vpc_id)` and
`vpc.has_firewall_endpoints(arn, subnets_by_az=mapping)`. They return `CheckResult`.

## Forward and return route selections

```python
from aws_network_asserts import expect, have_bidirectional_routes

zone = "eu-west-2a"
endpoint = layout.evidence["firewall_status"]["SyncStates"][zone]["Attachment"]["EndpointId"]
expect(network.subnet(ingress_subnet)).to(
    have_bidirectional_routes(
        "10.50.0.0/16",
        source="10.40.0.0/16",
        return_table=network.subnet(return_ingress_subnet),
        via=endpoint,
        return_via=endpoint,
    )
)
```

This asserts two explicit effective route selections. It checks every address in
each range, including more-specific routes and blackholes. Interface-scoped
IPv6 text (such as `fe80::1%eth0`) is rejected: AWS route CIDRs have no interface
scope. A source subnet's
explicit association or inherited main table must have complete active native
association evidence. A response for another table or subnet cannot pass.

`has_bidirectional_routes(destination, source=..., return_table=..., via=...,
return_via=...)` is also available directly on subnet and VPC route-table
selectors. For TGW tables, `via` and `return_via` name the forward and return
`tgw-attach-...` IDs; the matcher uses these same options. Both tables must
belong to the same scoped TGW for a TGW pair. VPC pairs stay in one region.

Use the validated endpoint for the intended AZ in both directions when your
design requires that symmetry. The route-pair check itself does not bind either
table to that AZ or infer the firewall subnet's egress routes. Declare those
relationships separately. An ingress route pair alone does not establish the
TGW association, every intermediate segment, per-flow symmetry or full packet
inspection. Negating paired routes or endpoint layout is rejected: an incomplete
layout is not evidence that inspection is absent.

Add RA path constraints where supported and authorized observed protocol checks.
For the real host network, use an [SSM probe](ssm-probes.md); a Lambda probe uses
its own interface. AWS's [centralized inspection guidance](https://aws.amazon.com/blogs/networking-and-content-delivery/centralized-inspection-architecture-with-aws-gateway-load-balancer-and-aws-transit-gateway/)
explains why appliance mode and forward/return routing matter together.

The [policy example](../iam/inspection-topology-policy.example.json) contains the
extra read permissions. Config inventory permissions remain separate.
