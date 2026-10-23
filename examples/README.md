# Run the examples against an existing network

These files are ordinary pytest tests. The optional helper in
[contrib/pytest_examples.py](../contrib/pytest_examples.py) supplies their fixtures
and command-line options. Run from the repository root after installing the
package's development dependencies:

```bash
# Collection is safe: without --run-aws every example is skipped.
python -m pytest examples/ -q

# Use your existing AWS profiles and resources.
python -m pytest -p contrib.pytest_examples examples/test_network.py \
  --run-aws --aws-region eu-west-2

# Or use the contrib MiniStack shim and its explicitly selected endpoint.
python -m pytest -p contrib.pytest_examples examples/test_network.py \
  --run-aws --ministack --config-mode off --aws-region eu-west-2
```

`--run-aws` authorizes contacting the chosen API endpoint. RA creates chargeable
paths and analyses. An emulator must provide the native evidence these checks
need; an unsupported operation raises. A passing mocked test or a partial
emulator does not establish compatibility with live AWS.

Use `NETWORK_ACCOUNT_ID` for resource ownership. Existing AWS setups use
`--aws-profile` and optional `NETWORK_ACCOUNT_PROFILES` JSON. MiniStack uses
`MINISTACK_ACCOUNT_ID` for the central account and separate shim sessions for
selected member accounts. See the [usage guide](../docs/usage.md#ministack-examples)
for endpoint and Config-reader settings. No examples enable recording, deploy
infrastructure, enroll SSM nodes or change an existing instance profile.

## Complete coverage and stable samples

[test_coverage.py](test_coverage.py) needs `SOURCE_SUBNET`, `EXPECTED_SOURCE_ENIS`,
`DESTINATION_ENIS` and `REACHABILITY_PORTS`; lists are comma-separated. It compares
the discovered ENIs with the exact expected set, prints the complete read-only
execution plan, then checks every source/destination/port combination. The
optional `MAX_REACHABILITY_ANALYSES` defaults to 100. This is an execution-count
limit, not a price estimate. All endpoints in this example use the selected
account/region; use scoped fixture selectors for cross-account populations.

Its stability test instead needs `SOURCE_SUBNET`, `DESTINATION_CIDR` and
`ROUTE_TARGET`. Choose a test with `-k` when only one set of inputs is configured.

## Observe connections

The [protocol](test_protocol_probe.py), [workload](test_workload_probe.py) and
[dual-stack](test_dual_stack.py) examples use temporary Lambda functions. They
require `--allow-probe-writes` in addition to `--run-aws`, plus the source/target
variables used in the file. Role and security-group creation are separate options:
`--auto-create-execution-role` and `--auto-create-security-group`. Workload-derived
Lambda probes retain the workload's actual groups and reject automatic groups.

[test_recoverable_probe.py](test_recoverable_probe.py) also needs a fresh
`PROBE_CLEANUP_MANIFEST` path in an existing directory. Keep this file outside
pytest's disposable directories and retain it as a private artifact if cleanup
is interrupted. The [recovery guide](../docs/recovery.md) explains dry-run
inspection and explicit deletion. One manifest belongs to one deployment.

[test_ssm_probe.py](test_ssm_probe.py) needs an existing online managed Linux
`SOURCE_INSTANCE` with Python 3.10+, and `PROBE_HEALTH_URL`. Its separate command
permission is explicit:

```bash
python -m pytest -p contrib.pytest_examples examples/test_ssm_probe.py \
  --run-aws --allow-ssm-commands --aws-region eu-west-2
```

SSM uses the host network under the agent's execution user. It does not reproduce
an application's container/user context. Read [SSM prerequisites and cancellation
limits](../docs/ssm-probes.md) before running it.

## Inspect existing firewall topology

[test_inspection.py](test_inspection.py) reads an existing TGW, inspection VPC and
Network Firewall. Set `TRANSIT_GATEWAY`, `INSPECTION_VPC_ID`,
`INSPECTION_FIREWALL_ARN`, `INSPECTION_SUBNETS_BY_AZ` (a JSON object mapping AZ names
to subnet IDs), `INSPECTION_AZ`, `INSPECTION_INGRESS_SUBNET`,
`INSPECTION_RETURN_SUBNET`, `SOURCE_CIDR` and `DESTINATION_CIDR`.

This example assumes the TGW and firewall share the selected owner account.
Use separate owner-scoped builders where they differ. It checks appliance mode,
exact ready endpoint placement and two selected routes through the endpoint for
one declared AZ. Other intermediate segments, table-to-AZ relationships,
firewall rules and packet inspection require additional checks. See the
[inspection guide](../docs/inspection-checks.md).
