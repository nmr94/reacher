# Recover an interrupted Lambda probe

Normal probe cleanup runs when its call or context ends, including after an
assertion or AWS error. A killed process cannot run that cleanup. Set
`cleanup_manifest` to keep a durable record that a later command can inspect.
The option works with one-shot Lambda probes and Lambda sessions, including
sessions derived from a workload ENI or instance.

```python
with source.subnet(subnet_id).probe_session(
    allow_write=True,
    auto_create_execution_role=True,
    auto_create_security_group=True,
    cleanup_manifest=".probe-runs/database-check.json",
) as probe:
    result = probe.tcp("database.internal.example", port=5432)
    assert result, result.message
```

Create the parent directory first. Use a fresh path for each deployment; an
existing file is never overwritten, even when its run completed. Keep the file
on storage that survives the test process, or retain it as a private CI artifact.
No AWS resources are created if the initial record cannot be saved. Each later
create also waits for its write-ahead record; a failed update triggers normal
cleanup of resources already created by the run.

The JSON contains the account, region, run ID, source subnet, groups and temporary
resource identities. It contains no credentials, function code, request bodies
or response bodies. Files are private to their owner when created, written by
atomic replacement and flushed to disk. A sibling `.lock` file coordinates the
running deployment and recovery commands; OS locks release when a process exits.
The empty lock file can remain after a completed run.

## Inspect first

Use the same account and region as the recorded deployment:

```bash
python -m aws_network_asserts.recovery .probe-runs/database-check.json \
  --account 111111111111 --region eu-west-2 --profile network-test-runner
```

This is a dry run. It reads current AWS identities and prints a JSON report,
without deleting resources or changing the manifest. Add `--allow-writes` to
perform cleanup:

```bash
python -m aws_network_asserts.recovery .probe-runs/database-check.json \
  --account 111111111111 --region eu-west-2 --profile network-test-runner \
  --allow-writes --cleanup-timeout 1200
```

The command uses normal boto3 profile credentials, verifies their account through
STS and never needs the original process's credentials. `--endpoint-url URL`
sets a custom service endpoint. Through the Python API, the supplied builder's
per-service/regional endpoints, member sessions, TLS and SDK transport settings
apply unchanged:

```python
from aws_network_asserts import recover_probes

report = recover_probes(source, ".probe-runs/database-check.json")
report = recover_probes(
    source,
    ".probe-runs/database-check.json",
    allow_write=True,
    cleanup_timeout=1200,
)
```

`source` must be a builder scoped to the recorded account and region. The write
option must be a boolean. Recovery does not read Config, create probes or send
application traffic. It cannot run while the same manifest is locked by an
active deployment or another recovery command.

## What recovery can delete

Create intent is saved before every AWS create call. The returned identity is
saved afterward. Recovery uses those confirmed identities and checks them again:

- Lambda: the run's exact name and ARN, creation revision, execution role,
  subnet and complete security-group set must still match.
- Security group: its ID, account, VPC, unique run name and probe tag must match.
- IAM role: its name, ARN and immutable role ID must match. A replacement with
  the same name does not qualify.

Resources with unconfirmed identities are skipped. For example, a process can
die after AWS creates a role but before its response is saved. A name in the
write-ahead record is useful for investigation; it does not authorize adopting
or deleting a resource found under that name. Missing native Lambda revision or
IAM role-ID evidence also prevents recovery from deleting that resource.

Existing caller-supplied roles and groups are never recorded as temporary
resources and are never deleted. Recovery never deletes ENIs or changes network
configuration. Do not edit a manifest to make an uncertain resource appear
confirmed; investigate it using your normal AWS administration process.

## Cleanup order and role reuse

Recovery deletes the function, then its temporary group, then its temporary
role. An already absent confirmed resource counts as deleted. Uncertain function
cleanup retains its group and role. If the group cannot be deleted after a
function was created, the role stays available for Lambda's ENI cleanup.

Before removing a role, recovery also requires its original Lambda trust policy,
its original ENI inline policy or no remaining inline policy, no extra attached
policies, no instance profiles and no permissions boundary. It lists Lambda
functions, including published versions, in every currently enabled region of
the account. A function using
the role, unavailable regional inventory or a changed policy retains the role
for review. A reported last-used region outside the original region also
requires manual review. Dry runs account for the recorded function's planned
deletion when reporting role eligibility.

With supplied groups, recovery still waits for matching Lambda ENIs in the
recorded subnet and region before removing the role's permissions. Successful
deletion of a temporary group establishes that no ENI uses that group. Polling
and dependency discovery share `cleanup_timeout`; individual SDK requests and
retries can extend elapsed time.

These checks cover current Lambda consumers and the recorded deployment's ENI
context. They cannot reconstruct all historical use of a role or make AWS reads
and deletes atomic. Avoid reusing temporary resources or changing them while
recovery runs. Keep roles when the report cannot establish safe cleanup; a
manifest is evidence of creation, not permission to remove unrelated dependencies.

## Reports, errors and permissions

Each resource reports `would_delete`, `deleted`, `absent`, `not_created`,
`skipped` or `retained`, with its recorded identity and a reason where needed.
An incomplete write-enabled recovery emits `CleanupWarning`; the CLI returns
exit status 1. Dry runs return status 0 when inspection completes, so read the
resource actions rather than treating that status as completed cleanup.

Permission, identity and service failures stop recovery and retain its report
on the exception's `.evidence`. Earlier successful deletions remain recorded so
the command can be rerun. A manifest-write failure during normal cleanup emits
a warning and preserves the original test error; owned AWS cleanup still runs.
If a final status could not be saved, the next recovery rechecks the live resource
instead of assuming the old status is current.

The [recovery policy template](../iam/probe-recovery-policy.example.json) grants
the identity/dependency reads and cleanup actions. Replace `REGION`, `ACCOUNT_ID`
and the partition before using it. Function and role actions use the probe name
prefix; group deletion requires the probe tag. List and EC2 describe operations
require broad read scope. The cross-region role scan needs `lambda:ListFunctions`
and verified credentials in every enabled region; restricted visibility retains
the role. This policy does not grant probe creation or network changes.
