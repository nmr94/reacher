"""Implementation of durable records and explicit Lambda probe recovery."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import tempfile
import time
import warnings
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from botocore.exceptions import ClientError

from .accounts import validate_account_id
from .errors import CleanupWarning, ProbeError, _attach_evidence
from .probe_role import _POLICY, _POLICY_NAME, _TRUST, TemporaryProbeRole
from .probe_security_group import TemporaryProbeSecurityGroup

_PREFIX = "aws-network-asserts-"
_TERMINAL = {"deleted", "not_created"}
_STATES = _TERMINAL | {"creating", "pending", "retained", "failed", "creation_unconfirmed"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _manifest_path(value):
    if not isinstance(value, (str, os.PathLike)) or not os.fspath(value):
        raise ValueError("cleanup_manifest must be a nonempty filesystem path")
    path = Path(value).absolute()
    if path.is_symlink():
        raise ValueError("A cleanup manifest cannot be a symbolic link")
    return path


@contextmanager
def _lock(path):
    """An OS lock releases on process exit, including a hard interruption."""
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path) + ".lock", flags, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            if not os.fstat(descriptor).st_size:
                os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


class _ProbeManifest:
    """One private file per deployment; never adopt an earlier run's file."""

    def __init__(self, path, data):
        self.path = path
        self.data = data

    @classmethod
    @contextmanager
    def new(cls, path, *, name, account_id, region, partition, subnet_id, groups):
        path = _manifest_path(path)
        validate_account_id(account_id)
        with _lock(path):
            # Reserving the name prevents overwriting even a completed run.
            descriptor = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600
            )
            os.close(descriptor)
            manifest = cls(
                path,
                {
                    "schema_version": 1,
                    "run_id": name.removeprefix(_PREFIX),
                    "function_name": name,
                    "account_id": account_id,
                    "region": region,
                    "partition": partition,
                    "subnet_id": subnet_id,
                    "security_group_ids": list(groups),
                    "created_at": _now(),
                    "resources": {},
                    "complete": False,
                },
            )
            manifest.write()
            yield manifest

    def write(self):
        self.data["updated_at"] = _now()
        self.data["complete"] = bool(self.data["resources"]) and all(
            resource["cleanup"] in _TERMINAL for resource in self.data["resources"].values()
        )
        descriptor, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(self.data, stream, indent=2, sort_keys=True, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name != "nt":
                parent = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def before_create(self, resource, identity):
        self.data["resources"][resource] = {
            "identity": dict(identity),
            "confirmed": False,
            "cleanup": "creating",
        }
        self.write()

    def confirm(self, resource, identity, *, confirmed=True):
        record = self.data["resources"][resource]
        record["identity"].update(identity)
        record.update(confirmed=confirmed, cleanup="pending")
        self.write()

    def status(self, resource, evidence):
        if resource in self.data["resources"]:
            self.data["resources"][resource]["cleanup"] = evidence["cleanup"]
            if evidence["cleanup"] == "creation_unconfirmed":
                self.data["resources"][resource]["confirmed"] = False
            if "cleanup_error" in evidence:
                self.data["resources"][resource]["cleanup_error"] = evidence["cleanup_error"]
            self.write()


def _load(path):
    with path.open(encoding="utf-8") as stream:
        data = json.load(stream)
    if (
        not isinstance(data, dict)
        or type(data.get("schema_version")) is not int
        or data["schema_version"] != 1
    ):
        raise ValueError("Unsupported cleanup manifest schema")
    validate_account_id(data.get("account_id"))
    run = data.get("run_id")
    if (
        not isinstance(run, str)
        or re.fullmatch(r"[0-9a-f]{32}", run) is None
        or data.get("function_name") != _PREFIX + run
        or not isinstance(data.get("region"), str)
        or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)+", data["region"]) is None
        or not isinstance(data.get("partition"), str)
        or not data["partition"]
        or not isinstance(data.get("subnet_id"), str)
        or re.fullmatch(r"subnet-[A-Za-z0-9]+", data["subnet_id"]) is None
        or not isinstance(data.get("security_group_ids"), list)
    ):
        raise ValueError("Cleanup manifest has an invalid run or source binding")
    if data["security_group_ids"]:
        _groups(data["security_group_ids"])
    resources = data.get("resources")
    if not isinstance(resources, dict) or resources.keys() - {"function", "security_group", "role"}:
        raise ValueError("Cleanup manifest has invalid resources")
    for item in resources.values():
        if (
            not isinstance(item, dict)
            or type(item.get("confirmed")) is not bool
            or not isinstance(item.get("cleanup"), str)
            or item["cleanup"] not in _STATES
            or not isinstance(item.get("identity"), dict)
        ):
            raise ValueError("Cleanup manifest has an invalid resource record")
    return data


def _groups(value):
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 5
        or any(
            not isinstance(item, str) or re.fullmatch(r"sg-[A-Za-z0-9]+", item) is None
            for item in value
        )
        or len(set(value)) != len(value)
    ):
        raise ValueError("Recovery requires one to five distinct recorded security groups")
    return sorted(value)


def _function_identity(data, identity):
    name = data["function_name"]
    arn = f"arn:{data['partition']}:lambda:{data['region']}:{data['account_id']}:function:{name}"
    if (
        identity.get("function_name") != name
        or identity.get("function_arn") != arn
        or not isinstance(identity.get("revision_id"), str)
        or not identity["revision_id"]
        or identity.get("subnet_id") != data["subnet_id"]
        or not isinstance(identity.get("execution_role_arn"), str)
        or not identity["execution_role_arn"].startswith(
            f"arn:{data['partition']}:iam::{data['account_id']}:role/"
        )
    ):
        raise ValueError("Recorded Lambda identity is incomplete or disagrees with this run")
    _groups(identity.get("security_group_ids"))


def _verify_function(client, data, identity):
    _function_identity(data, identity)
    actual = client.get_function_configuration(FunctionName=identity["function_name"])
    vpc = actual.get("VpcConfig", {})
    if (
        any(
            actual.get(key) != identity[field]
            for key, field in (
                ("FunctionName", "function_name"),
                ("FunctionArn", "function_arn"),
                ("RevisionId", "revision_id"),
                ("Role", "execution_role_arn"),
            )
        )
        or not isinstance(vpc, dict)
        or vpc.get("SubnetIds") != [identity["subnet_id"]]
        or _groups(vpc.get("SecurityGroupIds")) != _groups(identity["security_group_ids"])
    ):
        raise ProbeError(
            "Live Lambda identity/configuration differs from the recorded creation", {}
        )


def _group_identity(data, identity):
    name = data["function_name"]
    if (
        identity.get("group_name") != name
        or not isinstance(identity.get("group_id"), str)
        or re.fullmatch(r"sg-[A-Za-z0-9]+", identity["group_id"]) is None
        or not isinstance(identity.get("vpc_id"), str)
        or re.fullmatch(r"vpc-[A-Za-z0-9]+", identity["vpc_id"]) is None
    ):
        raise ValueError("Recorded security group identity is incomplete or has another run's name")


def _verify_group(client, data, identity):
    _group_identity(data, identity)
    name = data["function_name"]
    groups = []
    for page in client.get_paginator("describe_security_groups").paginate(
        GroupIds=[identity["group_id"]]
    ):
        items = page.get("SecurityGroups")
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise ProbeError("Security group recovery discovery is incomplete", {})
        groups.extend(items)
    if len(groups) != 1:
        raise ProbeError("Security group recovery needs exactly one matching group", {})
    actual = groups[0]
    tags = actual.get("Tags")
    if (
        any(
            actual.get(key) != expected
            for key, expected in (
                ("GroupId", identity["group_id"]),
                ("GroupName", name),
                ("VpcId", identity["vpc_id"]),
                ("OwnerId", data["account_id"]),
            )
        )
        or not isinstance(tags, list)
        or any(not isinstance(tag, dict) for tag in tags)
        or [tag.get("Value") for tag in tags if tag.get("Key") == "aws-network-asserts:probe"]
        != [name]
    ):
        raise ProbeError("Live security group ownership or run tag differs from its creation", {})


def _role_identity(data, identity):
    name = data["function_name"]
    arn = f"arn:{data['partition']}:iam::{data['account_id']}:role/{name}"
    if (
        identity.get("role_name") != name
        or identity.get("role_arn") != arn
        or not isinstance(identity.get("role_id"), str)
        or not identity["role_id"]
    ):
        raise ValueError("Recorded IAM role identity is incomplete or has another run's name")


def _verify_role(client, data, identity):
    _role_identity(data, identity)
    response = client.get_role(RoleName=identity["role_name"])
    actual = response.get("Role")
    if not isinstance(actual, dict) or any(
        actual.get(key) != identity[field]
        for key, field in (
            ("RoleName", "role_name"),
            ("Arn", "role_arn"),
            ("RoleId", "role_id"),
        )
    ):
        raise ProbeError("Live IAM role identity differs from the recorded creation", {})
    return actual


def _preflight(data):
    validators = {
        "function": _function_identity,
        "security_group": _group_identity,
        "role": _role_identity,
    }
    records = data["resources"]
    for resource, record in records.items():
        if record["confirmed"] and record["cleanup"] not in _TERMINAL:
            validators[resource](data, record["identity"])
    function = records.get("function")
    if function is not None and function["confirmed"]:
        identity = function["identity"]
        group = records.get("security_group")
        expected = (
            [group["identity"].get("group_id")] if group is not None else data["security_group_ids"]
        )
        if _groups(identity["security_group_ids"]) != _groups(expected):
            raise ValueError("Recorded function security groups disagree with this run")
        role = records.get("role")
        if role is not None and identity["execution_role_arn"] != role["identity"].get("role_arn"):
            raise ValueError("Recorded function and temporary role disagree")


def _items(client, operation, key, *, deadline, **request):
    pages = iter(client.get_paginator(operation).paginate(**request))
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError("Role dependency discovery exceeded cleanup_timeout")
        try:
            page = next(pages)
        except StopIteration:
            return
        if operation != "list_functions" and (
            type(page.get("IsTruncated")) is not bool
            or (page["IsTruncated"] and not page.get("Marker"))
        ):
            raise ProbeError(f"Recovery {operation} has incomplete pagination evidence", {})
        for token in ("Marker", "NextMarker"):
            if token in page and (not isinstance(page[token], str) or not page[token]):
                raise ProbeError(f"Recovery {operation} has an invalid continuation token", {})
        items = page.get(key)
        if not isinstance(items, list):
            raise ProbeError(f"Recovery {operation} is missing {key}", {})
        yield from items


def _policy(document):
    if isinstance(document, str):
        document = json.loads(unquote(document))
    if not isinstance(document, dict):
        raise ProbeError("Recovery received an invalid IAM policy", {})
    return document


def _role_dependencies(builder, iam, actual, identity, *, deadline, planned_function=None):
    """Refuse repurposed roles and any incomplete current Lambda consumer scan."""
    if (
        actual.get("PermissionsBoundary")
        or _policy(actual.get("AssumeRolePolicyDocument")) != _TRUST
    ):
        raise ProbeError("Temporary role trust or boundary changed; retain it for review", {})
    name = identity["role_name"]
    policies = list(
        _items(iam, "list_role_policies", "PolicyNames", RoleName=name, deadline=deadline)
    )
    if len(set(policies)) != len(policies) or any(policy != _POLICY_NAME for policy in policies):
        raise ProbeError("Temporary role has other inline policies; retain it for review", {})
    if policies:
        document = iam.get_role_policy(RoleName=name, PolicyName=_POLICY_NAME)
        if (
            document.get("RoleName") != name
            or document.get("PolicyName") != _POLICY_NAME
            or _policy(document.get("PolicyDocument")) != _POLICY
        ):
            raise ProbeError("Temporary role's ENI policy changed; retain it for review", {})
    if list(
        _items(
            iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name, deadline=deadline
        )
    ) or list(
        _items(
            iam,
            "list_instance_profiles_for_role",
            "InstanceProfiles",
            RoleName=name,
            deadline=deadline,
        )
    ):
        raise ProbeError("Temporary role has additional dependencies; retain it for review", {})
    response = builder.ec2.describe_regions(AllRegions=False)
    regions = response.get("Regions")
    if (
        not isinstance(regions, list)
        or not regions
        or any(not isinstance(item, dict) for item in regions)
    ):
        raise ProbeError("Cannot establish the account's enabled regions for role recovery", {})
    names = []
    for region in regions:
        name = region.get("RegionName")
        if (
            not isinstance(name, str)
            or not name
            or region.get("OptInStatus") not in {"opt-in-not-required", "opted-in"}
        ):
            raise ProbeError("Enabled region discovery is incomplete", {})
        names.append(name)
    if len(set(names)) != len(names) or builder.region_name not in names:
        raise ProbeError("Enabled region discovery disagrees with the original run", {})
    for region in names:
        if time.monotonic() >= deadline:
            raise TimeoutError("Role dependency discovery exceeded cleanup_timeout")
        if builder.clients.session.get_partition_for_region(
            region
        ) != builder.clients.session.get_partition_for_region(builder.region_name):
            raise ProbeError("Enabled region belongs to a different partition", {})
        client = builder.in_region(region)._live_client("lambda")
        for function in _items(
            client, "list_functions", "Functions", FunctionVersion="ALL", deadline=deadline
        ):
            if (
                not isinstance(function, dict)
                or not isinstance(function.get("Role"), str)
                or not function["Role"]
            ):
                raise ProbeError("Lambda consumer discovery is incomplete", {})
            if function["Role"] == identity["role_arn"]:
                if planned_function and function.get("FunctionArn") == planned_function:
                    continue
                raise ProbeError(
                    "Another Lambda function uses the temporary role",
                    {"consumer_region": region, "consumer_function": function.get("FunctionName")},
                )
    if actual.get("RoleLastUsed", {}).get("Region", builder.region_name) != builder.region_name:
        raise ProbeError("Role was used in another region; its ENI cleanup needs manual review", {})


def recover_probes(builder, manifest_path, *, allow_write=False, cleanup_timeout=1200.0):
    """Inspect a recorded run, or explicitly delete its verified temporary resources.

    Dry runs perform identity reads but do not delete or alter the manifest.
    Unconfirmed creations are reported and never adopted by name.
    """
    if type(allow_write) is not bool:
        raise ValueError("allow_write must be a boolean")
    if (
        isinstance(cleanup_timeout, bool)
        or not isinstance(cleanup_timeout, (int, float))
        or not math.isfinite(cleanup_timeout)
        or cleanup_timeout <= 0
    ):
        raise ValueError("cleanup_timeout must be positive and finite")
    path = _manifest_path(manifest_path)
    with _lock(path):
        data = _load(path)
        if builder.account_id != data["account_id"] or builder.region_name != data["region"]:
            raise ValueError("Recovery builder account/region must match the manifest")
        partition = builder.clients.session.get_partition_for_region(builder.region_name)
        if partition != data["partition"]:
            raise ValueError("Recovery partition does not match the manifest")
        _preflight(data)
        report = {
            "manifest_path": str(path),
            "run_id": data["run_id"],
            "account_id": data["account_id"],
            "region": data["region"],
            "dry_run": not allow_write,
            "resources": {},
        }
        journal = _ProbeManifest(path, data)
        records = data["resources"]
        function = records.get("function")
        function_safe = function is None or function["cleanup"] in _TERMINAL
        group_safe = (
            "security_group" not in records or records["security_group"]["cleanup"] in _TERMINAL
        )
        function_attempted = function is not None and function["cleanup"] != "not_created"
        deadline = time.monotonic() + cleanup_timeout
        try:
            for resource in ("function", "security_group", "role"):
                record = records.get(resource)
                if record is None:
                    continue
                result = report["resources"][resource] = {
                    "action": "checking",
                    "identity": dict(record["identity"]),
                }
                if record["cleanup"] in _TERMINAL:
                    result["action"] = record["cleanup"]
                    continue
                if not record["confirmed"]:
                    result.update(
                        action="skipped",
                        reason="Creation identity was not confirmed; inspect manually",
                    )
                    continue
                if resource != "function" and not function_safe:
                    result.update(action="retained", reason="Function cleanup is unconfirmed")
                    continue
                if resource == "role" and function_attempted and not group_safe:
                    result.update(action="retained", reason="Security group cleanup is unconfirmed")
                    continue
                if time.monotonic() >= deadline:
                    result.update(action="retained", reason="cleanup_timeout exhausted")
                    continue
                identity = record["identity"]
                service = {"function": "lambda", "security_group": "ec2", "role": "iam"}[resource]
                client = builder._live_client(service)
                verify = {
                    "function": _verify_function,
                    "security_group": _verify_group,
                    "role": _verify_role,
                }[resource]
                try:
                    actual = verify(client, data, identity)
                except ClientError as error:
                    absent = {
                        "function": "ResourceNotFoundException",
                        "security_group": "InvalidGroup.NotFound",
                        "role": "NoSuchEntity",
                    }[resource]
                    if error.response.get("Error", {}).get("Code") != absent:
                        raise
                    result["action"] = "absent"
                    if allow_write:
                        record["cleanup"] = "deleted"
                        journal.write()
                    if resource == "function":
                        function_safe = True
                    if resource == "security_group":
                        group_safe = True
                    continue
                if resource == "role":
                    try:
                        planned = (
                            function["identity"].get("function_arn")
                            if not allow_write
                            and function is not None
                            and report["resources"]["function"].get("action") == "would_delete"
                            else None
                        )
                        _role_dependencies(
                            builder,
                            client,
                            actual,
                            identity,
                            deadline=deadline,
                            planned_function=planned,
                        )
                    except Exception as error:
                        result.update(
                            action="retained", reason=str(error), error_type=type(error).__name__
                        )
                        if isinstance(getattr(error, "evidence", None), dict):
                            result["dependency_evidence"] = error.evidence
                        continue
                if not allow_write:
                    result["action"] = "would_delete"
                    if resource == "function":
                        function_safe = True
                    if resource == "security_group":
                        group_safe = True
                    continue
                if resource == "function":
                    result["action"] = "deleting"
                    try:
                        client.delete_function(FunctionName=identity["function_name"])
                    except ClientError as error:
                        if (
                            error.response.get("Error", {}).get("Code")
                            != "ResourceNotFoundException"
                        ):
                            raise
                    function_safe = True
                elif resource == "security_group":
                    group = TemporaryProbeSecurityGroup(
                        client,
                        account_id=data["account_id"],
                        timeout=max(deadline - time.monotonic(), 0.001),
                        poll_interval=builder.poll_interval,
                    )
                    group.created = group.visible = True
                    group.evidence = {**identity, "cleanup": "pending"}
                    group.cleanup()
                    group_safe = True
                else:
                    role = TemporaryProbeRole(
                        client,
                        builder.ec2,
                        account_id=data["account_id"],
                        partition=data["partition"],
                        timeout=max(deadline - time.monotonic(), 0.001),
                        poll_interval=builder.poll_interval,
                    )
                    role.created = True
                    role.evidence = {**identity, "cleanup": "pending"}
                    groups = (
                        function["identity"].get("security_group_ids")
                        if function is not None
                        else data["security_group_ids"]
                    )
                    role.cleanup(
                        data["subnet_id"],
                        _groups(groups) if function_attempted else groups,
                        wait_for_enis=function_attempted and "security_group" not in records,
                    )
                result["action"] = "deleted"
                record["cleanup"] = "deleted"
                journal.write()
        except BaseException as error:
            reason = str(error) or type(error).__name__
            if result["action"] in {"deleted", "absent"}:
                result["manifest_error"] = reason
            else:
                result.update(action="retained", reason=reason)
                record["cleanup"] = "retained"
                record["cleanup_error"] = reason
            if allow_write:
                try:
                    journal.write()
                except BaseException as persistence_error:
                    report["manifest_error"] = str(persistence_error)
            for remaining, pending in records.items():
                report["resources"].setdefault(
                    remaining,
                    {
                        "action": "retained",
                        "reason": "An earlier cleanup step failed",
                        "identity": dict(pending["identity"]),
                    },
                )
            _attach_evidence(error, report)
            if allow_write:
                try:
                    warnings.warn(
                        "Probe recovery stopped; inspect retained resources in the error evidence",
                        CleanupWarning,
                        stacklevel=2,
                    )
                except CleanupWarning:
                    pass
            raise
        report["complete"] = all(
            item["action"] in {"deleted", "absent", "not_created"}
            for item in report["resources"].values()
        )
        if allow_write and not report["complete"]:
            warnings.warn(
                "Probe recovery retained unconfirmed resources; inspect the recovery report",
                CleanupWarning,
                stacklevel=2,
            )
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect or recover a recorded Lambda probe run")
    parser.add_argument("manifest", help="Cleanup manifest from one Lambda deployment")
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--endpoint-url")
    parser.add_argument(
        "--allow-writes",
        action="store_true",
        help="Delete verified resources; otherwise inspect only",
    )
    parser.add_argument("--cleanup-timeout", type=float, default=1200.0)
    args = parser.parse_args(argv)
    from .builder import RuleBuilder

    builder = RuleBuilder(
        profile_name=args.profile,
        account_id=args.account,
        region_name=args.region,
        endpoint_url=args.endpoint_url,
        config_mode="off",
    )
    report = recover_probes(
        builder, args.manifest, allow_write=args.allow_writes, cleanup_timeout=args.cleanup_timeout
    )
    print(json.dumps(report, indent=2))
    return 0 if report["complete"] or report["dry_run"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
