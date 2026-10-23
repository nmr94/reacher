"""A temporary Lambda execution role, retained until VPC ENI cleanup is safe."""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from typing import Any

from botocore.exceptions import ClientError

from .errors import ProbeError, ProbeTimeoutError, _creation_uncertain

_POLICY_NAME = "VpcNetworkInterfaces"
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSubnets",
                "ec2:DeleteNetworkInterface",
                "ec2:AssignPrivateIpAddresses",
                "ec2:UnassignPrivateIpAddresses",
            ],
            "Resource": "*",
        }
    ],
}


class TemporaryProbeRole:
    """Manage only the unique role and inline policy created by this probe."""

    def __init__(
        self,
        iam: Any,
        ec2: Any,
        *,
        account_id: str,
        partition: str,
        timeout: float,
        poll_interval: float,
    ) -> None:
        self.iam = iam
        self.ec2 = ec2
        self.account_id = account_id
        self.partition = partition
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.created = False
        self.manifest = None
        self.evidence: dict[str, Any] = {"cleanup": "not_created"}

    def create(self, name: str, *, deadline: float) -> str:
        arn = f"arn:{self.partition}:iam::{self.account_id}:role/{name}"
        self.evidence.update(role_name=name, role_arn=arn, cleanup="not_created")
        if self.manifest is not None:
            self.manifest.before_create("role", {"role_name": name, "role_arn": arn})
        self.evidence["cleanup"] = "creation_unconfirmed"
        try:
            response = self.iam.create_role(
                RoleName=name,
                AssumeRolePolicyDocument=json.dumps(_TRUST),
                Description="Temporary AWS network assertions Lambda execution role",
            )
        except ClientError as error:
            if not _creation_uncertain(error):
                self.evidence["cleanup"] = "not_created"
            raise
        role = response.get("Role") if isinstance(response, dict) else None
        if not isinstance(role, dict) or role.get("Arn") != arn or role.get("RoleName") != name:
            raise ProbeError("CreateRole returned an unexpected role identity", self.evidence)
        self.created = True
        self.evidence["cleanup"] = "pending"
        if self.manifest is not None:
            role_id = role.get("RoleId")
            self.manifest.confirm(
                "role", {"role_id": role_id}, confirmed=isinstance(role_id, str) and bool(role_id)
            )
        while True:
            try:
                self.iam.put_role_policy(
                    RoleName=name, PolicyName=_POLICY_NAME, PolicyDocument=json.dumps(_POLICY)
                )
                break
            except ClientError as error:
                if error.response["Error"]["Code"] != "NoSuchEntity":
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProbeTimeoutError(
                        "IAM role policy propagation timed out", self.evidence
                    ) from error
                time.sleep(min(self.poll_interval, remaining))
        return arn

    def cleanup(
        self,
        subnet_id: str,
        groups: Sequence[str],
        *,
        wait_for_enis: bool,
    ) -> None:
        """Keep ENI permissions until no matching Lambda interfaces remain.

        Shared interfaces can outlive this function. Never delete them or revoke
        the role's policy just because a local deadline expires.
        """
        deadline = time.monotonic() + self.timeout
        if wait_for_enis:
            while True:
                interfaces = self._interfaces(subnet_id, groups)
                self.evidence["remaining_eni_ids"] = interfaces
                if not interfaces:
                    break
                self._wait(deadline, "Lambda VPC ENIs still exist")
        name = self.evidence["role_name"]
        while True:
            try:
                # Recheck our policy after a role deletion conflict: a previously
                # invisible PutRolePolicy can become visible during cleanup.
                self.iam.delete_role_policy(RoleName=name, PolicyName=_POLICY_NAME)
            except ClientError as error:
                if error.response["Error"]["Code"] != "NoSuchEntity":
                    raise
            try:
                self.iam.delete_role(RoleName=name)
                self.evidence["cleanup"] = "deleted"
                return
            except ClientError as error:
                code = error.response["Error"]["Code"]
                if code == "NoSuchEntity":
                    self.evidence["cleanup"] = "deleted"
                    return
                if code not in {"DeleteConflict", "ConcurrentModification"}:
                    raise
                self._wait(deadline, f"IAM role deletion is still pending: {code}")

    def _wait(self, deadline: float, reason: str) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"{reason}; role_cleanup_timeout expired")
        time.sleep(min(self.poll_interval, remaining))

    def _interfaces(self, subnet_id: str, groups: Sequence[str]) -> list[str]:
        interfaces = []
        pages = self.ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[
                {"Name": "subnet-id", "Values": [subnet_id]},
                {"Name": "group-id", "Values": list(groups)},
                {"Name": "interface-type", "Values": ["lambda"]},
            ]
        )
        for page in pages:
            items = page.get("NetworkInterfaces")
            if not isinstance(items, list):
                raise ValueError("ENI cleanup response is missing NetworkInterfaces")
            for item in items:
                if (
                    not isinstance(item, dict)
                    or not isinstance(item.get("Groups"), list)
                    or not item["Groups"]
                ):
                    raise ValueError("ENI cleanup response is missing security groups")
                group_ids = []
                for group in item["Groups"]:
                    if (
                        not isinstance(group, dict)
                        or not isinstance(group.get("GroupId"), str)
                        or not group["GroupId"]
                    ):
                        raise ValueError("ENI cleanup response has an invalid security group")
                    group_ids.append(group["GroupId"])
                # EC2's group-id filter is OR. Lambda shares by the exact set.
                if set(group_ids) != set(groups):
                    continue
                eni_id = item.get("NetworkInterfaceId")
                if not isinstance(eni_id, str) or not eni_id:
                    raise ValueError("ENI cleanup response is missing NetworkInterfaceId")
                interfaces.append(eni_id)
        return interfaces
