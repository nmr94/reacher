"""Create a probe-owned security group and wait for its dependencies on deletion."""

from __future__ import annotations

import re
import time
from typing import Any

from botocore.exceptions import ClientError

from .accounts import validate_account_id
from .errors import ProbeError, ProbeTimeoutError, _creation_uncertain


class TemporaryProbeSecurityGroup:
    """Use AWS's initial no-ingress/default-egress rules; change no existing group."""

    def __init__(self, ec2: Any, *, account_id: str, timeout: float, poll_interval: float) -> None:
        self.ec2 = ec2
        self.account_id = account_id
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.created = False
        self.manifest = None
        self.visible = False
        self.evidence: dict[str, Any] = {"cleanup": "not_created"}

    def create(self, name: str, subnet_id: str, *, ready_timeout: float) -> str:
        self.evidence.update(group_name=name, subnet_id=subnet_id)
        subnets = []
        for page in self.ec2.get_paginator("describe_subnets").paginate(SubnetIds=[subnet_id]):
            items = page.get("Subnets")
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                raise ProbeError("Subnet discovery is missing a Subnets list", self.evidence)
            subnets.extend(items)
        if len(subnets) != 1 or subnets[0].get("SubnetId") != subnet_id:
            raise ProbeError("Subnet discovery did not return the selected subnet", self.evidence)
        subnet = subnets[0]
        vpc = subnet.get("VpcId")
        if not isinstance(vpc, str) or re.fullmatch(r"vpc-[a-zA-Z0-9]+", vpc) is None:
            raise ProbeError("Subnet discovery is missing a valid VpcId", self.evidence)
        try:
            owner = validate_account_id(subnet.get("OwnerId"))
        except ValueError as error:
            raise ProbeError(
                "Subnet discovery is missing a valid OwnerId", self.evidence
            ) from error
        # A shared subnet can belong to another account. The new group belongs
        # to the verified caller, not necessarily the subnet/VPC owner.
        if subnet.get("State") != "available":
            raise ProbeError("Selected subnet is not in the available state", self.evidence)
        self.evidence.update(vpc_id=vpc, subnet_owner_id=owner, cleanup="not_created")
        if self.manifest is not None:
            self.manifest.before_create(
                "security_group",
                {
                    "group_name": name,
                    "vpc_id": vpc,
                    "subnet_id": subnet_id,
                },
            )
        self.evidence["cleanup"] = "creation_unconfirmed"
        try:
            response = self.ec2.create_security_group(
                GroupName=name,
                Description="Temporary AWS network assertions Lambda probe security group",
                VpcId=vpc,
                TagSpecifications=[
                    {
                        "ResourceType": "security-group",
                        "Tags": [{"Key": "aws-network-asserts:probe", "Value": name}],
                    }
                ],
            )
        except ClientError as error:
            if not _creation_uncertain(error):
                self.evidence["cleanup"] = "not_created"
            raise
        group_id = response.get("GroupId")
        if not isinstance(group_id, str) or re.fullmatch(r"sg-[a-zA-Z0-9]+", group_id) is None:
            raise ProbeError("CreateSecurityGroup returned no valid GroupId", self.evidence)
        self.created = True
        self.evidence.update(group_id=group_id, cleanup="pending")
        if self.manifest is not None:
            self.manifest.confirm("security_group", {"group_id": group_id})
        deadline = time.monotonic() + ready_timeout
        while True:
            try:
                groups = []
                pages = self.ec2.get_paginator("describe_security_groups").paginate(
                    GroupIds=[group_id]
                )
                for page in pages:
                    items = page.get("SecurityGroups")
                    if not isinstance(items, list) or any(
                        not isinstance(item, dict) for item in items
                    ):
                        raise ProbeError("Group discovery is missing SecurityGroups", self.evidence)
                    groups.extend(items)
                if groups:
                    if (
                        len(groups) != 1
                        or any(
                            groups[0].get(key) != expected
                            for key, expected in (
                                ("GroupId", group_id),
                                ("VpcId", vpc),
                                ("OwnerId", self.account_id),
                            )
                        )
                        or ("GroupName" in groups[0] and groups[0]["GroupName"] != name)
                    ):
                        self.created = False
                        self.evidence.update(cleanup="creation_unconfirmed", reported_groups=groups)
                        raise ProbeError(
                            "Group discovery returned an unexpected identity", self.evidence
                        )
                    self.visible = True
                    return group_id
            except ClientError as error:
                if error.response["Error"]["Code"] != "InvalidGroup.NotFound":
                    raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeTimeoutError("Security group propagation timed out", self.evidence)
            time.sleep(min(self.poll_interval, remaining))

    def cleanup(self) -> None:
        deadline = time.monotonic() + self.timeout
        group_id = self.evidence["group_id"]
        while True:
            try:
                response = self.ec2.delete_security_group(GroupId=group_id)
                if ("Return" in response and response["Return"] is not True) or (
                    response.get("GroupId", group_id) != group_id
                ):
                    raise ProbeError("DeleteSecurityGroup did not confirm deletion", self.evidence)
                self.evidence["cleanup"] = "deleted"
                return
            except ClientError as error:
                code = error.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound" and self.visible:
                    self.evidence["cleanup"] = "deleted"
                    return
                if code not in {"DependencyViolation", "InvalidGroup.NotFound"}:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"Security group deletion is pending ({code}); "
                        "security_group_cleanup_timeout expired"
                    ) from error
                time.sleep(min(self.poll_interval, remaining))
