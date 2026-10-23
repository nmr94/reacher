"""Temporary VPC Lambda lifecycle for explicit, observed TCP checks."""

from __future__ import annotations

import io
import json
import logging
import math
import os
import re
import sys
import time
import warnings
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from importlib.resources import files
from ipaddress import IPv4Address, ip_address
from typing import Any
from uuid import uuid4
from zipfile import ZIP_DEFLATED, ZipFile

from botocore.exceptions import ClientError

from ._recovery import _manifest_path, _ProbeManifest
from .errors import (
    CleanupWarning,
    ProbeError,
    ProbeTimeoutError,
    _attach_evidence,
    _creation_uncertain,
)
from .probe_role import TemporaryProbeRole
from .probe_security_group import TemporaryProbeSecurityGroup
from .result import CheckResult


def _package(*, application: bool = False) -> bytes:
    archive = io.BytesIO()
    modules = ["probe_handler"]
    if application:
        modules.append("application_handler")
    with ZipFile(archive, "w", ZIP_DEFLATED) as package:
        for module in modules:
            source = files("aws_network_asserts").joinpath(f"_{module}.py").read_bytes()
            package.writestr(f"{module}.py", source)
    return archive.getvalue()


@dataclass(frozen=True)
class LambdaProbe:
    """Validated probe settings; construction performs no AWS calls."""

    host: str
    port: int
    execution_role_arn: str | None
    security_group_ids: Sequence[str] | None
    connect_timeout: float
    ready_timeout: float
    address_family: str = "ipv4"
    cleanup_manifest: str | os.PathLike[str] | None = None
    account_id: str | None = None

    def __post_init__(self) -> None:
        if self.cleanup_manifest is not None:
            _manifest_path(self.cleanup_manifest)
        if not isinstance(self.address_family, str) or self.address_family not in {
            "ipv4",
            "ipv6",
            "dual",
        }:
            raise ValueError("address_family must be ipv4, ipv6, or dual")
        if not isinstance(self.host, str) or len(self.host) > 253:
            raise ValueError("host must be an IP address or DNS hostname")
        try:
            address = ip_address(self.host)
            if "%" in self.host or getattr(address, "ipv4_mapped", None) is not None:
                raise ValueError("Scoped and IPv4-mapped IPv6 addresses are unsupported")
        except ValueError:
            labels = self.host.removesuffix(".").split(".")
            if all(char in "0123456789." for char in self.host) or any(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) is None
                for label in labels
            ):
                raise ValueError(
                    "host must be an IP address or DNS hostname, without a CIDR or scope"
                ) from None
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise ValueError("port must be an integer between 1 and 65535")
        for label, value, maximum in (
            ("connect_timeout", self.connect_timeout, 10),
            ("ready_timeout", self.ready_timeout, None),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
                or (maximum is not None and value > maximum)
            ):
                raise ValueError(
                    f"{label} must be positive and finite" + (" and <= 10" if maximum else "")
                )
        if self.security_group_ids is None:
            return  # The public builder validated the explicit automatic-group mode.
        if (
            not isinstance(self.security_group_ids, Sequence)
            or isinstance(self.security_group_ids, str)
            or not 1 <= len(self.security_group_ids) <= 5
            or any(
                not isinstance(group, str) or re.fullmatch(r"sg-[a-zA-Z0-9]+", group) is None
                for group in self.security_group_ids
            )
            or len(set(self.security_group_ids)) != len(self.security_group_ids)
        ):
            raise ValueError("security_group_ids must contain 1 to 5 distinct security group IDs")
        object.__setattr__(self, "security_group_ids", tuple(self.security_group_ids))

    @contextmanager
    def deployed(
        self,
        client: Any,
        subnet_id: str,
        *,
        poll_interval: float,
        role: TemporaryProbeRole | None = None,
        security_group: TemporaryProbeSecurityGroup | None = None,
        application: bool = False,
    ) -> Iterator[dict[str, Any]]:
        name = f"aws-network-asserts-{uuid4().hex}"
        persistence = nullcontext(None)
        if self.cleanup_manifest is not None:
            partition = (
                role.partition if role is not None else self.execution_role_arn.split(":")[1]
            )
            persistence = _ProbeManifest.new(
                self.cleanup_manifest,
                name=name,
                account_id=self.account_id,
                region=client.meta.region_name,
                partition=partition,
                subnet_id=subnet_id,
                groups=self.security_group_ids or (),
            )
        with persistence as manifest:
            with self._deployment(
                client,
                subnet_id,
                poll_interval=poll_interval,
                role=role,
                security_group=security_group,
                application=application,
                name=name,
                manifest=manifest,
            ) as evidence:
                yield evidence

    @contextmanager
    def _deployment(
        self, client, subnet_id, *, poll_interval, role, security_group, application, name, manifest
    ):
        if self.address_family != "ipv4" and not application:
            raise ValueError("IPv6 observations require the protocol session runtime")
        groups = list(self.security_group_ids or ())
        if not groups and security_group is None:
            raise ValueError("Select security groups or explicitly create a temporary group")
        evidence: dict[str, Any] = {
            "method": "lambda_session" if application else "lambda_tcp",
            "function_name": name,
            "region": client.meta.region_name,
            "subnet_id": subnet_id,
            "security_group_ids": groups,
            "execution_role_arn": self.execution_role_arn,
            "host": None if application else self.host,
            "port": None if application else self.port,
            "connect_timeout": self.connect_timeout,
            "cleanup": "not_created",
            "address_family": self.address_family,
        }
        created = False
        creation_uncertain = False
        if role is not None:
            evidence["temporary_role"] = role.evidence
            role.manifest = manifest
        if security_group is not None:
            evidence["temporary_security_group"] = security_group.evidence
            security_group.manifest = manifest
        if manifest is not None:
            evidence["cleanup_manifest"] = str(manifest.path)
            evidence["run_id"] = manifest.data["run_id"]
        try:
            if security_group is not None:
                groups = [security_group.create(name, subnet_id, ready_timeout=self.ready_timeout)]
                evidence["security_group_ids"] = groups
            deadline = time.monotonic() + self.ready_timeout if role is not None else None
            role_arn = (
                self.execution_role_arn if role is None else role.create(name, deadline=deadline)
            )
            evidence["execution_role_arn"] = role_arn
            request = {
                "FunctionName": name,
                "Runtime": "python3.12",
                "Role": role_arn,
                "Handler": "probe_handler.handler",
                "Code": {"ZipFile": _package(application=application)},
                "Timeout": 15,
                "MemorySize": 128,
                "Publish": False,
                "VpcConfig": {
                    "SubnetIds": [subnet_id],
                    "SecurityGroupIds": groups,
                },
            }
            if self.address_family != "ipv4":
                request["VpcConfig"]["Ipv6AllowedForDualStack"] = True
            while True:
                if manifest is not None:
                    manifest.before_create(
                        "function",
                        {
                            "function_name": name,
                            "subnet_id": subnet_id,
                            "security_group_ids": groups,
                            "execution_role_arn": role_arn,
                        },
                    )
                creation_uncertain = True
                evidence["cleanup"] = "creation_unconfirmed"
                try:
                    created_function = client.create_function(**request)
                    if (
                        not isinstance(created_function, dict)
                        or created_function.get("FunctionName") != name
                    ):
                        self._raise(
                            "CreateFunction returned an unexpected function identity", evidence
                        )
                    if manifest is not None:
                        expected_arn = (
                            f"arn:{manifest.data['partition']}:lambda:{client.meta.region_name}:"
                            f"{self.account_id}:function:{name}"
                        )
                        if created_function.get("FunctionArn", expected_arn) != expected_arn:
                            self._raise(
                                "CreateFunction returned a contradictory function ARN", evidence
                            )
                    created = True
                    evidence["cleanup"] = "pending"
                    if manifest is not None:
                        revision = created_function.get("RevisionId")
                        manifest.confirm(
                            "function",
                            {
                                "function_arn": created_function.get("FunctionArn"),
                                "revision_id": revision,
                            },
                            confirmed=(
                                created_function.get("FunctionArn") == expected_arn
                                and isinstance(revision, str)
                                and bool(revision)
                            ),
                        )
                    break
                except ClientError as error:
                    code = error.response["Error"]["Code"]
                    message = error.response["Error"].get("Message", "").lower()
                    # Retry only explicit role-propagation rejections for our new
                    # role. AccessDenied, malformed VPC settings and server errors
                    # keep their original exception types.
                    creation_uncertain = _creation_uncertain(error)
                    if not creation_uncertain:
                        evidence["cleanup"] = "not_created"
                    propagation = code == "InvalidParameterValueException" and any(
                        text in message
                        for text in (
                            "role defined for the function cannot be assumed by lambda",
                            "provided execution role does not have permissions to call "
                            "createnetworkinterface",
                        )
                    )
                    if role is None or not propagation or creation_uncertain:
                        raise
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self._raise(
                            "Lambda execution role propagation timed out", evidence, timeout=True
                        )
                    time.sleep(min(poll_interval, remaining))
            created = True
            evidence["cleanup"] = "pending"
            deadline = time.monotonic() + self.ready_timeout
            while True:
                configuration = client.get_function_configuration(FunctionName=name)
                evidence["configuration"] = configuration
                state = configuration.get("State")
                if state == "Active":
                    break
                if state != "Pending":
                    self._raise(f"Lambda did not become Active: {configuration!r}", evidence)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._raise("Lambda readiness polling timed out", evidence, timeout=True)
                time.sleep(min(poll_interval, remaining))
            yield evidence
        except BaseException as error:
            # Keep SDK exception types while retaining the name needed to investigate
            # a lost CreateFunction response or a failed invocation/cleanup.
            try:
                previous = getattr(error, "evidence", None)
                if isinstance(previous, dict) and previous is not evidence:
                    # Exclude the batch's deployment back-reference to avoid cycles.
                    evidence["failed_check"] = {
                        key: value for key, value in previous.items() if key != "deployment"
                    }
            except Exception:
                pass
            _attach_evidence(error, evidence)
            raise
        finally:
            preserve_error = sys.exc_info()[0] is not None
            cleanup_interrupt = None
            failures = []

            def save_status(resource, details):
                nonlocal cleanup_interrupt
                if manifest is None:
                    return
                try:
                    manifest.status(resource, details)
                except BaseException as error:
                    reason = str(error) or type(error).__name__
                    evidence.setdefault("manifest_errors", []).append(reason)
                    failures.append(f"manifest={manifest.path}: {reason}")
                    if not isinstance(error, Exception) and cleanup_interrupt is None:
                        cleanup_interrupt = error

            if not created and creation_uncertain:
                failures.append(f"function={name}: creation unconfirmed; inspect before cleanup")
            if created:
                try:
                    client.delete_function(FunctionName=name)
                    evidence["cleanup"] = "deleted"
                except BaseException as error:
                    if (
                        isinstance(error, ClientError)
                        and error.response["Error"]["Code"] == "ResourceNotFoundException"
                    ):
                        # Creation established ownership of this unique name. A
                        # missing function no longer needs its dependencies.
                        evidence["cleanup"] = "deleted"
                    else:
                        reason = str(error) or type(error).__name__
                        evidence["cleanup"] = "failed"
                        evidence["cleanup_error"] = reason
                        failures.append(f"function={name}: {reason}")
                        if not isinstance(error, Exception):
                            cleanup_interrupt = error
            save_status("function", evidence)
            function_uncertain = (created and evidence["cleanup"] != "deleted") or (
                not created and creation_uncertain
            )
            if security_group is not None and security_group.created:
                try:
                    if function_uncertain:
                        raise RuntimeError(
                            "Function deletion is unconfirmed; retaining its security group"
                        )
                    security_group.cleanup()
                except BaseException as error:
                    reason = str(error) or type(error).__name__
                    security_group.evidence.update(cleanup="retained", cleanup_error=reason)
                    failures.append(
                        f"security_group={security_group.evidence['group_id']}: {reason}"
                    )
                    if not isinstance(error, Exception) and cleanup_interrupt is None:
                        cleanup_interrupt = error
            if security_group is not None:
                save_status("security_group", security_group.evidence)
            if role is not None and role.created:
                try:
                    if function_uncertain:
                        raise RuntimeError(
                            "Function deletion is unconfirmed; retaining its execution role"
                        )
                    if (
                        created
                        and security_group is not None
                        and (security_group.evidence["cleanup"] != "deleted")
                    ):
                        raise RuntimeError(
                            "Security group cleanup is unconfirmed; retaining the execution role "
                            "for Lambda ENI cleanup"
                        )
                    role.cleanup(
                        subnet_id,
                        groups,
                        # Successful SG deletion guarantees that no ENI uses it.
                        wait_for_enis=created and security_group is None,
                    )
                except BaseException as error:
                    reason = str(error) or type(error).__name__
                    role.evidence.update(cleanup="retained", cleanup_error=reason)
                    failures.append(f"role={role.evidence['role_name']}: {reason}")
                    if not isinstance(error, Exception) and cleanup_interrupt is None:
                        cleanup_interrupt = error
            if role is not None:
                save_status("role", role.evidence)
            for resource, label, identity in (
                (security_group, "security_group", "group_name"),
                (role, "role", "role_arn"),
            ):
                if (
                    resource is not None
                    and not resource.created
                    and resource.evidence["cleanup"] == "creation_unconfirmed"
                ):
                    failures.append(
                        f"{label}={resource.evidence[identity]}: creation unconfirmed; "
                        "inspect before cleanup"
                    )
            if failures:
                message = f"Lambda probe cleanup in {client.meta.region_name}: " + "; ".join(
                    failures
                )
                try:
                    warnings.warn(message, CleanupWarning, stacklevel=3)
                except CleanupWarning:
                    if not preserve_error and cleanup_interrupt is None:
                        raise
                    logging.getLogger(__name__).warning(message)
            if cleanup_interrupt is not None and not preserve_error:
                _attach_evidence(cleanup_interrupt, evidence)
                raise cleanup_interrupt

    def check(
        self,
        client: Any,
        subnet_id: str,
        *,
        poll_interval: float,
        role: TemporaryProbeRole | None = None,
        security_group: TemporaryProbeSecurityGroup | None = None,
    ) -> CheckResult:
        with self.deployed(
            client, subnet_id, poll_interval=poll_interval, role=role, security_group=security_group
        ) as evidence:
            name = evidence["function_name"]
            response = client.invoke(
                FunctionName=name,
                InvocationType="RequestResponse",
                LogType="None",
                Payload=json.dumps(
                    {"host": self.host, "port": self.port, "connect_timeout": self.connect_timeout}
                ).encode(),
            )
            payload = response.get("Payload")
            if payload is None:
                self._raise("Lambda invocation returned no Payload", evidence)
            try:
                raw = payload.read()
            finally:
                payload.close()
            try:
                observation = json.loads(raw)
            except (ValueError, TypeError) as error:
                raise ProbeError(
                    f"Invalid Lambda JSON response; function={name}", evidence
                ) from error
            evidence["observation"] = observation
            if response.get("StatusCode") != 200 or response.get("FunctionError"):
                self._raise("Lambda execution failed", evidence)
            if (
                not isinstance(observation, dict)
                or not isinstance(observation.get("outcome"), str)
                or observation["outcome"] not in {"connected", "timeout", "refused", "unreachable"}
            ):
                self._raise("Lambda returned an unknown TCP outcome", evidence)
            if not isinstance(observation.get("resolved_ip"), str):
                self._raise("Lambda returned no valid resolved IPv4 address", evidence)
            try:
                IPv4Address(observation["resolved_ip"])
            except (KeyError, ValueError, TypeError):
                self._raise("Lambda returned no valid resolved IPv4 address", evidence)
            try:
                requested_ip = str(IPv4Address(self.host))
            except ValueError:
                requested_ip = None
            if requested_ip is not None and observation["resolved_ip"] != requested_ip:
                self._raise("Lambda returned a different destination address", evidence)
            if type(observation.get("port")) is not int or observation["port"] != self.port:
                self._raise("Lambda returned a different destination port", evidence)
            outcome = observation["outcome"]
            return CheckResult(
                outcome == "connected",
                f"TCP from {subnet_id} to {self.host}:{self.port} "
                f"({observation['resolved_ip']}): {outcome}; function={name}",
                evidence,
            )

    @staticmethod
    def _raise(message: str, evidence: dict[str, Any], *, timeout: bool = False) -> None:
        error_type = ProbeTimeoutError if timeout else ProbeError
        raise error_type(f"{message}; function={evidence['function_name']}", evidence)
