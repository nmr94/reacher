"""Opt-in protocol observations inside an existing SSM-managed Linux instance."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import re
import sys
import time
import warnings
from collections.abc import Sequence
from importlib.resources import files
from typing import Any
from uuid import UUID, uuid4

from botocore.exceptions import ClientError

from .errors import (
    CleanupWarning,
    ProbeError,
    ProbeTimeoutError,
    UnsupportedCheckError,
    WriteNotAllowedError,
    _attach_evidence,
    _creation_uncertain,
)
from .probe_session import ProbeSession, _families, _networks, _number

_DOCUMENT = "AWS-RunShellScript"
_MAX_SCRIPT = 48_000
_MAX_OUTPUT = 20_000
_TERMINAL = {"Success", "Failed", "Cancelled", "TimedOut"}
_PENDING = {"Pending", "InProgress", "Delayed", "Cancelling"}


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _script(source: bytes, request: dict[str, Any], nonce: str, execution_timeout: int) -> str:
    """Only trusted source and base64 data enter this fixed shell program."""
    encoded_source = base64.b64encode(source).decode("ascii")
    encoded_request = base64.b64encode(_json(request)).decode("ascii")
    program = f"""python3 -I -B - <<'AWS_NETWORK_ASSERTS_PYTHON'
import base64, hashlib, json, os, platform, signal, sys
if sys.version_info < (3, 10) or platform.system() != 'Linux':
    raise RuntimeError('SSM probes require Linux and Python 3.10 or newer')
source = base64.b64decode('{encoded_source}')
request_bytes = base64.b64decode('{encoded_request}')
namespace = {{}}
exec(compile(source, '<aws-network-asserts-probe>', 'exec'), namespace)
def expired(signum, frame):
    raise TimeoutError('SSM probe execution deadline exceeded')
previous_handler = signal.signal(signal.SIGALRM, expired)
signal.alarm({max(1, execution_timeout - 1)})
try:
    observation = namespace['handler'](json.loads(request_bytes), None)
finally:
    signal.alarm(0)
    signal.signal(signal.SIGALRM, previous_handler)
envelope = {{
    'version': 1, 'nonce': '{nonce}',
    'handler_sha256': hashlib.sha256(source).hexdigest(),
    'request_sha256': hashlib.sha256(request_bytes).hexdigest(),
    'runtime': {{'platform': platform.system(), 'python': list(sys.version_info[:3]),
                'effective_uid': os.geteuid()}},
    'temporary_files': 'not_created', 'observation': observation,
}}
output = json.dumps(envelope, sort_keys=True, separators=(',', ':'))
if len(output.encode()) >= {_MAX_OUTPUT}:
    raise RuntimeError('SSM probe output exceeds the safe inline-output limit')
print(output)
AWS_NETWORK_ASSERTS_PYTHON"""
    if len(program.encode()) > _MAX_SCRIPT:
        raise ValueError("SSM probe command exceeds 48000 bytes; reduce the request or CA bundle")
    return program


class SsmProbeSession(ProbeSession):
    """Run fixed protocol operations as the SSM agent user on one existing instance.

    The session creates no Lambda, role, group or probe files. SSM command history
    and the agent's own command artifacts follow the account's existing retention.
    """

    transport = "ssm"

    def __init__(
        self,
        selector: Any,
        *,
        allow_write: bool = False,
        address_family: str = "ipv4",
        expected_source_cidrs: Sequence[str] = (),
        command_timeout: float = 60,
        execution_timeout: int = 30,
        poll_interval: float = 1,
        cancellation_timeout: float = 5,
    ) -> None:
        if allow_write is not True:
            raise WriteNotAllowedError("SSM commands require allow_write=True on this session")
        if selector.config_type != "AWS::EC2::Instance":
            raise UnsupportedCheckError("SSM probes require an instance() selector")
        if selector.account_id is None:
            raise ValueError("Select the instance account with in_account() or account_id")
        if re.fullmatch(r"i-[0-9a-f]{8}(?:[0-9a-f]{9})?", selector.resource_id) is None:
            raise ValueError("SSM probes require a plain EC2 instance ID")
        _families(address_family)
        _number(command_timeout, "command_timeout", 3600)
        _number(poll_interval, "poll_interval", 30)
        _number(cancellation_timeout, "cancellation_timeout", 60)
        if type(execution_timeout) is not int or not 2 <= execution_timeout <= 300:
            raise ValueError("execution_timeout must be an integer from 2 to 300 seconds")
        self.selector = selector
        self.address_family = address_family
        self._networks = _networks(expected_source_cidrs, "expected_source_cidrs")
        self.command_timeout = command_timeout
        self.execution_timeout = execution_timeout
        self.poll_interval = poll_interval
        self.cancellation_timeout = cancellation_timeout
        self._active = False
        self._used = False
        self._pending: dict[str, dict[str, Any]] = {}
        self._source = files("aws_network_asserts").joinpath("_application_handler.py").read_bytes()
        self._geometry = None
        self.source_context: dict[str, Any] = {}
        self.evidence: dict[str, Any] = {
            "transport": "ssm",
            "instance_id": selector.resource_id,
            "account_id": selector.account_id,
            "region": selector.region,
            "handler_sha256": _digest(self._source),
            "commands": [],
            "cleanup": {"temporary_files": "not_created", "commands": "not_sent"},
        }

    def __enter__(self):
        if self._used:
            raise RuntimeError("A probe session cannot be entered more than once")
        self._used = True
        try:
            self._client = self.selector.builder._live_client("ssm")
            self._refresh(self.address_family)
            self._active = True
            return self
        except BaseException as error:
            _attach_evidence(error, self.evidence)
            raise

    def __exit__(self, error_type, error, traceback):
        self._active = False
        try:
            for record in list(self._pending.values()):
                if record.get("cancellation") is None:
                    self._cancel(record, error is not None)
        finally:
            commands = self.evidence["commands"]
            status = (
                "terminal" if any(row["cleanup"] != "not_sent" for row in commands) else "not_sent"
            )
            unknown_attempts = any(row.get("earlier_commands_unconfirmed") for row in commands)
            if (
                self._pending
                or any(row["cleanup"] == "send_unconfirmed" for row in commands)
                or unknown_attempts
            ):
                status = "unconfirmed"
            self.evidence["cleanup"]["commands"] = status
            self.evidence["cleanup"]["earlier_commands_unconfirmed"] = unknown_attempts
            if unknown_attempts:
                self._warn(
                    "SSM SendCommand retry history leaves earlier command IDs unconfirmed; "
                    "returned command completion does not confirm all attempts stopped",
                    error is not None or sys.exc_info()[0] is not None,
                )
        return False

    def _refresh(self, family):
        # Reuse the native metadata validators used by the public selectors.
        from .builder import _id, _items, _one, _required_text, _WorkloadProbeSession

        instances = []
        for reservation in _items(
            self.selector.builder.ec2,
            "describe_instances",
            "Reservations",
            InstanceIds=[self.selector.resource_id],
        ):
            self.selector._check_owner(reservation)
            rows = reservation.get("Instances")
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise ProbeError("EC2 returned an incomplete instance collection", self.evidence)
            instances.extend(rows)
        instance = _one(instances, f"instance {self.selector.resource_id}")
        if (
            instance.get("InstanceId") != self.selector.resource_id
            or instance.get("State", {}).get("Name") != "running"
            or not isinstance(instance.get("Placement"), dict)
        ):
            raise ProbeError("SSM source must be the selected running instance", self.evidence)
        zone = _required_text(instance["Placement"], "AvailabilityZone", "Instance")
        rows = instance.get("NetworkInterfaces")
        if not isinstance(rows, list) or not rows or any(not isinstance(row, dict) for row in rows):
            raise ProbeError("Instance has no complete network-interface list", self.evidence)
        identifiers = [
            _id(_required_text(row, "NetworkInterfaceId", "Instance interface"), "eni-")
            for row in rows
        ]
        if len(set(identifiers)) != len(identifiers):
            raise ProbeError("Instance has duplicate network-interface IDs", self.evidence)
        interfaces = []
        for item in _items(
            self.selector.builder.ec2,
            "describe_network_interfaces",
            "NetworkInterfaces",
            NetworkInterfaceIds=sorted(identifiers),
        ):
            self.selector._check_owner(item)
            attachment = item.get("Attachment", {})
            if (
                item.get("NetworkInterfaceId") not in identifiers
                or item.get("Status") != "in-use"
                or not isinstance(attachment, dict)
                or attachment.get("InstanceId") != self.selector.resource_id
                or attachment.get("Status") != "attached"
                or attachment.get("InstanceOwnerId", self.selector.account_id)
                != self.selector.account_id
                or item.get("AvailabilityZone") != zone
            ):
                raise ProbeError(
                    "Live interface does not confirm the selected instance", self.evidence
                )
            groups = item.get("Groups")
            if (
                not isinstance(groups, list)
                or not groups
                or any(not isinstance(group, dict) for group in groups)
            ):
                raise ProbeError("Instance interface has incomplete security groups", self.evidence)
            group_ids = [
                _id(_required_text(group, "GroupId", "Interface group"), "sg-") for group in groups
            ]
            if len(set(group_ids)) != len(group_ids):
                raise ProbeError("Instance interface has duplicate security groups", self.evidence)
            interfaces.append(
                {
                    "network_interface_id": item["NetworkInterfaceId"],
                    "subnet_id": _id(_required_text(item, "SubnetId", "Interface"), "subnet-"),
                    "vpc_id": _id(_required_text(item, "VpcId", "Interface"), "vpc-"),
                    "security_group_ids": sorted(group_ids),
                    "addresses_by_family": _WorkloadProbeSession._interface_addresses(item),
                }
            )
        if sorted(item["network_interface_id"] for item in interfaces) != sorted(identifiers):
            raise ProbeError(
                "Live interfaces do not match the instance's complete set", self.evidence
            )
        interfaces.sort(key=lambda item: item["network_interface_id"])
        geometry = {
            "availability_zone": zone,
            "interfaces": [
                {key: value for key, value in item.items() if key != "addresses_by_family"}
                for item in interfaces
            ],
        }
        if self._geometry is not None and self._geometry != geometry:
            raise ProbeError("Instance source changed; open a new SSM session", self.evidence)
        required = _families(family)
        if any(
            not any(item["addresses_by_family"][f"ipv{version}"] for item in interfaces)
            for version in required
        ):
            raise ProbeError(
                "Instance has no assigned address in each requested family", self.evidence
            )
        nodes = list(
            _items(
                self._client,
                "describe_instance_information",
                "InstanceInformationList",
                Filters=[{"Key": "InstanceIds", "Values": [self.selector.resource_id]}],
            )
        )
        node = _one(nodes, f"SSM managed instance {self.selector.resource_id}")
        if (
            node.get("InstanceId") != self.selector.resource_id
            or node.get("ResourceType") != "EC2Instance"
            or node.get("PlatformType") != "Linux"
            or node.get("PingStatus") != "Online"
            or node.get("SourceId", self.selector.resource_id) != self.selector.resource_id
            or node.get("SourceType", "AWS::EC2::Instance") != "AWS::EC2::Instance"
        ):
            raise ProbeError("SSM source must be the selected online Linux EC2 node", self.evidence)
        self._geometry = geometry
        self.source_context = {
            "kind": "instance",
            "transport": "ssm",
            "account_id": self.selector.account_id,
            "region": self.selector.region,
            "instance_id": self.selector.resource_id,
            "availability_zone": zone,
            "network_interfaces": interfaces,
            "address_family": self.address_family,
            "host_firewall_tested": True,
            "process_context": "SSM agent execution user; no application or container identity",
        }
        for key in ("subnet_id", "vpc_id", "security_group_ids"):
            if all(item[key] == interfaces[0][key] for item in interfaces):
                self.source_context[key] = interfaces[0][key]
        self.evidence["source_context"] = dict(self.source_context)

    def _begin(self, kind, target, port, *, address_family=None):
        if not self._active:
            raise RuntimeError(
                "SSM checks require an active with instance.ssm_probe_session() context"
            )
        self._selected_family = self._check_family(address_family)
        return {
            **self.selector._context(),
            "method": f"ssm_{kind}",
            "transport": "ssm",
            "kind": kind,
            "target": target,
            "port": port,
            "source_context": dict(self.source_context),
            "deployment": self.evidence,
            "commands": [],
        }

    def _invoke(self, request, evidence):
        record = {"kind": request["kind"], "nonce": str(uuid4()), "cleanup": "not_sent"}
        evidence["commands"].append(record)
        self.evidence["commands"].append(record)
        try:
            self._refresh(self._selected_family)
            evidence["source_context"] = dict(self.source_context)
            record["source_context"] = dict(self.source_context)
            script = _script(self._source, request, record["nonce"], self.execution_timeout)
            parameters = {"commands": [script], "executionTimeout": [str(self.execution_timeout)]}
            record["request_sha256"] = _digest(_json(request))
            record["cleanup"] = "send_unconfirmed"
            response = self._client.send_command(
                InstanceIds=[self.selector.resource_id],
                DocumentName=_DOCUMENT,
                Parameters=parameters,
                TimeoutSeconds=max(30, math.ceil(self.command_timeout)),
                Comment=f"aws-network-asserts {record['nonce']}",
                CloudWatchOutputConfig={"CloudWatchOutputEnabled": False},
            )
            metadata = response.get("ResponseMetadata", {})
            retries = metadata.get("RetryAttempts", 0) if isinstance(metadata, dict) else None
            record["sdk_retry_attempts"] = retries
            record["earlier_commands_unconfirmed"] = type(retries) is not int or retries != 0
            command = response.get("Command")
            if not isinstance(command, dict):
                raise ProbeError("SSM did not return a command identity", evidence)
            command_id = command.get("CommandId")
            record["command_id"] = command_id
            try:
                if not isinstance(command_id, str) or str(UUID(command_id)) != command_id:
                    raise ValueError
            except ValueError as error:
                raise ProbeError("SSM returned an invalid command ID", evidence) from error
            if (
                command.get("DocumentName") != _DOCUMENT
                or command.get("InstanceIds") != [self.selector.resource_id]
                or ("Parameters" in command and command["Parameters"] != parameters)
                or command.get("Targets")
            ):
                raise ProbeError(
                    "SSM command did not confirm its document and sole target", evidence
                )
            self._pending[command_id] = record
            record["cleanup"] = "pending"
            invocation = self._poll(command_id, self.command_timeout, record)
            self._pending.pop(command_id, None)
            record["cleanup"] = "terminal"
            if (
                invocation["Status"] != "Success"
                or invocation.get("StatusDetails", "Success") not in {"", "Success"}
                or type(invocation.get("ResponseCode")) is not int
                or invocation["ResponseCode"] != 0
            ):
                raise ProbeError("SSM command did not complete successfully", evidence)
            output = invocation.get("StandardOutputContent")
            if (
                not isinstance(output, str)
                or not output
                or len(output.encode()) >= _MAX_OUTPUT
                or invocation.get("StandardErrorContent") != ""
            ):
                raise ProbeError("SSM returned missing, truncated or unexpected output", evidence)
            try:
                envelope = json.loads(output)
            except (TypeError, ValueError) as error:
                raise ProbeError("SSM returned incomplete or malformed JSON", evidence) from error
            runtime = envelope.get("runtime") if isinstance(envelope, dict) else None
            if (
                not isinstance(envelope, dict)
                or type(envelope.get("version")) is not int
                or envelope.get("version") != 1
                or envelope.get("nonce") != record["nonce"]
                or envelope.get("handler_sha256") != self.evidence["handler_sha256"]
                or envelope.get("request_sha256") != record["request_sha256"]
                or envelope.get("temporary_files") != "not_created"
                or not isinstance(envelope.get("observation"), dict)
                or not isinstance(runtime, dict)
                or runtime.get("platform") != "Linux"
                or not isinstance(runtime.get("python"), list)
                or len(runtime["python"]) != 3
                or any(type(value) is not int or value < 0 for value in runtime["python"])
                or tuple(runtime["python"][:2]) < (3, 10)
                or type(runtime.get("effective_uid")) is not int
                or runtime["effective_uid"] < 0
            ):
                raise ProbeError(
                    "SSM output does not confirm this probe request and runtime", evidence
                )
            record["runtime"] = runtime
            evidence["source_context"]["execution_runtime"] = runtime
            observation = envelope["observation"]
            evidence["last_observation"] = observation
            return observation
        except BaseException as error:
            _attach_evidence(error, evidence)
            command_id = record.get("command_id")
            if isinstance(command_id, str) and command_id in self._pending:
                self._cancel(record, True)
            elif record["cleanup"] == "send_unconfirmed":
                if isinstance(error, ClientError) and not _creation_uncertain(error):
                    record["cleanup"] = "not_sent"
                else:
                    self._warn(
                        "SSM command creation is unconfirmed; inspect the recorded comment/ID", True
                    )
            raise

    def _invocation(self, command_id):
        result = self._client.get_command_invocation(
            CommandId=command_id, InstanceId=self.selector.resource_id
        )
        if (
            result.get("CommandId") != command_id
            or result.get("InstanceId") != self.selector.resource_id
            or result.get("DocumentName") != _DOCUMENT
            or result.get("Status") not in _PENDING | _TERMINAL
        ):
            raise ProbeError("SSM invocation identity or status is unconfirmed", self.evidence)
        return result

    def _poll(self, command_id, timeout, record):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                result = self._invocation(command_id)
                record["last_invocation"] = result
                if result["Status"] in _TERMINAL:
                    return result
            except ClientError as error:
                if error.response["Error"]["Code"] != "InvocationDoesNotExist":
                    raise
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(self.poll_interval, remaining))
        raise ProbeTimeoutError("SSM command exceeded its polling deadline", self.evidence)

    def _cancel(self, record, preserve_error):
        command_id = record["command_id"]
        record["cancellation"] = "unconfirmed"
        try:
            self._client.cancel_command(
                CommandId=command_id, InstanceIds=[self.selector.resource_id]
            )
            record["cancellation"] = "requested"
            terminal = self._poll(command_id, self.cancellation_timeout, record)
            record["cleanup"] = "terminal_after_cancellation"
            record["terminal_status"] = terminal["Status"]
            self._pending.pop(command_id, None)
        except BaseException as error:
            record["cleanup"] = "unconfirmed"
            record["cancellation_error"] = str(error) or type(error).__name__
            if not isinstance(error, Exception) and not preserve_error:
                _attach_evidence(error, self.evidence)
                raise
        finally:
            record["process_stop_confirmed"] = False
            self._warn(
                f"SSM command {command_id}: cancellation is best effort; "
                "inspect command history if execution may still be running",
                preserve_error or sys.exc_info()[0] is not None,
            )

    def _warn(self, message, preserve_error):
        try:
            warnings.warn(message, CleanupWarning, stacklevel=3)
        except CleanupWarning as warning:
            if not preserve_error:
                _attach_evidence(warning, self.evidence)
                raise
            logging.getLogger(__name__).warning(message)

    def _validate_observation(self, observation, spec, address, evidence):
        super()._validate_observation(observation, spec, address, evidence)
        source = observation.get("source_ip")
        if source is not None:
            matches = [
                item
                for item in self.source_context["network_interfaces"]
                if any(source in values for values in item["addresses_by_family"].values())
            ]
            if len(matches) != 1:
                raise ProbeError(
                    "Observed source IP does not identify a current instance ENI", evidence
                )
            observation["source_interface"] = matches[0]
