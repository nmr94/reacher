"""Standalone boto3 shim for MiniStack: pick the account per client, no roles, no credentials.

MiniStack treats a 12-digit access key id as the account id of the request, so acting "in" an
account is just signing with that account id as the key. This module hides that behind a tiny API.
It depends only on boto3 and can be copied into any project as a single file.

    from ministack_boto3 import MiniStack

    ms = MiniStack()                                   # http://localhost:4566 by default
    s3_a = ms.client("s3", account="111111111111")
    s3_b = ms.client("s3", account="222222222222")     # same call, different tenant

    dev = ms.account("333333333333", region="eu-west-1")   # bound view
    dev.client("sqs").create_queue(QueueName="q")
    dev.resource("dynamodb")

    ms.client("sts").get_caller_identity()["Account"]  # default account

The endpoint comes from the constructor, else MINISTACK_ENDPOINT / AWS_ENDPOINT_URL, else
http://localhost:4566. Module-level ``client`` / ``resource`` / ``session`` use a shared default
instance.
"""
from __future__ import annotations

import os
import re
import threading
from typing import Any, Optional

import boto3
from botocore.config import Config

__all__ = ["MiniStack", "Account", "client", "resource", "session"]

DEFAULT_ENDPOINT = "http://localhost:4566"
_ACCOUNT_RE = re.compile(r"^\d{12}$")
# MiniStack ignores the secret unless IAM enforcement is on, and never needs a session token.
_SECRET = "test"


def _check_account(account: str) -> str:
    account = str(account)
    if not _ACCOUNT_RE.match(account):
        raise ValueError(f"account must be a 12-digit string, got {account!r}")
    return account


class MiniStack:
    def __init__(
        self,
        endpoint_url: Optional[str] = None,
        region: Optional[str] = None,
        default_account: Optional[str] = None,
    ):
        self.endpoint_url = (
            endpoint_url
            or os.environ.get("MINISTACK_ENDPOINT")
            or os.environ.get("AWS_ENDPOINT_URL")
            or DEFAULT_ENDPOINT
        )
        self.region = region or os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-east-1"
        self.default_account = _check_account(
            default_account or os.environ.get("MINISTACK_ACCOUNT_ID") or "000000000000"
        )
        self._sessions: dict[tuple[str, str], boto3.Session] = {}
        self._lock = threading.Lock()

    def session(self, account: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
        """A boto3 Session that signs as ``account`` (cached per account/region)."""
        account = _check_account(account or self.default_account)
        region = region or self.region
        key = (account, region)
        with self._lock:
            if key not in self._sessions:
                # The account id is the access key id; that is the whole trick.
                self._sessions[key] = boto3.Session(
                    aws_access_key_id=account,
                    aws_secret_access_key=_SECRET,
                    region_name=region,
                )
            return self._sessions[key]

    def _config(self, config: Optional[Config]) -> Config:
        # Path-style S3 so buckets resolve against a bare host like localhost.
        base = Config(s3={"addressing_style": "path"})
        return base.merge(config) if config else base

    def client(
        self,
        service: str,
        account: Optional[str] = None,
        region: Optional[str] = None,
        config: Optional[Config] = None,
        **kwargs: Any,
    ):
        kwargs.setdefault("endpoint_url", self.endpoint_url)
        return self.session(account, region).client(service, config=self._config(config), **kwargs)

    def resource(
        self,
        service: str,
        account: Optional[str] = None,
        region: Optional[str] = None,
        config: Optional[Config] = None,
        **kwargs: Any,
    ):
        kwargs.setdefault("endpoint_url", self.endpoint_url)
        return self.session(account, region).resource(service, config=self._config(config), **kwargs)

    def account(self, account: str, region: Optional[str] = None) -> "Account":
        """A view bound to one account (and optionally region)."""
        return Account(self, _check_account(account), region)


class Account:
    """A MiniStack handle fixed to one account, so callers never repeat ``account=``."""

    def __init__(self, stack: MiniStack, account_id: str, region: Optional[str] = None):
        self.stack = stack
        self.account_id = account_id
        self.region = region

    def session(self, region: Optional[str] = None) -> boto3.Session:
        return self.stack.session(self.account_id, region or self.region)

    def client(self, service: str, region: Optional[str] = None, **kwargs: Any):
        return self.stack.client(service, self.account_id, region or self.region, **kwargs)

    def resource(self, service: str, region: Optional[str] = None, **kwargs: Any):
        return self.stack.resource(service, self.account_id, region or self.region, **kwargs)

    def __repr__(self) -> str:
        return f"Account({self.account_id!r}, region={self.region!r})"


_default: Optional[MiniStack] = None
_default_lock = threading.Lock()


def _stack() -> MiniStack:
    global _default
    with _default_lock:
        if _default is None:
            _default = MiniStack()
        return _default


def client(service: str, account: Optional[str] = None, region: Optional[str] = None, **kwargs: Any):
    return _stack().client(service, account, region, **kwargs)


def resource(service: str, account: Optional[str] = None, region: Optional[str] = None, **kwargs: Any):
    return _stack().resource(service, account, region, **kwargs)


def session(account: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
    return _stack().session(account, region)
