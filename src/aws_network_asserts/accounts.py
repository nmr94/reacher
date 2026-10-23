"""Route live account-scoped API calls through verified boto3 sessions."""

import re
from collections.abc import Mapping
from threading import Lock
from typing import Any

import boto3

from .clients import AwsClients
from .errors import AccountMismatchError


def validate_account_id(value: str) -> str:
    """Return an AWS account ID, rejecting anything except 12 ASCII digits."""
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{12}", value) is None:
        raise ValueError("AWS account ID must be a string containing exactly 12 digits")
    return value


class AccountClients:
    """Use optional member-account profiles or sessions for live API calls.

    Unmapped accounts use the central session only if STS confirms that it
    belongs to that account. Profiles are loaded lazily; boto3 handles any
    configured AssumeRole provider and credential refresh. Every factory
    inherits the central client's endpoint and transport settings.
    """

    def __init__(
        self,
        central: AwsClients,
        *,
        account_profiles: Mapping[str, str] | None = None,
        account_sessions: Mapping[str, boto3.Session] | None = None,
    ) -> None:
        self._central = central
        self._profiles = dict(account_profiles or {})
        self._sessions = dict(account_sessions or {})
        for account_id, profile in self._profiles.items():
            validate_account_id(account_id)
            if not isinstance(profile, str) or not profile.strip():
                raise ValueError("account_profiles values must be nonempty profile names")
        for account_id, session in self._sessions.items():
            validate_account_id(account_id)
            if not callable(getattr(session, "client", None)):
                raise TypeError("account_sessions values must be boto3 sessions")
        if self._profiles.keys() & self._sessions.keys():
            raise ValueError("An account cannot have both a profile and a session mapping")
        self._factories: dict[str, AwsClients] = {}
        self._identities: dict[tuple[AwsClients, str], str] = {}
        self._lock = Lock()

    def _factory(self, account_id: str) -> AwsClients:
        if account_id in self._factories:
            return self._factories[account_id]
        if account_id in self._sessions:
            session = self._sessions[account_id]
        elif account_id in self._profiles:
            session = boto3.Session(profile_name=self._profiles[account_id])
        else:
            return self._central
        factory = AwsClients(
            session,
            endpoint_url=self._central.endpoint_url,
            endpoint_urls=self._central.endpoint_urls,
            boto_config=self._central.boto_config,
            verify=self._central.verify,
        )
        self._factories[account_id] = factory
        return factory

    def client(self, service: str, region: str, account_id: str) -> Any:
        """Return a regional client only after verifying its credential account.

        Successful identity checks are reused per factory and region. Failures
        propagate and are never treated as evidence about network topology.
        """
        validate_account_id(account_id)
        with self._lock:
            factory = self._factory(account_id)
            key = (factory, region)
            actual = self._identities.get(key)
            if actual is None:
                actual = factory.client("sts", region).get_caller_identity().get("Account")
            if actual != account_id:
                raise AccountMismatchError(
                    f"Credentials resolve to AWS account {actual!r}, but account "
                    f"{account_id!r} was requested. Configure account_profiles or "
                    "account_sessions for the requested account."
                )
            self._identities[key] = actual
            return factory.client(service, region)
