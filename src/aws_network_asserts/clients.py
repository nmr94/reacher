"""A small, region-aware boto3 client factory with explicit endpoint overrides."""

from collections.abc import Mapping
from threading import Lock
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import NoRegionError


class AwsClients:
    """Reuse clients without changing the caller's credential provider chain.

    Endpoint precedence is ``region:service``, then ``service``, then the
    common ``endpoint_url``. If no override applies, boto3 resolves its usual
    endpoint (including configured AWS_ENDPOINT_URL environment variables).
    """

    def __init__(
        self,
        session: boto3.Session | None = None,
        *,
        endpoint_url: str | None = None,
        endpoint_urls: Mapping[str, str] | None = None,
        boto_config: Config | None = None,
        verify: bool | str | None = None,
    ) -> None:
        self.session = session if session is not None else boto3.Session()
        self.endpoint_url = endpoint_url
        self.endpoint_urls = dict(endpoint_urls or {})
        self.verify = verify
        defaults = Config(
            retries={"mode": "standard", "total_max_attempts": 3},
            connect_timeout=5,
            read_timeout=30,
        )
        self.boto_config = defaults.merge(boto_config) if boto_config is not None else defaults
        self._clients: dict[tuple[str, str], Any] = {}
        self._lock = Lock()

    @property
    def region_name(self) -> str | None:
        """Return the session region; never invent a default AWS Region."""
        return self.session.region_name

    def client(self, service: str, region: str) -> Any:
        """Get a client cached by service and region, creating it at most once."""
        if not region:
            raise NoRegionError()
        key = (service, region)
        # Session/client construction is not thread safe. The clients themselves
        # may be shared by threads after this serialized creation step.
        with self._lock:
            if key not in self._clients:
                kwargs: dict[str, Any] = {
                    "region_name": region,
                    "config": self.boto_config,
                }
                endpoint = self.endpoint_urls.get(
                    f"{region}:{service}",
                    self.endpoint_urls.get(service, self.endpoint_url),
                )
                if endpoint is not None:
                    kwargs["endpoint_url"] = endpoint
                if self.verify is not None:
                    kwargs["verify"] = self.verify
                self._clients[key] = self.session.client(service, **kwargs)
            return self._clients[key]
