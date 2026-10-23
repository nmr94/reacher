"""Evaluation errors are deliberately different from failed assertions."""

from typing import Any


def _creation_uncertain(error: Any) -> bool:
    """A final rejection cannot undo a write from an earlier SDK attempt."""
    metadata = error.response.get("ResponseMetadata", {})
    if not isinstance(metadata, dict):
        return True
    status = metadata.get("HTTPStatusCode")
    retries = metadata.get("RetryAttempts", 0)
    return (
        type(status) is not int
        or not 400 <= status < 500
        or type(retries) is not int
        or retries != 0
        or error.response.get("Error", {}).get("Code")
        in {"ResourceConflictException", "RequestTimeout", "RequestTimeoutException"}
    )


def _attach_evidence(
    error: BaseException, evidence: dict[str, Any], name: str = "evidence"
) -> None:
    """Diagnostics must never replace an original exception, even a user exception."""
    try:
        setattr(error, name, evidence)
    except Exception:
        pass  # Some exception classes expose read-only diagnostic attributes.


class NetworkAssertionError(RuntimeError):
    """The check could not be evaluated; this is never proof of isolation."""


class UnsupportedCheckError(NetworkAssertionError):
    """AWS or this small library cannot establish the requested claim."""


class ResourceNotFoundError(NetworkAssertionError):
    """A prerequisite resource was not found."""


class ConfigResourceNotFoundError(ResourceNotFoundError):
    """AWS Config has no usable recorded configuration for a resource."""


class AnalysisError(NetworkAssertionError):
    """Reachability Analyzer did not produce a conclusive result."""


class AnalysisTimeoutError(AnalysisError):
    """Reachability Analyzer did not complete before the polling deadline."""


class CleanupWarning(UserWarning):
    """A temporary analysis, Lambda, role or security group needs attention."""


class AccountMismatchError(NetworkAssertionError):
    """Selected credentials belong to a different AWS account than requested."""


class WriteNotAllowedError(NetworkAssertionError):
    """A Lambda probe requires explicit permission on the individual test call."""


class ProbeError(NetworkAssertionError):
    """The Lambda probe could not produce a connection observation."""

    def __init__(self, message: str, evidence: dict[str, Any]) -> None:
        super().__init__(message)
        self.evidence = evidence


class ProbeTimeoutError(ProbeError):
    """Resource propagation or Lambda readiness exceeded its polling deadline."""
