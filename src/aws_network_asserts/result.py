"""Small assertion results that produce useful pytest failure output."""

import json
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any


@dataclass(frozen=True)
class CheckResult:
    passed: bool
    message: str
    evidence: dict[str, Any] = field(default_factory=dict, repr=False)

    def __bool__(self) -> bool:
        return self.passed

    def __repr__(self) -> str:
        return f"{'PASS' if self.passed else 'FAIL'}: {self.message}"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible snapshot, including current cleanup evidence."""
        return json.loads(
            json.dumps(
                {
                    "passed": self.passed,
                    "message": self.message,
                    "evidence": self.evidence,
                },
                default=_json_default,
            )
        )

    def assert_ok(self) -> None:
        """Useful when an explicit AssertionError is preferable to ``assert``."""
        if not self.passed:
            raise AssertionError(self.message)


def _json_default(value):
    if isinstance(value, CheckResult):
        return value.to_dict()
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    raise TypeError(f"Cannot serialize evidence value {type(value).__name__}")
