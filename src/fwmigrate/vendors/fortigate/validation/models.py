from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ValidationSeverity(str, Enum):
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """
    One validation finding.

    Validation reports problems only. It never modifies extracted
    FortiGate source data or derived views.
    """

    severity: ValidationSeverity

    domain: str
    vdom: str

    object_name: str | None = None
    field: str | None = None

    message: str = ""


@dataclass(slots=True)
class ValidationResult:
    """Aggregate validation result."""

    issues: list[ValidationIssue] = field(
        default_factory=list
    )

    @property
    def errors(
        self,
    ) -> list[ValidationIssue]:
        return [
            issue
            for issue in self.issues
            if issue.severity
            == ValidationSeverity.ERROR
        ]

    @property
    def warnings(
        self,
    ) -> list[ValidationIssue]:
        return [
            issue
            for issue in self.issues
            if issue.severity
            == ValidationSeverity.WARNING
        ]

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def warning_count(self) -> int:
        return len(self.warnings)