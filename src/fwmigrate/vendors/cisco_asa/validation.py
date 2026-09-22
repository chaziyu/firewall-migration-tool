"""Cisco ASA source validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .derived import ASADerivedViews


@dataclass(frozen=True)
class ASAValidationIssue:
    severity: str
    category: str
    message: str
    source_context: str | None = None
    source_object: str | None = None


@dataclass(frozen=True)
class ASAValidationResult:
    issues: tuple[ASAValidationIssue, ...] = ()

    @property
    def errors(self) -> tuple[ASAValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "error")

    @property
    def warnings(self) -> tuple[ASAValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "warning")


def validate_asa_config(config: Any, derived: ASADerivedViews) -> ASAValidationResult:
    issues = [ASAValidationIssue(
        severity="error" if not item.resolved else "warning",
        category=item.reference_type,
        message=item.reason,
        source_context=item.source_context,
        source_object=item.source_object,
    ) for item in derived.reference_issues if not item.resolved]
    issues.extend(ASAValidationIssue(
        severity="error",
        category="parse",
        message=item.reason,
        source_object=item.object_name,
    ) for item in config.diagnostics)
    issues.extend(ASAValidationIssue(
        severity="warning",
        category="unsupported",
        message=item["reason"],
        source_object=f"line {item.get('line_number', '')}".strip(),
    ) for item in config.unsupported_commands)
    return ASAValidationResult(tuple(issues))


__all__ = ["ASAValidationIssue", "ASAValidationResult", "validate_asa_config"]

