"""Validation for Junos source reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .derived import JuniperDerivedViews


@dataclass(frozen=True)
class JuniperValidationIssue:
    severity: str
    category: str
    message: str
    context: str | None = None
    object_name: str | None = None


@dataclass(frozen=True)
class JuniperValidationResult:
    issues: tuple[JuniperValidationIssue, ...] = ()


def validate_juniper_config(config: Any, derived: JuniperDerivedViews) -> JuniperValidationResult:
    issues = [JuniperValidationIssue("error", "reference", item.notes or f"Unresolved {item.expected_type}: {item.reference}",
                                     item.source_context, item.source_object)
              for item in derived.dependencies if item.result == "UNRESOLVED"]
    issues.extend(JuniperValidationIssue("warning", "unsupported", command.raw_sanitized,
                                         command.context_name)
                  for command in config.unsupported_commands)
    return JuniperValidationResult(tuple(issues))


__all__ = ["JuniperValidationIssue", "JuniperValidationResult", "validate_juniper_config"]
