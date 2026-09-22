"""Check Point source validation."""

from __future__ import annotations

from dataclasses import dataclass

from .derived import CheckPointDerivedViews
from .models import CollectionStatus
from .source_model import CheckPointConfig


@dataclass(frozen=True)
class CheckPointValidationIssue:
    severity: str
    category: str
    message: str
    command: str | None = None
    reference: str | None = None


@dataclass(frozen=True)
class CheckPointValidationResult:
    issues: tuple[CheckPointValidationIssue, ...] = ()

    @property
    def errors(self) -> tuple[CheckPointValidationIssue, ...]:
        return tuple(item for item in self.issues if item.severity == "error")

    @property
    def warnings(self) -> tuple[CheckPointValidationIssue, ...]:
        return tuple(item for item in self.issues if item.severity == "warning")


def validate_checkpoint_config(config: CheckPointConfig, derived: CheckPointDerivedViews) -> CheckPointValidationResult:
    issues = [CheckPointValidationIssue(
        severity="error" if item.status in {CollectionStatus.API_ERROR, CollectionStatus.TRANSPORT_ERROR, CollectionStatus.PERMISSION_DENIED} else "warning",
        category="collection",
        message=item.error or f"Collection incomplete: {item.command}",
        command=item.command,
    ) for item in config.collection if not item.complete]
    issues.extend(CheckPointValidationIssue(
        severity="warning",
        category="unsupported",
        message=f"Unsupported collection command: {item.command}",
        command=item.command,
    ) for item in config.collection if item.status == CollectionStatus.UNSUPPORTED_COMMAND)
    issues.extend(CheckPointValidationIssue(
        severity="error",
        category="reference",
        message=f"Unresolved Check Point reference: {item['reference']}",
        command=item.get("command"),
        reference=item.get("reference"),
    ) for item in derived.unresolved_references)
    return CheckPointValidationResult(tuple(issues))


__all__ = ["CheckPointValidationIssue", "CheckPointValidationResult", "validate_checkpoint_config"]
