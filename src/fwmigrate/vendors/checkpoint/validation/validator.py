"""Check Point source validation logic."""

from __future__ import annotations

from ..derived import CheckPointDerivedViews
from ..models import CollectionStatus
from ..model.source import CheckPointConfig
from .models import CheckPointValidationIssue, CheckPointValidationResult


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


__all__ = ["validate_checkpoint_config"]
