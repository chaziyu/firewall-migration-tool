"""Check Point source validation logic."""

from __future__ import annotations

from ..derived import CheckPointDerivedViews
from ..models import CollectionStatus
from ..model.source import CheckPointConfig
from .models import CheckPointValidationIssue, CheckPointValidationResult


def validate_checkpoint_config(config: CheckPointConfig, derived: CheckPointDerivedViews, collection: tuple = ()) -> CheckPointValidationResult:
    issues = [CheckPointValidationIssue(
        severity="error" if item.status in {CollectionStatus.API_ERROR, CollectionStatus.TRANSPORT_ERROR, CollectionStatus.PERMISSION_DENIED} else "warning",
        category="collection",
        message=item.error or f"Collection incomplete: {item.command}",
        command=item.command,
    ) for item in collection if not item.complete]
    issues.extend(CheckPointValidationIssue(
        severity="warning",
        category="unsupported",
        message=f"Unsupported collection command: {item.command}",
        command=item.command,
    ) for item in collection if item.status == CollectionStatus.UNSUPPORTED_COMMAND)
    issues.extend(CheckPointValidationIssue(
        severity="error" if item.status in {"wrong_type", "conflicting_relationship"} else "warning",
        category="reference",
        message=f"Check Point reference {item.status}: {item.reference}",
        command=getattr(item.source, "command", None),
        reference=item.reference,
    ) for item in derived.broken_references)
    issues.extend(CheckPointValidationIssue(
        severity="warning",
        category="nat-transform",
        message=item.message,
        command="show-nat-rulebase",
        reference=item.reference or item.source_name,
    ) for item in derived.nat.issues)
    return CheckPointValidationResult(tuple(issues))


__all__ = ["validate_checkpoint_config"]
