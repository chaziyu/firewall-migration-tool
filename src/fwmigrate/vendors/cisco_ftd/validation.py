"""Validation for FTD source reporting."""

from dataclasses import dataclass

from .derived import FTDDerivedViews
from .model import CiscoFTDConfig


@dataclass(frozen=True)
class FTDValidationIssue:
    severity: str
    category: str
    message: str
    source_plane: str
    source_object: str | None = None


@dataclass(frozen=True)
class FTDValidationResult:
    issues: tuple[FTDValidationIssue, ...] = ()


def validate_ftd_config(config: CiscoFTDConfig, derived: FTDDerivedViews) -> FTDValidationResult:
    issues = [FTDValidationIssue("error",
        "ambiguous-reference" if item.status == "AMBIGUOUS" else
        "wrong-kind-reference" if item.status == "WRONG_KIND" else "unresolved-reference",
        f"{item.reason.replace('-', ' ').capitalize()} FTD reference {item.reference} in {item.field}; "
        f"expected {' | '.join(item.expected_kinds)}; found {' | '.join(item.found_kinds) or 'none'} "
        f"in domain/scope {item.domain_id or item.scope or 'source'}",
        item.source_plane, item.owner) for item in derived.unresolved_references]
    issues.extend(FTDValidationIssue("warning", "unsupported", str(item.get("reason", "Unsupported source evidence")),
                                     config.source_plane, str(item.get("source_path", "")))
                  for item in config.unsupported_evidence)
    return FTDValidationResult(tuple(issues))


__all__ = ["FTDValidationIssue", "FTDValidationResult", "validate_ftd_config"]
