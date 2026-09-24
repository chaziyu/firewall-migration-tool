"""Validation for Junos source reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.extraction.sanitize import sanitize_raw_text

from .derived import JuniperDerivedViews


@dataclass(frozen=True)
class JuniperValidationIssue:
    severity: str
    category: str
    message: str
    context: str | None = None
    object_name: str | None = None
    code: str = "JUNIPER_REVIEW"
    context_type: str | None = None
    context_name: str | None = None
    source_path: str | None = None
    object_type: str | None = None
    field: str | None = None
    reference: str | None = None
    expected_type: str | None = None


@dataclass(frozen=True)
class JuniperReviewItem:
    severity: str
    category: str
    message: str
    context: str | None = None
    source_path: str | None = None
    object_name: str | None = None
    field: str | None = None
    code: str = "JUNIPER_REVIEW"


@dataclass(frozen=True)
class JuniperValidationResult:
    issues: tuple[JuniperValidationIssue, ...] = ()

    @property
    def errors(self) -> tuple[JuniperValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "error")

    @property
    def warnings(self) -> tuple[JuniperValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "warning")


def _context_parts(context: str | None) -> tuple[str | None, str | None]:
    if not context:
        return None, None
    kind, _, name = context.partition(" ")
    return (kind, name) if name else ("root", "root")


def validate_juniper_config(config: Any, derived: JuniperDerivedViews) -> JuniperValidationResult:
    """Report source/derived issues without changing either input."""
    issues: list[JuniperValidationIssue] = []
    for item in derived.dependencies:
        if item.result != "UNRESOLVED":
            continue
        context_type, context_name = _context_parts(item.source_context)
        issues.append(JuniperValidationIssue(
            severity="error", category="reference",
            message=item.notes or f"Unresolved {item.expected_type}: {item.reference}",
            context=item.source_context, object_name=item.source_object, code="UNRESOLVED_REFERENCE",
            context_type=context_type, context_name=context_name, source_path=item.source_path,
            object_type=item.source_path.rsplit(" ", 1)[-1], field=item.source_field,
            reference=item.reference, expected_type=item.expected_type,
        ))
    for item in derived.inheritance_view.get("issues", ()):
        status = str(item.get("status", "INHERITANCE_REVIEW")).upper()
        context_type, context_name = _context_parts(item.get("context"))
        issues.append(JuniperValidationIssue(
            severity="error", category="inheritance", message=status.replace("_", " ").title(),
            context=item.get("context"), object_name=" ".join(item.get("target_path") or ()),
            code=status, context_type=context_type, context_name=context_name,
            source_path=" ".join(item.get("target_path") or ()), object_type="configuration-group",
        ))
    for command in config.unsupported_commands:
        status = command.extraction_status or ExtractionStatus.UNSUPPORTED
        if status not in (ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARTIAL, ExtractionStatus.SOURCE_ONLY,
                          ExtractionStatus.PARSE_ERROR, ExtractionStatus.UNKNOWN, ExtractionStatus.IGNORED):
            continue
        severity = "info" if status in (ExtractionStatus.SOURCE_ONLY, ExtractionStatus.IGNORED) else "warning"
        code = {ExtractionStatus.UNSUPPORTED: "UNSUPPORTED_SOURCE", ExtractionStatus.PARTIAL: "PARTIAL_EXTRACTION",
                ExtractionStatus.SOURCE_ONLY: "SOURCE_ONLY", ExtractionStatus.PARSE_ERROR: "PARSE_ERROR",
                ExtractionStatus.UNKNOWN: "UNKNOWN_SOURCE", ExtractionStatus.IGNORED: "IGNORED_SOURCE"}[status]
        issues.append(JuniperValidationIssue(
            severity, "extraction-coverage", sanitize_raw_text(command.parse_error or
                f"{status.value.replace('_', ' ').title()} source requires review"),
            command.context_name, object_name=" ".join(command.tokens[1:3]) or None, code=code,
            context_type=command.context_type, context_name=command.context_name,
            source_path=" ".join(command.tokens[1:2]) or None,
        ))
    unique: dict[tuple[Any, ...], JuniperValidationIssue] = {}
    for issue in issues:
        key = (issue.code, issue.context_type, issue.context_name, issue.source_path, issue.object_name,
               issue.field, issue.reference, issue.expected_type)
        unique.setdefault(key, issue)
    return JuniperValidationResult(tuple(unique.values()))


def build_review_items(validation: JuniperValidationResult, sections=(), unsupported=()) -> tuple[JuniperReviewItem, ...]:
    """Combine validation and extraction evidence into a stable review projection."""
    items = [JuniperReviewItem(issue.severity, issue.category, issue.message, issue.context,
                               issue.source_path, issue.object_name, issue.field, issue.code)
             for issue in validation.issues]
    for section in sections:
        if section.status == ExtractionStatus.EXTRACTED:
            continue
        for status in section.review_reasons or [section.status.value]:
            code = status if status in {"SOURCE_ONLY", "PARTIAL", "UNSUPPORTED", "PARSE_ERROR", "UNKNOWN", "IGNORED"} else section.status.value
            items.append(JuniperReviewItem("info" if code == "SOURCE_ONLY" else "warning", "extraction-coverage",
                                           f"{code.replace('_', ' ').title()} source in {section.path}",
                                           section.source_context, section.path, code=code))
    for item in unsupported:
        items.append(JuniperReviewItem("warning", "unsupported", item.reason, item.source_context,
                                       item.source_path, item.source_name, code="UNSUPPORTED_SOURCE"))
    unique: dict[tuple[Any, ...], JuniperReviewItem] = {}
    for item in items:
        unique.setdefault((item.code, item.context, item.source_path, item.object_name, item.field), item)
    return tuple(unique.values())


class JuniperValidationIssueIndex:
    """Read-only lookup for report annotation by context, object, path, or category."""

    def __init__(self, issues: tuple[JuniperValidationIssue, ...]):
        self.by_context = _index(issues, lambda issue: issue.context)
        self.by_object = _index(issues, lambda issue: (issue.context, issue.object_type, issue.object_name))
        self.by_path = _index(issues, lambda issue: issue.source_path)
        self.by_category = _index(issues, lambda issue: issue.category)


def _index(issues, key):
    result: dict[Any, list[JuniperValidationIssue]] = {}
    for issue in issues:
        value = key(issue)
        if value is not None:
            result.setdefault(value, []).append(issue)
    return {value: tuple(items) for value, items in result.items()}


__all__ = ["JuniperValidationIssue", "JuniperValidationResult", "JuniperReviewItem",
           "JuniperValidationIssueIndex", "validate_juniper_config", "build_review_items"]
