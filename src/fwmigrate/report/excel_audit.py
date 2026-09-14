"""Shared row classification used by Excel audit generation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence


OBJECT_HEADERS = (
    "Name", "Rule Name", "Object Name", "Item", "ID", "Source ID",
    "Section", "Interface", "Profile Name",
)
REASON_HEADERS = (
    "Review Reasons", "Review Reason", "Reason", "Message", "Notes", "Audit Note",
)
REVIEW_STATUS_HEADERS = (
    "Extraction Status", "Migration Status", "Status", "Confidence", "Result",
)
EVIDENCE_STATUS_HEADERS = ("Extraction Status", "Migration Status", "Status")
AUDIT_SHEETS = frozenset({"Warnings", "Unsupported", "Unresolved References"})


@dataclass(frozen=True)
class AuditClassification:
    review: tuple[str, str, str, str, str, int] | None = None
    evidence: tuple[str, str, str, str, str, int] | None = None


@dataclass
class ExcelAuditAccumulator:
    """Collect only actionable audit rows while inventory rows are written."""

    review_rows: list[tuple[str, str, str, str, str, int]] = field(default_factory=list)
    evidence_rows: list[tuple[str, str, str, str, str, int]] = field(default_factory=list)

    def add_row(
        self,
        sheet_title: str,
        headers: Sequence[str],
        values: Sequence[Any],
        row_number: int,
        category: Callable[[str], str],
    ) -> None:
        classified = classify_row(sheet_title, headers, values, row_number, category)
        if classified.review is not None:
            self.review_rows.append(classified.review)
        if classified.evidence is not None:
            self.evidence_rows.append(classified.evidence)

    def for_sheets(self, sheet_names: Iterable[str]) -> tuple[list[tuple], list[tuple]]:
        allowed = set(sheet_names)
        return (
            [row for row in self.review_rows if row[4] in allowed],
            [row for row in self.evidence_rows if row[4] in allowed],
        )


def _status(value: Any) -> str:
    value = getattr(value, "value", value)
    return str(value or "").strip().upper().replace(" ", "_")


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"yes", "true", "1", "manual", "required"}


def _requires_review(value: Any) -> bool:
    return _status(value) in {
        "PARTIALLY_NORMALIZED", "UNSUPPORTED", "PARSE_ERROR", "MANUAL",
        "PARTIAL", "UNRESOLVED",
    }


def _first(values: Sequence[Any], columns: Sequence[int], fallback: str) -> str:
    return next(
        (
            str(values[column - 1])
            for column in columns
            if column <= len(values) and values[column - 1] not in (None, "")
        ),
        fallback,
    )


def classify_row(
    sheet_title: str,
    headers: Sequence[str],
    values: Sequence[Any],
    row_number: int,
    category: Callable[[str], str],
) -> AuditClassification:
    if sheet_title in {"Summary", "Review Required", "Extraction Evidence"}:
        return AuditClassification()

    columns = {str(header or "").strip(): index for index, header in enumerate(headers, 1)}
    manual_column = columns.get("Manual Review")
    review_columns = [columns[name] for name in REVIEW_STATUS_HEADERS if name in columns]
    evidence_columns = [columns[name] for name in EVIDENCE_STATUS_HEADERS if name in columns]
    object_columns = [columns[name] for name in OBJECT_HEADERS if name in columns]
    reason_columns = [columns[name] for name in REASON_HEADERS if name in columns]
    review_values = [
        values[column - 1] for column in review_columns if column <= len(values)
    ]
    evidence_values = [
        values[column - 1] for column in evidence_columns if column <= len(values)
    ]
    manual_review = (
        manual_column is not None
        and manual_column <= len(values)
        and _truthy(values[manual_column - 1])
    )
    status_value = next((str(value) for value in review_values if value not in (None, "")), "")
    status_requires_review = any(_requires_review(value) for value in review_values)
    item = _first(values, object_columns, f"Row {row_number}")
    reason = _first(values, reason_columns, "Source-only configuration retained as extraction evidence.")
    try:
        row_category = category(sheet_title)
    except Exception:
        row_category = "Review"

    evidence = None
    if any(_status(value) == "EXTRACT_ONLY" for value in evidence_values):
        evidence = (row_category, item, reason, "Extract only", sheet_title, row_number)

    if not (sheet_title in AUDIT_SHEETS or manual_review or status_requires_review):
        return AuditClassification(evidence=evidence)
    if _status(status_value) == "EXTRACT_ONLY":
        return AuditClassification(evidence=evidence)
    issue = _first(values, reason_columns, status_value or "Manual review required")
    review = (row_category, item, issue, status_value or ("MANUAL" if manual_review else "REVIEW"), sheet_title, row_number)
    return AuditClassification(review=review, evidence=evidence)
