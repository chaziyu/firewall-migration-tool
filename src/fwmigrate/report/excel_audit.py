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
NON_AUDIT_SHEETS = frozenset({"Summary", "Review Required", "Extraction Evidence"})


@dataclass(frozen=True)
class AuditClassification:
    review: tuple[str, str, str, str, str, int] | None = None
    evidence: tuple[str, str, str, str, str, int] | None = None


@dataclass(frozen=True)
class AuditSheetClassifier:
    """Header-derived audit metadata reused for every row in one worksheet."""

    sheet_title: str
    category: str
    manual_column: int | None
    review_columns: tuple[int, ...]
    evidence_columns: tuple[int, ...]
    object_columns: tuple[int, ...]
    reason_columns: tuple[int, ...]
    audit_sheet: bool
    can_produce_review: bool
    can_produce_evidence: bool

    def classify(
        self,
        values: Sequence[Any],
        row_number: int,
    ) -> AuditClassification:
        if not self.can_produce_review and not self.can_produce_evidence:
            return AuditClassification()

        manual_review = (
            self.manual_column is not None
            and self.manual_column <= len(values)
            and _truthy(values[self.manual_column - 1])
        )
        status_value = next(
            (
                str(values[column - 1])
                for column in self.review_columns
                if column <= len(values) and values[column - 1] not in (None, "")
            ),
            "",
        )
        status_requires_review = any(
            _requires_review(values[column - 1])
            for column in self.review_columns
            if column <= len(values)
        )
        evidence_found = any(
            _status(values[column - 1]) == "EXTRACT_ONLY"
            for column in self.evidence_columns
            if column <= len(values)
        )

        if not (self.audit_sheet or manual_review or status_requires_review or evidence_found):
            return AuditClassification()

        item = _first(values, self.object_columns, f"Row {row_number}")
        reason = _first(
            values,
            self.reason_columns,
            "Source-only configuration retained as extraction evidence.",
        )
        evidence = (
            self.category,
            item,
            reason,
            "Extract only",
            self.sheet_title,
            row_number,
        ) if evidence_found else None

        if _status(status_value) == "EXTRACT_ONLY":
            return AuditClassification(evidence=evidence)
        issue = _first(
            values,
            self.reason_columns,
            status_value or "Manual review required",
        )
        review = (
            self.category,
            item,
            issue,
            status_value or ("MANUAL" if manual_review else "REVIEW"),
            self.sheet_title,
            row_number,
        )
        return AuditClassification(review=review, evidence=evidence)


def build_audit_classifier(
    sheet_title: str,
    headers: Sequence[str],
    category: Callable[[str], str],
) -> AuditSheetClassifier:
    columns = {
        str(header or "").strip(): index
        for index, header in enumerate(headers, 1)
    }
    try:
        row_category = category(sheet_title)
    except Exception:
        row_category = "Review"
    manual_column = columns.get("Manual Review")
    review_columns = tuple(
        columns[name] for name in REVIEW_STATUS_HEADERS if name in columns
    )
    evidence_columns = tuple(
        columns[name] for name in EVIDENCE_STATUS_HEADERS if name in columns
    )
    audit_sheet = sheet_title in AUDIT_SHEETS
    audit_enabled = sheet_title not in NON_AUDIT_SHEETS
    return AuditSheetClassifier(
        sheet_title=sheet_title,
        category=row_category,
        manual_column=manual_column,
        review_columns=review_columns,
        evidence_columns=evidence_columns,
        object_columns=tuple(
            columns[name] for name in OBJECT_HEADERS if name in columns
        ),
        reason_columns=tuple(
            columns[name] for name in REASON_HEADERS if name in columns
        ),
        audit_sheet=audit_sheet,
        can_produce_review=audit_enabled and (
            audit_sheet or manual_column is not None or bool(review_columns)
        ),
        can_produce_evidence=audit_enabled and bool(evidence_columns),
    )


@dataclass
class ExcelAuditAccumulator:
    """Collect only actionable audit rows while inventory rows are written."""

    review_rows: list[tuple[str, str, str, str, str, int]] = field(default_factory=list)
    evidence_rows: list[tuple[str, str, str, str, str, int]] = field(default_factory=list)
    _classifiers: dict[tuple[str, tuple[str, ...]], AuditSheetClassifier] = field(
        default_factory=dict,
        repr=False,
    )

    def add_row(
        self,
        sheet_title: str,
        headers: Sequence[str],
        values: Sequence[Any],
        row_number: int,
        category: Callable[[str], str],
        classifier: AuditSheetClassifier | None = None,
    ) -> None:
        key = (sheet_title, tuple(headers))
        if classifier is None:
            classifier = self._classifiers.get(key)
            if classifier is None:
                classifier = build_audit_classifier(sheet_title, headers, category)
        self._classifiers[key] = classifier
        if not classifier.can_produce_review and not classifier.can_produce_evidence:
            return
        classified = classifier.classify(values, row_number)
        if classified.review is not None:
            self.review_rows.append(classified.review)
        if classified.evidence is not None:
            self.evidence_rows.append(classified.evidence)

    def rename_sheet(self, old_title: str, new_title: str) -> None:
        if old_title == new_title:
            return
        for attribute in ("review_rows", "evidence_rows"):
            rows = getattr(self, attribute)
            setattr(
                self,
                attribute,
                [
                    (*row[:4], new_title, *row[5:])
                    if row[4] == old_title
                    else row
                    for row in rows
                ],
            )
        for key, classifier in tuple(self._classifiers.items()):
            if key[0] == old_title:
                self._classifiers.pop(key)
                self._classifiers[(new_title, key[1])] = AuditSheetClassifier(
                    sheet_title=new_title,
                    category=classifier.category,
                    manual_column=classifier.manual_column,
                    review_columns=classifier.review_columns,
                    evidence_columns=classifier.evidence_columns,
                    object_columns=classifier.object_columns,
                    reason_columns=classifier.reason_columns,
                    audit_sheet=classifier.audit_sheet,
                    can_produce_review=classifier.can_produce_review,
                    can_produce_evidence=classifier.can_produce_evidence,
                )

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
    return build_audit_classifier(sheet_title, headers, category).classify(
        values,
        row_number,
    )
