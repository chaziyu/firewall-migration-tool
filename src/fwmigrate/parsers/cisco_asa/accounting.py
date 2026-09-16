from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, Optional

from pydantic import BaseModel

from fwmigrate.extraction.models import (
    ExtractionStatus,
    SourceCommand,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)
from fwmigrate.extraction.sanitize import sanitize_raw_text


_SEVERITY = {
    ExtractionStatus.NORMALIZED: 0,
    ExtractionStatus.EXTRACT_ONLY: 1,
    ExtractionStatus.PARTIALLY_NORMALIZED: 2,
    ExtractionStatus.VENDOR_EXTENSION: 2,
    ExtractionStatus.UNSUPPORTED: 3,
    ExtractionStatus.PARSE_ERROR: 4,
    ExtractionStatus.IGNORED_BY_POLICY: 0,
}


def _status(value: Any) -> Optional[ExtractionStatus]:
    if value is None:
        return None
    try:
        return ExtractionStatus(value)
    except (TypeError, ValueError):
        return None


def _walk_models(value: Any, seen: Optional[set[int]] = None) -> Iterable[BaseModel]:
    seen = seen or set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        yield value
        for field_name in value.__class__.model_fields:
            yield from _walk_models(getattr(value, field_name, None), seen)
        return
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_models(child, seen)
        return
    if isinstance(value, (list, tuple, set)):
        for child in value:
            yield from _walk_models(child, seen)


def _record_line(record: BaseModel, source_positions: Dict[str, list[int]]) -> Optional[int]:
    for attribute in ("source_line_number", "source_order", "line_number"):
        value = getattr(record, attribute, None)
        if isinstance(value, int) and value > 0:
            return value
    source_attributes = getattr(record, "source_attributes", None)
    if isinstance(source_attributes, dict):
        for key in ("source_line_number", "line_number", "source_order"):
            value = source_attributes.get(key)
            if isinstance(value, int) and value > 0:
                return value
    raw_line = getattr(record, "raw_line", None)
    if not raw_line:
        raw_lines = getattr(record, "raw_lines", None)
        raw_line = raw_lines[0] if isinstance(raw_lines, list) and raw_lines else None
    positions = source_positions.get(sanitize_raw_text(str(raw_line)).strip(), []) if raw_line else []
    return positions[0] if len(positions) == 1 else None


def _set_worst(mapping: Dict[int, ExtractionStatus], line: int, status: ExtractionStatus) -> None:
    previous = mapping.get(line)
    if previous is None or _SEVERITY[status] > _SEVERITY[previous]:
        mapping[line] = status


def build_asa_source_accounting(
    text: str,
    sections: list[SourceSectionResult],
    config: Any,
) -> tuple[list[SourceInventoryItem], list[UnsupportedItem]]:
    """Build line inventory from the parsed source model and diagnostics."""
    source_positions: Dict[str, list[int]] = defaultdict(list)
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line and not line.startswith(("!", ":")):
            source_positions[sanitize_raw_text(line)].append(number)

    actual_status_by_line: Dict[int, ExtractionStatus] = {}
    review_by_line: Dict[int, bool] = {}
    for record in _walk_models(config):
        record_status = _status(getattr(record, "migration_status", None))
        line_number = _record_line(record, source_positions)
        if record_status is not None and line_number is not None:
            _set_worst(actual_status_by_line, line_number, record_status)
            if getattr(record, "requires_manual_review", False):
                review_by_line[line_number] = True

    diagnostics_by_line = {item.line_number: item for item in config.diagnostics}
    for diagnostic in config.diagnostics:
        diagnostic_status = _status(diagnostic.migration_effect) or ExtractionStatus.PARSE_ERROR
        _set_worst(actual_status_by_line, diagnostic.line_number, diagnostic_status)
        review_by_line[diagnostic.line_number] = True

    for section in sections:
        actual = [
            status for number, status in actual_status_by_line.items()
            if (section.line_start or 0) <= number <= (section.line_end or section.line_start or 0)
        ]
        if actual:
            worst = max([section.status, *actual], key=lambda item: _SEVERITY[item])
            section.status = worst
            if worst == ExtractionStatus.PARSE_ERROR:
                section.notes.append("A recognized command in this section failed safe parsing.")

    status_by_line = {
        line: section.status
        for section in sections
        for line in range(section.line_start or 0, (section.line_end or section.line_start or 0) + 1)
    }
    inventory = []
    unsupported = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("!", ":")):
            continue
        status = status_by_line.get(number, ExtractionStatus.UNSUPPORTED)
        actual = actual_status_by_line.get(number)
        if actual is not None and _SEVERITY[actual] > _SEVERITY[status]:
            status = actual
        safe_line = sanitize_raw_text(line)
        safe_parts = safe_line.split()
        requires_review = review_by_line.get(number, False) or status in {
            ExtractionStatus.PARTIALLY_NORMALIZED,
            ExtractionStatus.UNSUPPORTED,
            ExtractionStatus.PARSE_ERROR,
            ExtractionStatus.VENDOR_EXTENSION,
        }
        source_path = next(
            (s.path for s in sections if (s.line_start or 0) <= number <= (s.line_end or s.line_start or 0)),
            "other",
        )
        inventory.append(SourceInventoryItem(
            domain="cisco_asa",
            source_path=source_path,
            source_id=str(number),
            source_type="command",
            commands=[SourceCommand(
                operation=safe_parts[0].lower(),
                key=" ".join(safe_parts[:2]).lower(),
                values=safe_parts[2:],
                line_number=number,
                status=status,
                parser_handler="CiscoASAParser.parse_raw" if status != ExtractionStatus.UNSUPPORTED else None,
                requires_manual_review=requires_review,
            )],
            source_attributes={"line_number": number, "raw": safe_line},
            status=status,
            requires_manual_review=requires_review,
            notes=([diagnostics_by_line[number].reason] if number in diagnostics_by_line else []),
        ))
        if status == ExtractionStatus.UNSUPPORTED:
            unsupported.append(UnsupportedItem(
                source_path=source_path,
                reason="Cisco ASA command is preserved but not safely normalized.",
                raw_capture=safe_line,
            ))

    for item in config.unsupported_commands:
        unsupported.append(UnsupportedItem(
            source_path="other",
            source_name=f"line {item['line_number']}",
            reason=item["reason"],
            raw_capture=sanitize_raw_text(item["raw_line"]),
        ))
    return inventory, unsupported


__all__ = ["build_asa_source_accounting"]
