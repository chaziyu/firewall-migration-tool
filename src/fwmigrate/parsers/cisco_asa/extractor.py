from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, Optional

from pydantic import BaseModel

from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    SourceCommand,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.extraction.sanitize import sanitize_extraction_result, sanitize_raw_text
from fwmigrate.parsers.cisco_asa.coverage import classify_cisco_asa_coverage
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser
from fwmigrate.parsers.cisco_asa.section_scanner import scan_cisco_asa_sections


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
    """Walk the parsed ASA source model, including nested MPF/HA/context records."""
    seen = seen or set()
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in seen:
            return
        seen.add(identity)
        yield value
        for field_name in value.__class__.model_fields:
            child = getattr(value, field_name, None)
            yield from _walk_models(child, seen)
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
    if raw_line:
        positions = source_positions.get(sanitize_raw_text(str(raw_line)).strip(), [])
        if len(positions) == 1:
            return positions[0]
    return None


def _set_worst(mapping: Dict[int, ExtractionStatus], line: int, status: ExtractionStatus) -> None:
    previous = mapping.get(line)
    if previous is None or _SEVERITY[status] > _SEVERITY[previous]:
        mapping[line] = status


def extract_cisco_asa_config(
    text: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ExtractionResult:
    sections = scan_cisco_asa_sections(text)
    classify_cisco_asa_coverage(sections)
    parser = CiscoASAParser(text, zone_mapping=zone_mapping)
    ir = parser.transform_to_ir()
    config = parser.config

    source_positions: Dict[str, list[int]] = defaultdict(list)
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line and not line.startswith(("!", ":")):
            source_positions[sanitize_raw_text(line)].append(number)

    # Phase 17.3: derive actual parser status from the complete source model,
    # not only ACL/NAT. This includes interfaces, objects/groups, routing, VPN,
    # AAA, MPF, DHCP/DNS, management, HA and context records, including nested
    # child records with their own source_order.
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

    # Parser-level unsupported evidence is also authoritative. Static coverage
    # must not make a recognized-but-unsupported command look partially
    # normalized simply because the top-level keyword is known.
    for item in config.unsupported_commands:
        line_number = item.get("line_number")
        if isinstance(line_number, int) and line_number > 0:
            _set_worst(actual_status_by_line, line_number, ExtractionStatus.UNSUPPORTED)
            review_by_line[line_number] = True

    # A malformed recognized child makes its owning section PARSE_ERROR. Parent
    # records that became PARSE_ERROR because of a child also contribute through
    # their header line above.
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

    return sanitize_extraction_result(ExtractionResult(
        canonical_ir=ir,
        source_sections=sections,
        inventory_items=inventory,
        unsupported_items=unsupported,
    ))
