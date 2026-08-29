from __future__ import annotations

from typing import Dict, Optional

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


def extract_cisco_asa_config(
    text: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ExtractionResult:
    sections = scan_cisco_asa_sections(text)
    classify_cisco_asa_coverage(sections)
    parser = CiscoASAParser(text, zone_mapping=zone_mapping)
    ir = parser.transform_to_ir()
    config = parser.config
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
        safe_line = sanitize_raw_text(line)
        safe_parts = safe_line.split()
        inventory.append(SourceInventoryItem(
            domain="cisco_asa",
            source_path=next((s.path for s in sections if (s.line_start or 0) <= number <= (s.line_end or s.line_start or 0)), "other"),
            source_id=str(number),
            source_type="command",
            commands=[SourceCommand(
                operation=safe_parts[0].lower(),
                key=" ".join(safe_parts[:2]).lower(),
                values=safe_parts[2:],
            )],
            source_attributes={"line_number": number, "raw": safe_line},
            status=status,
            requires_manual_review=status in {ExtractionStatus.UNSUPPORTED, ExtractionStatus.PARSE_ERROR},
        ))
        if status == ExtractionStatus.UNSUPPORTED:
            unsupported.append(UnsupportedItem(
                source_path=inventory[-1].source_path,
                reason="Cisco ASA command is preserved but not safely normalized.",
                raw_capture=sanitize_raw_text(line),
            ))
    for item in config.unsupported_commands:
        unsupported.append(UnsupportedItem(
            source_path="other", source_name=f"line {item['line_number']}",
            reason=item["reason"], raw_capture=sanitize_raw_text(item["raw_line"]),
        ))
    return sanitize_extraction_result(ExtractionResult(
        canonical_ir=ir,
        source_sections=sections,
        inventory_items=inventory,
        unsupported_items=unsupported,
    ))
