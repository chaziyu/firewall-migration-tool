from __future__ import annotations

from fwmigrate.extraction.models import ExtractionResult, SourceCommand, SourceInventoryItem, ExtractionStatus, UnsupportedItem
from fwmigrate.extraction.sanitize import sanitize_extraction_result, sanitize_raw_text
from fwmigrate.parsers.cisco_ftd.coverage import classify_cisco_ftd_coverage
from fwmigrate.parsers.cisco_ftd.parser import CiscoFTDParser
from fwmigrate.parsers.cisco_ftd.section_scanner import scan_cisco_ftd_sections


def extract_cisco_ftd_config(text: str) -> ExtractionResult:
    sections = scan_cisco_ftd_sections(text)
    classify_cisco_ftd_coverage(sections)
    ir = CiscoFTDParser(text).parse()
    inventory = []
    unsupported = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("!", ":", "#")):
            continue
        safe = sanitize_raw_text(line)
        section = next((s for s in sections if s.line_start == number), None)
        status = section.status if section else ExtractionStatus.UNSUPPORTED
        inventory.append(SourceInventoryItem(
            domain="cisco_ftd", source_path=section.path if section else "other",
            source_id=str(number), source_type="command",
            commands=[SourceCommand(operation=safe.split()[0].lower(), key=" ".join(safe.split()[:2]).lower(), values=safe.split()[2:])],
            source_attributes={"line_number": number, "raw": safe}, status=status,
            requires_manual_review=True,
        ))
        if status == ExtractionStatus.UNSUPPORTED:
            unsupported.append(UnsupportedItem(source_path="other", source_name=str(number), reason="FTD input syntax is not yet verified", raw_capture=safe))
    return sanitize_extraction_result(ExtractionResult(canonical_ir=ir, source_sections=sections, inventory_items=inventory, unsupported_items=unsupported))
