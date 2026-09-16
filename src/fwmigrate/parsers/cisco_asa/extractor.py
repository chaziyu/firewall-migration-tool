from __future__ import annotations

from typing import Dict, Optional

from fwmigrate.extraction.models import ExtractionResult
from fwmigrate.extraction.sanitize import sanitize_extraction_result
from fwmigrate.parsers.cisco_asa.accounting import build_asa_source_accounting
from fwmigrate.parsers.cisco_asa.coverage import classify_cisco_asa_coverage
from fwmigrate.parsers.cisco_asa.stages import get_asa_parser_class
from fwmigrate.parsers.cisco_asa.transformer import ASAtoIRTransformer
from fwmigrate.parsers.cisco_asa.section_scanner import scan_cisco_asa_sections


def extract_cisco_asa_config(
    text: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ExtractionResult:
    sections = scan_cisco_asa_sections(text)
    classify_cisco_asa_coverage(sections)
    parser = get_asa_parser_class()(text, zone_mapping=zone_mapping)
    ir = ASAtoIRTransformer(parser).transform()
    config = parser.config
    inventory, unsupported = build_asa_source_accounting(text, sections, config)

    return sanitize_extraction_result(ExtractionResult(
        canonical_ir=ir,
        source_sections=sections,
        inventory_items=inventory,
        unsupported_items=unsupported,
    ))
