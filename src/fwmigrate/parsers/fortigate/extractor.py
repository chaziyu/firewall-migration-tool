"""High-level FortiGate source extraction orchestration."""

from __future__ import annotations

from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    UnsupportedItem,
)
from fwmigrate.parsers.fortigate.coverage import classify_section_coverage
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.section_scanner import scan_fortigate_sections
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def extract_fortigate_config(text: str) -> ExtractionResult:
    source_sections = scan_fortigate_sections(text)

    parser = FortiGateParser(FortiGateTokenizer(text))
    fg_config = parser.parse()
    ir_config = FGToIRTransformer(fg_config).transform()

    classify_section_coverage(source_sections, fg_config, ir_config)
    status_by_path = {section.path: section.status for section in source_sections}

    inventory_items = []
    for item in parser.source_inventory_items:
        status = status_by_path.get(item.source_path, ExtractionStatus.UNSUPPORTED)
        has_source_only_operation = any(
            command.operation in {"unset", "append"}
            for command in item.commands
        )
        if status in {
            ExtractionStatus.EXTRACT_ONLY,
            ExtractionStatus.VENDOR_EXTENSION,
            ExtractionStatus.UNSUPPORTED,
        } or has_source_only_operation or (
            status == ExtractionStatus.PARTIALLY_NORMALIZED
            and item.name is None
        ):
            item.status = status
            item.requires_manual_review = status == ExtractionStatus.UNSUPPORTED
            inventory_items.append(item)

    unsupported_items = [
        UnsupportedItem(
            source_path=section.path,
            reason="No typed FortiGate extraction handler is registered for this source section.",
        )
        for section in source_sections
        if section.status == ExtractionStatus.UNSUPPORTED
    ]

    return ExtractionResult(
        canonical_ir=ir_config,
        source_sections=source_sections,
        inventory_items=inventory_items,
        unsupported_items=unsupported_items,
    )
