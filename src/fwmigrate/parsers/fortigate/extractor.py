"""High-level FortiGate source extraction orchestration."""

from __future__ import annotations

from typing import Dict, Optional

from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    UnsupportedItem,
)
from fwmigrate.parsers.fortigate.coverage import (
    classify_section_coverage,
    extract_only_requires_manual_review,
)
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.section_scanner import scan_fortigate_sections
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def extract_fortigate_config(
    text: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ExtractionResult:
    source_sections = scan_fortigate_sections(text)

    parser = FortiGateParser(FortiGateTokenizer(text))
    fg_config = parser.parse()
    ir_config = FGToIRTransformer(fg_config, zone_mapping=zone_mapping or {}).transform()

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
        ) or item.source_path in {
            "firewall policy",
            "firewall ippool",
            "firewall ippool6",
            "firewall vip",
            "firewall vip realservers",
            "firewall vip6",
            "firewall vip6 realservers",
            "firewall vipgrp",
            "firewall vipgrp6",
        }:
            item.status = status
            item.requires_manual_review = (
                status == ExtractionStatus.UNSUPPORTED
                or "structured-security-profile" in item.notes
                or extract_only_requires_manual_review(item.source_path)
            )
            inventory_items.append(item)

    unsupported_items = [
        UnsupportedItem(
            source_path=section.path,
            reason=f"FortiGate section '{section.path}' is not supported for canonical migration.",
            requires_manual_review=True,
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
