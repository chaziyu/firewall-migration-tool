from __future__ import annotations

from fwmigrate.extraction.models import (
    ExtractionResult,
    SourceCommand,
    SourceInventoryItem,
    SourceSectionResult,
    ExtractionStatus,
    UnsupportedItem,
)
from fwmigrate.extraction.sanitize import sanitize_extraction_result, sanitize_raw_text
from fwmigrate.parsers.cisco_ftd.coverage import classify_cisco_ftd_coverage
from fwmigrate.parsers.cisco_ftd.fmc_bundle import CiscoFMCBundleParser, is_fmc_bundle
from fwmigrate.parsers.cisco_ftd.parser import CiscoFTDParser
from fwmigrate.parsers.cisco_ftd.section_scanner import scan_cisco_ftd_sections


def _status(value: str, requires_review: bool = False) -> ExtractionStatus:
    normalized = str(value or "NORMALIZED").upper()
    if normalized == "NORMALIZED" and not requires_review:
        return ExtractionStatus.NORMALIZED
    if normalized == "PARSE_ERROR":
        return ExtractionStatus.PARSE_ERROR
    if normalized == "EXTRACT_ONLY":
        return ExtractionStatus.EXTRACT_ONLY
    return ExtractionStatus.PARTIALLY_NORMALIZED


def _extract_fmc_bundle(text: str) -> ExtractionResult:
    parser = CiscoFMCBundleParser(text)
    ir = parser.parse()
    inventory: list[SourceInventoryItem] = []

    def add(items, path: str, source_type: str) -> None:
        for index, item in enumerate(items, 1):
            name = getattr(item, "name", None) or str(index)
            status = _status(
                getattr(item, "migration_status", "NORMALIZED"),
                getattr(item, "requires_manual_review", False),
            )
            inventory.append(SourceInventoryItem(
                domain="cisco_ftd",
                domain_uid=parser.domain_id,
                domain_name=parser.domain_name,
                source_path=path,
                name=name,
                source_id=str(getattr(item, "source_uuid", None) or getattr(item, "source_rule_id", None) or name),
                source_type=source_type,
                source_context=getattr(item, "source_context", None),
                source_attributes={
                    "migration_status": getattr(item, "migration_status", "NORMALIZED"),
                    "requires_manual_review": getattr(item, "requires_manual_review", False),
                },
                status=status,
                requires_manual_review=getattr(item, "requires_manual_review", False),
            ))

    add(ir.addresses, "fmc/objects/network", "network-object")
    add(ir.address_groups, "fmc/objects/network-groups", "network-group")
    add(ir.services, "fmc/objects/ports", "port-object")
    add(ir.service_groups, "fmc/objects/port-groups", "port-object-group")
    add(ir.zones, "fmc/objects/security-zones", "security-zone")
    add(ir.applications, "fmc/objects/applications", "application")
    add(ir.policies, "fmc/access-policies", "access-rule")
    add(ir.nat_rules, "fmc/nat-policies", "nat-rule")

    object_count = sum(len(values) for values in (
        ir.addresses, ir.address_groups, ir.services, ir.service_groups, ir.zones, ir.applications,
    ))
    sections = [
        SourceSectionResult(
            path="fmc/objects", source_context=parser.context,
            status=ExtractionStatus.NORMALIZED,
            object_count_source=object_count,
            object_count_parsed=object_count,
            object_count_normalized=sum(1 for item in inventory if item.source_path.startswith("fmc/objects") and item.status == ExtractionStatus.NORMALIZED),
        ),
        SourceSectionResult(
            path="fmc/access-policies", source_context=parser.context,
            status=(ExtractionStatus.PARTIALLY_NORMALIZED if any(item.requires_manual_review for item in ir.policies) else ExtractionStatus.NORMALIZED),
            object_count_source=len(ir.policies), object_count_parsed=len(ir.policies),
            object_count_normalized=sum(1 for item in ir.policies if not item.requires_manual_review),
        ),
        SourceSectionResult(
            path="fmc/nat-policies", source_context=parser.context,
            status=(ExtractionStatus.PARTIALLY_NORMALIZED if any(item.requires_manual_review for item in ir.nat_rules) else ExtractionStatus.NORMALIZED),
            object_count_source=len(ir.nat_rules), object_count_parsed=len(ir.nat_rules),
            object_count_normalized=sum(1 for item in ir.nat_rules if not item.requires_manual_review),
        ),
    ]

    unresolved = parser.unresolved_references
    unsupported = [
        UnsupportedItem(
            source_path="fmc/reference-resolution",
            source_name=str(item.get("owner") or item.get("reference") or "reference"),
            source_context=parser.context,
            reason=f"Unresolved FMC reference in {item.get('field') or 'unknown field'}",
            raw_capture=sanitize_raw_text(str(item)),
        )
        for item in unresolved if isinstance(item, dict)
    ]

    if unresolved:
        ir.generation_safe = False
        reason = "Unresolved FMC object/policy reference"
        if reason not in ir.generation_blocking_reasons:
            ir.generation_blocking_reasons.append(reason)

    return sanitize_extraction_result(ExtractionResult(
        canonical_ir=ir,
        source_sections=sections,
        inventory_items=inventory,
        unsupported_items=unsupported,
        requires_manual_review=bool(unsupported) or any(item.requires_manual_review for item in [*ir.policies, *ir.nat_rules]),
        migration_complete=not bool(unsupported),
        generation_safe=ir.generation_safe and not bool(unsupported),
        blocking_reasons=list(ir.generation_blocking_reasons),
    ))


def extract_cisco_ftd_config(text: str) -> ExtractionResult:
    if is_fmc_bundle(text):
        return _extract_fmc_bundle(text)

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
