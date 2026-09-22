from __future__ import annotations

from typing import Any

from fwmigrate.extraction.models import (
    ExtractionResult,
    SourceCommand,
    SourceInventoryItem,
    SourceSectionResult,
    ExtractionStatus,
    UnsupportedItem,
)
from fwmigrate.extraction.sanitize import sanitize_extraction_result, sanitize_raw_text
from .cli.coverage import classify_cisco_ftd_coverage
from .fmc.fmc_adapter import CiscoFMCBundleParser, is_fmc_bundle
from .fdm.fdm_adapter import CiscoFDMBundleParser, is_fdm_bundle
from .cli.parser import (
    FTD_TEXT_GENERATION_BLOCK_REASON,
    CiscoFTDParser,
)
from .cli.section_scanner import scan_cisco_ftd_sections


def _status(value: str, requires_review: bool = False) -> ExtractionStatus:
    normalized = str(value or "NORMALIZED").upper()
    if normalized == "NORMALIZED" and not requires_review:
        return ExtractionStatus.NORMALIZED
    if normalized == "PARSE_ERROR":
        return ExtractionStatus.PARSE_ERROR
    if normalized == "EXTRACT_ONLY":
        return ExtractionStatus.EXTRACT_ONLY
    return ExtractionStatus.PARTIALLY_NORMALIZED


def _bundle_items(value: Any) -> list[dict]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict) and isinstance(value.get("items"), list):
        return [item for item in value["items"] if isinstance(item, dict)]
    return []


def _classify_ftd_input_source(text: str) -> str:
    if is_fmc_bundle(text):
        return "fmc-rest-bundle"
    if is_fdm_bundle(text):
        return "fdm-rest-bundle"
    return "ftd-text-evidence"


def _extract_fmc_bundle(
    text: str,
    *,
    zone_mapping: dict[str, str] | None = None,
) -> ExtractionResult:
    # FMC zones are authoritative source objects; caller mappings apply only
    # to the text evidence adapter.
    parser = CiscoFMCBundleParser(text)
    ir = parser.parse()
    source_config = parser.parse_source()
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
                source_id=str(getattr(item, "source_id", None) or name),
                source_type=source_type,
                source_context=getattr(item, "source_context", None),
                source_attributes={
                    "source_plane": getattr(item, "source_plane", "fmc-rest-bundle"),
                    **getattr(item, "source_attributes", {}),
                },
                status=status,
                requires_manual_review=getattr(item, "requires_manual_review", False),
            ))

    add(source_config.managed_objects, "fmc/objects", "object")
    add(source_config.object_groups, "fmc/objects/network-groups", "network-group")
    add(source_config.services, "fmc/objects/services", "service")
    add(source_config.security_zones, "fmc/objects/security-zones", "security-zone")
    add(source_config.acp_rules, "fmc/access-policies", "access-rule")
    add(source_config.nat_policies, "fmc/nat-policies", "nat-rule")

    raw_objects = parser._object_collections()

    source_object_count = sum(len(values) for values in raw_objects.values())
    parsed_object_count = sum(
        1 for item in inventory if item.source_path.startswith("fmc/objects")
    )
    normalized_object_count = sum(
        1
        for item in inventory
        if item.source_path.startswith("fmc/objects")
        and item.status == ExtractionStatus.NORMALIZED
    )

    access_source_count = 0
    for policy in _bundle_items(parser.payload.get("access_policies")):
        access_source_count += len(_bundle_items(policy.get("rules")))
        if isinstance(policy.get("defaultAction"), dict) and policy.get("defaultAction"):
            access_source_count += 1

    nat_source_count = 0
    for policy in _bundle_items(parser.payload.get("nat_policies")):
        before = _bundle_items(policy.get("manual_rules_before_auto"))
        after = _bundle_items(policy.get("manual_rules_after_auto"))
        manual = _bundle_items(policy.get("manual_rules"))
        auto = _bundle_items(policy.get("auto_rules"))
        nat_source_count += len(auto)
        nat_source_count += len(manual) if manual and not before and not after else len(before) + len(after)

    pbr_source_count = sum(
        len(_bundle_items(policy.get("rules") or policy.get("items"))) or 1
        for policy in _bundle_items(
            parser.payload.get("pbr_policies") or parser.payload.get("policy_routes") or parser.payload.get("pbr_rules")
        )
    )

    unresolved = parser.unresolved_references
    unsupported = [
        UnsupportedItem(
            source_path="fmc/reference-resolution",
            source_name=str(item.get("owner") or item.get("reference") or "reference"),
            source_context=parser.context,
            reason=f"Unresolved FMC reference in {item.get('field') or 'unknown field'}",
            raw_capture=sanitize_raw_text(str(item)),
        )
        for item in unresolved
        if isinstance(item, dict)
    ]

    object_partial = bool(unsupported) or parsed_object_count < source_object_count
    sections = [
        SourceSectionResult(
            path="fmc/objects",
            source_context=parser.context,
            status=(
                ExtractionStatus.PARTIALLY_NORMALIZED
                if object_partial
                else ExtractionStatus.NORMALIZED
            ),
            object_count_source=source_object_count,
            object_count_parsed=parsed_object_count,
            object_count_normalized=normalized_object_count,
        ),
        SourceSectionResult(
            path="fmc/access-policies",
            source_context=parser.context,
            status=(
                ExtractionStatus.PARTIALLY_NORMALIZED
                if any(item.requires_manual_review for item in ir.policies)
                or len(ir.policies) < access_source_count
                else ExtractionStatus.NORMALIZED
            ),
            object_count_source=access_source_count,
            object_count_parsed=len(ir.policies),
            object_count_normalized=sum(
                1 for item in ir.policies if not item.requires_manual_review
            ),
        ),
        SourceSectionResult(
            path="fmc/nat-policies",
            source_context=parser.context,
            status=(
                ExtractionStatus.PARTIALLY_NORMALIZED
                if any(item.requires_manual_review for item in ir.nat_rules)
                or len(ir.nat_rules) < nat_source_count
                else ExtractionStatus.NORMALIZED
            ),
            object_count_source=nat_source_count,
            object_count_parsed=len(ir.nat_rules),
            object_count_normalized=sum(
                1 for item in ir.nat_rules if not item.requires_manual_review
            ),
        ),
    ]
    if pbr_source_count:
        sections.append(SourceSectionResult(
            path="fmc/policy-based-routing",
            source_context=parser.context,
            status=(
                ExtractionStatus.PARTIALLY_NORMALIZED
                if any(item.requires_manual_review for item in ir.policy_route_rules)
                or len(ir.policy_route_rules) < pbr_source_count
                else ExtractionStatus.NORMALIZED
            ),
            object_count_source=pbr_source_count,
            object_count_parsed=len(ir.policy_route_rules),
            object_count_normalized=sum(1 for item in ir.policy_route_rules if not item.requires_manual_review),
        ))

    if unresolved:
        ir.generation_safe = False
        reason = "Unresolved FMC object/policy reference"
        if reason not in ir.generation_blocking_reasons:
            ir.generation_blocking_reasons.append(reason)

    requires_review = bool(unsupported) or any(
        item.requires_manual_review for item in [*ir.policies, *ir.nat_rules]
    )
    return sanitize_extraction_result(ExtractionResult(
        canonical_ir=ir,
        source_sections=sections,
        inventory_items=inventory,
        unsupported_items=unsupported,
        requires_manual_review=requires_review,
        migration_complete=not requires_review,
        generation_safe=ir.generation_safe and not bool(unsupported),
        blocking_reasons=list(ir.generation_blocking_reasons),
        input_source_type="fmc-rest-bundle",
        policy_extraction_supported=True,
        nat_extraction_supported=True,
        object_extraction_supported=True,
    ))


def _extract_fdm_bundle(
    text: str,
    *,
    zone_mapping: dict[str, str] | None = None,
) -> ExtractionResult:
    # FDM zones are authoritative source objects; caller mappings apply only
    # to the text evidence adapter.
    parser = CiscoFDMBundleParser(text)
    ir = parser.parse()
    source_config = parser.parse_source()
    inventory: list[SourceInventoryItem] = []

    def add(items: list[Any], path: str, source_type: str) -> None:
        for index, item in enumerate(items, 1):
            review = bool(getattr(item, "requires_manual_review", False))
            inventory.append(SourceInventoryItem(
                domain="cisco_ftd", domain_uid=parser.domain_id, domain_name=parser.domain_name,
                source_path=path, name=getattr(item, "name", None) or str(index),
                source_id=str(getattr(item, "source_id", None) or index),
                source_type=source_type, source_context=getattr(item, "source_context", parser.context),
                source_attributes={
                    "source_plane": getattr(item, "source_plane", "fdm-rest-bundle"),
                    **getattr(item, "source_attributes", {}),
                },
                status=_status(getattr(item, "migration_status", "NORMALIZED"), review),
                requires_manual_review=review,
            ))

    add(source_config.managed_objects, "fdm/objects", "object")
    add(source_config.object_groups, "fdm/objects/network-groups", "network-group")
    add(source_config.services, "fdm/objects/services", "service")
    add(source_config.source_interfaces, "fdm/interfaces", "interface")
    add(source_config.security_zones, "fdm/zones", "security-zone")
    add(source_config.nat_policies, "fdm/nat-policies", "nat-rule")

    unresolved = parser.unresolved_references
    unsupported = [
        UnsupportedItem(
            source_path="fdm/reference-resolution",
            source_name=str(item.get("owner") or item.get("reference") or "reference"),
            source_context=parser.context,
            reason=str(
                item.get("reason")
                or f"Unresolved FDM reference in {item.get('field') or 'unknown field'}"
            ),
            raw_capture=sanitize_raw_text(str(item)),
        )
        for item in unresolved
    ]

    source_object_count = sum(len(parser._collection(*names)) for names in (
        ("hosts", "network_hosts"),
        ("networks", "network_objects"),
        ("ranges", "network_ranges"),
        ("network_groups", "networkgroups"),
        ("services", "service_objects"),
        ("service_groups", "servicegroups"),
    ))
    parsed_object_items = [
        item for item in inventory if item.source_path.startswith("fdm/objects")
    ]
    parsed_object_count = len(parsed_object_items)
    normalized_object_count = sum(
        1 for item in parsed_object_items if item.status == ExtractionStatus.NORMALIZED
    )
    object_partial = (
        parsed_object_count < source_object_count
        or any(item.requires_manual_review for item in parsed_object_items)
    )

    sections = [
        SourceSectionResult(
            path="fdm/objects", source_context=parser.context,
            status=(
                ExtractionStatus.PARTIALLY_NORMALIZED
                if object_partial else ExtractionStatus.NORMALIZED
            ),
            object_count_source=source_object_count,
            object_count_parsed=parsed_object_count,
            object_count_normalized=normalized_object_count,
        ),
        SourceSectionResult(
            path="fdm/nat-policies", source_context=parser.context,
            status=ExtractionStatus.PARTIALLY_NORMALIZED if any(item.requires_manual_review for item in ir.nat_rules) else ExtractionStatus.NORMALIZED,
            object_count_source=len(ir.nat_rules), object_count_parsed=len(ir.nat_rules),
            object_count_normalized=sum(1 for item in ir.nat_rules if not item.requires_manual_review),
        ),
    ]
    requires_review = bool(unsupported) or any(item.requires_manual_review for item in inventory)
    return sanitize_extraction_result(ExtractionResult(
        canonical_ir=ir, source_sections=sections, inventory_items=inventory,
        unsupported_items=unsupported, requires_manual_review=requires_review,
        migration_complete=not requires_review,
        generation_safe=ir.generation_safe and not bool(unsupported),
        blocking_reasons=list(ir.generation_blocking_reasons),
        input_source_type="fdm-rest-bundle",
        policy_extraction_supported=True, nat_extraction_supported=True,
        object_extraction_supported=True,
    ))


def extract_cisco_ftd_config(
    text: str,
    zone_mapping: dict[str, str] | None = None,
) -> ExtractionResult:
    input_source = _classify_ftd_input_source(text)
    if input_source == "fmc-rest-bundle":
        return _extract_fmc_bundle(text, zone_mapping=zone_mapping)
    if input_source == "fdm-rest-bundle":
        return _extract_fdm_bundle(text, zone_mapping=zone_mapping)

    sections = scan_cisco_ftd_sections(text)
    classify_cisco_ftd_coverage(sections)
    ir = CiscoFTDParser(text, zone_mapping=zone_mapping).parse()
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
            domain="cisco_ftd",
            source_path=section.path if section else "other",
            source_id=str(number),
            source_type="command",
            commands=[SourceCommand(
                operation=safe.split()[0].lower(),
                key=" ".join(safe.split()[:2]).lower(),
                values=safe.split()[2:],
            )],
            source_attributes={"line_number": number, "raw": safe},
            status=status,
            requires_manual_review=status != ExtractionStatus.NORMALIZED,
        ))
        if status == ExtractionStatus.UNSUPPORTED:
            unsupported.append(UnsupportedItem(
                source_path="other",
                source_name=str(number),
                reason="FTD input syntax is not yet verified",
                raw_capture=safe,
            ))
    if FTD_TEXT_GENERATION_BLOCK_REASON not in ir.generation_blocking_reasons:
        ir.generation_blocking_reasons.append(FTD_TEXT_GENERATION_BLOCK_REASON)
    ir.generation_safe = False
    has_unsupported_policy_syntax = any(
        item.source_path == "other"
        and item.commands
        and item.commands[0].operation in {"access-list", "nat", "object", "policy-map", "class-map", "service-policy"}
        for item in inventory
    )
    if has_unsupported_policy_syntax:
        reason = "FTD text contains policy/NAT syntax that is retained as unsupported evidence"
        if reason not in ir.generation_blocking_reasons:
            ir.generation_blocking_reasons.append(reason)
    return sanitize_extraction_result(ExtractionResult(
        canonical_ir=ir,
        source_sections=sections,
        inventory_items=inventory,
        unsupported_items=unsupported,
        requires_manual_review=True,
        migration_complete=False,
        generation_safe=False,
        blocking_reasons=list(ir.generation_blocking_reasons),
        input_source_type=input_source,
        policy_extraction_supported=False,
        nat_extraction_supported=False,
        object_extraction_supported=False,
    ))
