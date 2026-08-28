"""Main extraction pipeline for Check Point R81 configurations."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)
from fwmigrate.extraction.sanitize import sanitize_extraction_result
from fwmigrate.ir.core import IRConfig, IRMetadata, IRZone
from fwmigrate.parsers.checkpoint.access import extract_access_rulebase
from fwmigrate.parsers.checkpoint.coverage import create_section_result
from fwmigrate.parsers.checkpoint.gaia import parse_gaia_configuration
from fwmigrate.parsers.checkpoint.loader import (
    build_rulebase_safety_map,
    canonicalize_command,
    group_response_pages,
    load_checkpoint_input,
    validate_pagination,
)
from fwmigrate.parsers.checkpoint.models import CheckPointExportBundle, ScopeSelectionResult
from fwmigrate.parsers.checkpoint.nat import extract_nat_rulebase
from fwmigrate.parsers.checkpoint.objects import extract_address_objects
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver, SemanticKind
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase
from fwmigrate.parsers.checkpoint.schedules import extract_time_objects
from fwmigrate.parsers.checkpoint.services import extract_service_objects


def extract_checkpoint_config(
    content: str,
    zone_mapping: Optional[Dict[str, str]] = None,
) -> ExtractionResult:
    """
    Extract Check Point configuration into a comprehensive ExtractionResult
    containing canonical IR, source sections, leaf inventory items, and unsupported records.
    """
    bundle, scope = load_checkpoint_input(content)
    # Pagination/collection integrity must be known before any canonical rule is built.
    rulebase_safety = build_rulebase_safety_map(bundle)
    resolver = CheckPointObjectResolver()
    zone_map = zone_mapping or {}
    parse_responses = [resp for resp in bundle.responses if resp.collection_status != "ERROR"]
    collection_inv: List[SourceInventoryItem] = [
        SourceInventoryItem(
            domain=resp.domain or "global",
            source_path=f"checkpoint/{canonicalize_command(resp.command)}",
            name=f"failed-command:{canonicalize_command(resp.command)}",
            source_type="collection-error",
            source_attributes={"error": resp.error or "collection failed"},
            status=ExtractionStatus.PARSE_ERROR,
            requires_manual_review=True,
            notes=["failed-source-command"],
        )
        for resp in bundle.responses if resp.collection_status == "ERROR"
    ]

    # Step 1: Pre-register all objects and dictionaries across all responses
    for resp in parse_responses:
        domain = resp.domain or bundle.domain
        data = resp.data
        if "objects-dictionary" in data:
            resolver.register_dictionary(data["objects-dictionary"], domain=domain)
        objects = data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())
        if isinstance(objects, list):
            for obj in objects:
                if isinstance(obj, dict):
                    resolver.register_object(obj, domain=domain)

    # Step 2: Extract Gaia OS configuration (if present)
    gaia_meta = None
    gaia_ifaces = []
    gaia_zones = []
    gaia_routes = []
    gaia_inv: List[SourceInventoryItem] = []
    gaia_unsupp: List[UnsupportedItem] = []

    for resp in parse_responses:
        if canonicalize_command(resp.command) == "gaia/show-configuration":
            cli_text = resp.data.get("cli_text", "")
            gaia_meta, gaia_ifaces, gaia_zones, gaia_routes, gaia_inv, gaia_unsupp = parse_gaia_configuration(cli_text)
            for z in gaia_zones:
                resolver.set_object_normalization(
                    uid_or_name=z.name,
                    canonical_name=z.name,
                    status=ExtractionStatus.NORMALIZED,
                    semantic_kind=SemanticKind.SECURITY_ZONE,
                )

    # Step 3: Extract Address objects and groups
    nat_safety_states = [
        state for key, state in rulebase_safety.items() if key[0] == "show-nat-rulebase"
    ]
    nat_rulebase_complete = bool(nat_safety_states) and all(state.complete for state in nat_safety_states)
    addresses, address_groups, addr_inv, addr_unsupp = extract_address_objects(
        parse_responses, resolver, nat_rulebase_complete=nat_rulebase_complete
    )

    # Step 4: Extract Schedules and Time objects
    schedules, time_inv, time_unsupp = extract_time_objects(parse_responses, resolver)

    # Step 5: Extract Services and Service groups
    services, service_groups, svc_inv, svc_unsupp = extract_service_objects(parse_responses, resolver)

    # Step 6: Extract Access Control Rulebase
    policies, access_inv, access_unsupp = extract_access_rulebase(
        parse_responses, resolver, scope, rulebase_safety
    )

    # Step 7: Extract NAT Rulebase
    nat_rules, nat_inv, nat_unsupp = extract_nat_rulebase(
        parse_responses, resolver, scope, rulebase_safety
    )

    # Apply zone mapping to policies and NAT rules if configured
    if zone_map:
        for pol in policies:
            pol.from_zone = [zone_map.get(z, z) for z in pol.from_zone]
            pol.to_zone = [zone_map.get(z, z) for z in pol.to_zone]
        for nat in nat_rules:
            nat.from_zone = [zone_map.get(z, z) for z in nat.from_zone]
            nat.to_zone = [zone_map.get(z, z) for z in nat.to_zone]

    # Step 8: Build Source Section accounting
    source_sections: List[SourceSectionResult] = []
    grouped = group_response_pages(bundle)

    for (cmd, domain, package, layer, gateway), pages in grouped.items():
        is_paged_valid, page_err = validate_pagination(pages)
        source_count = 0
        parsed_count = 0
        normalized_count = 0
        section_status = ExtractionStatus.NORMALIZED
        notes: List[str] = []

        if not is_paged_valid:
            section_status = ExtractionStatus.PARTIALLY_NORMALIZED
            notes.append(f"Pagination error: {page_err}")
        if any(page.collection_status == "ERROR" for page in pages):
            section_status = ExtractionStatus.PARSE_ERROR
            notes.append("failed-source-command")

        for page in pages:
            data = page.data
            objects = data.get("objects", [])
            if isinstance(objects, dict):
                objects = list(objects.values())
            if isinstance(objects, list) and objects:
                source_count += len(objects)
                parsed_count += len(objects)
                normalized_count += len([o for o in objects if isinstance(o, dict)])

            rulebase = data.get("rulebase", [])
            if isinstance(rulebase, list) and rulebase:
                flat_rules = flatten_rulebase(rulebase)
                source_count += len(flat_rules)
                parsed_count += len(flat_rules)
                normalized_count += len([r for r, _ in flat_rules if "_malformed_rule" not in r])

            if cmd == "gaia/show-configuration":
                source_count = len(gaia_inv)
                parsed_count = len(gaia_inv)
                normalized_count = len([i for i in gaia_inv if i.status == ExtractionStatus.NORMALIZED])

        if scope.ambiguous and ("rulebase" in cmd or "access" in cmd or "nat" in cmd):
            section_status = ExtractionStatus.PARTIALLY_NORMALIZED
            notes.extend(["scope-selection-required", *scope.reasons])

        source_sections.append(create_section_result(
            command=cmd,
            domain=domain,
            package=package,
            layer=layer,
            gateway=gateway,
            source_count=source_count,
            parsed_count=parsed_count,
            normalized_count=normalized_count,
            status=section_status,
            notes=notes,
        ))

    # Step 9: Assemble Canonical IRConfig
    hostname = (
        bundle.gateway
        or (gaia_meta.hostname if gaia_meta and gaia_meta.hostname != "checkpoint-gw" else None)
        or bundle.domain
        or "checkpoint-gw"
    )

    canonical_ir = IRConfig(
        metadata=IRMetadata(
            hostname=hostname,
            source_vendor="checkpoint",
            source_version=bundle.api_version,
        ),
        interfaces=gaia_ifaces,
        zones=gaia_zones,
        addresses=addresses,
        address_groups=address_groups,
        services=services,
        service_groups=service_groups,
        schedules=schedules,
        policies=policies,
        nat_rules=nat_rules,
        routes=gaia_routes,
    )

    all_inventory = addr_inv + time_inv + svc_inv + access_inv + nat_inv + gaia_inv + collection_inv
    all_unsupported = addr_unsupp + time_unsupp + svc_unsupp + access_unsupp + nat_unsupp + gaia_unsupp

    raw_result = ExtractionResult(
        canonical_ir=canonical_ir,
        source_sections=source_sections,
        inventory_items=all_inventory,
        unsupported_items=all_unsupported,
    )

    return sanitize_extraction_result(raw_result)
