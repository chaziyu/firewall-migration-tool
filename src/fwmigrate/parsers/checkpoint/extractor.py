"""Main extraction pipeline for Check Point R81 configurations."""

from __future__ import annotations

from typing import Any, Dict, Hashable, List, Optional, Set, Tuple
from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)
from fwmigrate.extraction.sanitize import sanitize_extraction_result
from fwmigrate.ir.core import IRConfig, IRMetadata, IRZone, IRDNSSettings, IRNTPSettings, IRNTPServer
from fwmigrate.parsers.checkpoint.access import extract_access_rulebase
from fwmigrate.parsers.checkpoint.coverage import (
    authoritative_object_identity,
    create_section_result,
)
from fwmigrate.parsers.checkpoint.gaia import parse_gaia_configuration
from fwmigrate.parsers.checkpoint.gateways import extract_gateway_topology
from fwmigrate.parsers.checkpoint.loader import (
    build_rulebase_safety_map,
    canonicalize_command,
    group_response_pages,
    load_checkpoint_input,
    validate_pagination,
)
from fwmigrate.parsers.checkpoint.models import (
    CheckPointExportBundle,
    CheckPointResponse,
    CollectionStatus,
    ScopeSelectionResult,
    collection_status_is_success,
)
from fwmigrate.parsers.checkpoint.nat import extract_nat_rulebase
from fwmigrate.parsers.checkpoint.objects import extract_address_objects
from fwmigrate.parsers.checkpoint.resolver import (
    CheckPointObjectResolver,
    SemanticKind,
    infer_semantic_kind,
    iter_dictionary_objects,
)
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase
from fwmigrate.parsers.checkpoint.schedules import extract_time_objects
from fwmigrate.parsers.checkpoint.services import extract_service_objects


def _dictionary_source_reference(resp: CheckPointResponse) -> str:
    scope = "/".join(str(value) for value in (
        resp.domain or "global",
        resp.package or "<missing-package>",
        resp.layer or "<missing-layer>",
    ))
    return f"objects-dictionary:{canonicalize_command(resp.command)}:{scope}"


def _prepare_dictionary_accounting(
    bundle: CheckPointExportBundle,
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
) -> Tuple[
    List[CheckPointResponse],
    List[SourceInventoryItem],
    Dict[Tuple[Hashable, ...], List[str]],
]:
    """Deduplicate dictionary objects and route portable definitions through normal extractors."""
    dedicated_keys: Set[Tuple[Hashable, ...]] = set()
    for resp in responses:
        domain = resp.domain or bundle.domain or "global"
        objects = resp.data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())
        if isinstance(objects, list):
            for obj in objects:
                dedicated_keys.add(authoritative_object_identity(
                    obj, domain, canonicalize_command(resp.command),
                ))

    seen = set(dedicated_keys)
    synthetic_responses: List[CheckPointResponse] = []
    evidence_inventory: List[SourceInventoryItem] = []
    provenance: Dict[Tuple[Hashable, ...], List[str]] = {}
    portable_kinds = {
        SemanticKind.ADDRESS,
        SemanticKind.ADDRESS_GROUP,
        SemanticKind.SERVICE,
        SemanticKind.SERVICE_GROUP,
        SemanticKind.TIME,
        SemanticKind.TIME_GROUP,
    }
    review_kinds = {
        SemanticKind.APPLICATION,
        SemanticKind.APPLICATION_GROUP,
        SemanticKind.APPLICATION_CATEGORY,
        SemanticKind.SITE,
        SemanticKind.VPN_COMMUNITY,
        SemanticKind.NONPORTABLE_MATCH_OBJECT,
    }

    for resp in responses:
        if "objects-dictionary" not in resp.data:
            continue
        domain = resp.domain or bundle.domain or "global"
        cmd = canonicalize_command(resp.command)
        source_path = f"checkpoint/{cmd}/objects-dictionary"
        source_reference = _dictionary_source_reference(resp)
        raw_dictionary = resp.data.get("objects-dictionary")
        dictionary_objects = list(iter_dictionary_objects(raw_dictionary))

        # Retain malformed dictionary values that the typed iterator cannot use.
        raw_values = list(raw_dictionary.values()) if isinstance(raw_dictionary, dict) else (
            list(raw_dictionary) if isinstance(raw_dictionary, list) else []
        )
        for index, value in enumerate(raw_values):
            if isinstance(value, dict):
                continue
            identity = authoritative_object_identity(
                value, domain, f"{cmd}/objects-dictionary:{index}",
            )
            provenance.setdefault(identity, []).append(source_reference)
            if identity in seen:
                continue
            seen.add(identity)
            evidence_inventory.append(SourceInventoryItem(
                domain=domain,
                source_path=source_path,
                name=f"<malformed-dictionary:{index}>",
                source_type="malformed-objects-dictionary-entry",
                source_attributes={"raw_value": repr(value)},
                source_references=[source_reference],
                status=ExtractionStatus.PARSE_ERROR,
                requires_manual_review=True,
                notes=["malformed-objects-dictionary-entry"],
            ))

        for obj in dictionary_objects:
            identity = authoritative_object_identity(
                obj, domain, f"{cmd}/objects-dictionary",
            )
            refs = provenance.setdefault(identity, [])
            if source_reference not in refs:
                refs.append(source_reference)
            if identity in seen:
                continue
            seen.add(identity)

            obj_type = str(obj.get("type") or "")
            name = obj.get("name")
            uid = obj.get("uid")
            semantic_kind = infer_semantic_kind(obj_type, name)
            if semantic_kind in portable_kinds:
                synthetic_responses.append(CheckPointResponse(
                    command=f"{cmd}/objects-dictionary",
                    domain=resp.domain,
                    package=resp.package,
                    layer=resp.layer,
                    gateway=resp.gateway,
                    data={"objects": [obj]},
                ))
                continue

            ambiguous_identity = not uid and not name
            if ambiguous_identity:
                status = ExtractionStatus.PARSE_ERROR
                notes = ["ambiguous-objects-dictionary-identity"]
            elif semantic_kind in {SemanticKind.UNKNOWN, SemanticKind.NONPORTABLE_MATCH_OBJECT}:
                status = ExtractionStatus.UNSUPPORTED
                notes = [f"dictionary-object-not-canonically-modeled:{obj_type or '<missing>'}"]
            else:
                status = ExtractionStatus.EXTRACT_ONLY
                notes = [f"dictionary-resolution-evidence:{semantic_kind.value}"]

            evidence_inventory.append(SourceInventoryItem(
                domain=domain,
                source_path=source_path,
                name=name or f"<unnamed:{uid or len(evidence_inventory) + 1}>",
                source_id=uid,
                source_type=obj_type or None,
                source_attributes=obj,
                source_references=[source_reference],
                status=status,
                requires_manual_review=ambiguous_identity or semantic_kind in review_kinds,
                notes=notes,
            ))
            if uid or name:
                resolver.set_object_normalization(
                    uid_or_name=str(uid or name),
                    canonical_name=name,
                    status=status,
                    requires_manual_review=ambiguous_identity or semantic_kind in review_kinds,
                    usable=False,
                    semantic_kind=semantic_kind,
                )

    return synthetic_responses, evidence_inventory, provenance


def _attach_dictionary_provenance(
    items: List[SourceInventoryItem],
    provenance: Dict[Tuple[Hashable, ...], List[str]],
) -> None:
    for item in items:
        identity = authoritative_object_identity(
            item.source_attributes,
            item.domain,
            item.source_path.removeprefix("checkpoint/"),
        )
        for reference in provenance.get(identity, []):
            if reference not in item.source_references:
                item.source_references.append(reference)


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
    parse_responses = [resp for resp in bundle.responses if collection_status_is_success(resp.collection_status)]
    collection_inv: List[SourceInventoryItem] = []
    for resp in bundle.responses:
        if collection_status_is_success(resp.collection_status):
            continue
        is_unsupported = resp.collection_status == CollectionStatus.UNSUPPORTED_COMMAND
        collection_inv.append(SourceInventoryItem(
            domain=resp.domain or "global",
            source_path=f"checkpoint/{canonicalize_command(resp.command)}",
            name=f"failed-command:{canonicalize_command(resp.command)}",
            source_type="collection-error",
            source_attributes={
                "collection_status": resp.collection_status.value,
                "error_code": resp.collection_error_code,
                "error": resp.error or "collection failed",
                "object_count": resp.object_count,
            },
            status=(ExtractionStatus.UNSUPPORTED if is_unsupported else ExtractionStatus.PARSE_ERROR),
            requires_manual_review=True,
            notes=["failed-source-command"],
        ))

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

    dictionary_responses, dictionary_evidence_inv, dictionary_provenance = (
        _prepare_dictionary_accounting(bundle, parse_responses, resolver)
    )
    object_responses = parse_responses + dictionary_responses

    # Step 2: Extract Gaia OS configuration (if present)
    gaia_meta = None
    gaia_ifaces = []
    gaia_zones = []
    gaia_routes = []
    gaia_inv: List[SourceInventoryItem] = []
    gaia_unsupp: List[UnsupportedItem] = []
    gaia_contexts = set()
    gaia_metadata_by_gateway: Dict[Optional[str], List[IRMetadata]] = {}

    for response_index, resp in enumerate(parse_responses):
        if canonicalize_command(resp.command) == "gaia/show-configuration":
            cli_text = resp.data.get("cli_text", "")
            response_name = resp.source_response or f"response-{response_index + 1}"
            context = f"{resp.domain or bundle.domain or 'global'}:{resp.gateway or bundle.gateway or 'unknown'}:{response_name}"
            parsed_meta, parsed_ifaces, parsed_zones, parsed_routes, parsed_inv, parsed_unsupp = parse_gaia_configuration(
                cli_text, domain=resp.domain or bundle.domain, gateway=resp.gateway or bundle.gateway,
                source_response=response_name,
                cluster_member=resp.cluster_member or resp.data.get("cluster_member"),
            )
            gaia_contexts.add(context)
            gaia_metadata_by_gateway.setdefault(resp.gateway or bundle.gateway, []).append(parsed_meta)
            gaia_ifaces.extend(parsed_ifaces)
            gaia_zones.extend(parsed_zones)
            gaia_routes.extend(parsed_routes)
            gaia_inv.extend(parsed_inv)
            gaia_unsupp.extend(parsed_unsupp)
            for z in parsed_zones:
                resolver.set_object_normalization(
                    uid_or_name=z.name,
                    canonical_name=z.name,
                    status=ExtractionStatus.NORMALIZED,
                    semantic_kind=SemanticKind.SECURITY_ZONE,
                )

    # Management topology has no member context in its legacy model. Keep it
    # separate when Gaia supplied multiple contexts instead of collapsing names.
    if len(gaia_contexts) <= 1:
        gaia_ifaces, management_zones, gateway_inv, gateway_unsupp = extract_gateway_topology(
            object_responses, resolver, gaia_ifaces,
        )
    else:
        management_zones, gateway_inv, gateway_unsupp = [], [], []
    gaia_zones_by_name = {(zone.source_context, zone.name): zone for zone in gaia_zones}
    for zone in management_zones:
        existing = gaia_zones_by_name.get((zone.source_context, zone.name))
        if existing:
            for interface in zone.interfaces:
                if interface not in existing.interfaces:
                    existing.interfaces.append(interface)
            existing.source_attributes.update(zone.source_attributes)
        else:
            gaia_zones_by_name[(zone.source_context, zone.name)] = zone
    gaia_zones = list(gaia_zones_by_name.values())

    dns_values = [item.source_attributes for item in gaia_inv if item.source_type == "gaia-dns"]
    domain_values = [item.source_attributes.get("value") for item in gaia_inv if item.source_type == "gaia-domain-name"]
    dns = IRDNSSettings(
        primary=next((x["value"] for x in dns_values if x.get("setting") == "primary"), None),
        secondary=next((x["value"] for x in dns_values if x.get("setting") == "secondary"), None),
        tertiary=next((x["value"] for x in dns_values if x.get("setting") == "tertiary"), None),
        domain_name=next(iter(domain_values), None),
        search_suffixes=[x["value"] for x in dns_values if x.get("setting") in {"search", "search-suffix"}],
    ) if dns_values or domain_values else None
    ntp_entries = [item.source_attributes for item in gaia_inv if item.source_type == "gaia-ntp"]
    ntp = IRNTPSettings(servers=[IRNTPServer(role=e["role"], address=e.get("address"), source_attributes=e) for e in ntp_entries if e.get("role") and e.get("address")]) if ntp_entries else None

    # Step 3: Extract Address objects and groups
    nat_safety_states = [state for key, state in rulebase_safety.items() if key[0] == "show-nat-rulebase"]
    nat_completeness_by_scope = {
        (domain or "global", package): state.complete
        for (command, domain, package, _layer, _gateway), state in rulebase_safety.items()
        if command == "show-nat-rulebase"
    }
    nat_rulebase_complete = bool(nat_safety_states) and all(state.complete for state in nat_safety_states)
    addresses, address_groups, addr_inv, addr_unsupp = extract_address_objects(
        object_responses, resolver, nat_rulebase_complete=nat_rulebase_complete,
        nat_completeness_by_scope=nat_completeness_by_scope,
        selected_package=scope.selected_package,
    )

    # Step 4: Extract Schedules and Time objects
    schedules, time_inv, time_unsupp = extract_time_objects(object_responses, resolver)

    # Step 5: Extract Services and Service groups
    services, service_groups, svc_inv, svc_unsupp = extract_service_objects(object_responses, resolver)

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
        failed_pages = [page for page in pages if not collection_status_is_success(page.collection_status)]
        if failed_pages:
            section_status = (
                ExtractionStatus.UNSUPPORTED
                if all(page.collection_status == CollectionStatus.UNSUPPORTED_COMMAND for page in failed_pages)
                else ExtractionStatus.PARSE_ERROR
            )
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
        if cmd == "show-access-rulebase" and package is None:
            section_status = ExtractionStatus.PARTIALLY_NORMALIZED
            notes.append("missing-package-scope")
        if cmd == "show-access-rulebase" and layer is None:
            section_status = ExtractionStatus.PARTIALLY_NORMALIZED
            notes.append("missing-access-layer-scope")
        if cmd == "show-nat-rulebase" and package is None:
            section_status = ExtractionStatus.PARTIALLY_NORMALIZED
            notes.append("missing-package-scope")

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
    selected_gaia = gaia_metadata_by_gateway.get(scope.selected_gateway, []) if scope.selected_gateway else []
    hostnames = {m.hostname for m in selected_gaia if m.hostname and m.hostname != "checkpoint-gw"}
    if len(hostnames) == 1:
        hostname = next(iter(hostnames))
    elif len(gaia_metadata_by_gateway) == 1:
        only_metadata = next(iter(gaia_metadata_by_gateway.values()))
        hostname = next((m.hostname for m in only_metadata if m.hostname != "checkpoint-gw"), None)
    else:
        hostname = bundle.gateway if scope.selected_gateway else None
    if hostname is None and len(gaia_metadata_by_gateway) > 1 and not scope.selected_gateway:
        gaia_inv.append(SourceInventoryItem(
            domain=bundle.domain or "global", source_path="checkpoint/gaia/show-configuration/system",
            name="hostname", source_type="gaia-hostname-selection", source_context="bundle",
            source_attributes={"gateway_scopes": sorted(str(k) for k in gaia_metadata_by_gateway)},
            status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True,
            notes=["multiple-gateway-hostnames-without-selector"],
        ))
    hostname = hostname or bundle.domain or "checkpoint-gw"

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
        dns_settings=dns,
        ntp_settings=ntp,
    )

    object_inventory = addr_inv + time_inv + svc_inv
    _attach_dictionary_provenance(object_inventory, dictionary_provenance)
    _attach_dictionary_provenance(dictionary_evidence_inv, dictionary_provenance)
    all_inventory = (
        object_inventory + dictionary_evidence_inv + access_inv + nat_inv
        + gaia_inv + gateway_inv + collection_inv
    )
    all_unsupported = addr_unsupp + time_unsupp + svc_unsupp + access_unsupp + nat_unsupp + gaia_unsupp + gateway_unsupp

    # Final inventory status is authoritative for normalization coverage. A
    # structurally parsed dictionary/rule is not necessarily canonicalized.
    for section in source_sections:
        parts = section.path.split("/")
        command = (
            "gaia/show-configuration"
            if section.path.startswith("checkpoint/gaia/show-configuration")
            else parts[1] if len(parts) > 1 else ""
        )
        candidates = [
            item for item in all_inventory
            if item.source_path.startswith(f"checkpoint/{command}")
            and (len(parts) < 3 or not parts[2] or item.domain == parts[2] or parts[2] in item.source_path)
        ]
        if command == "show-access-rulebase" and len(parts) >= 4:
            package, layer = parts[-2], parts[-1]
            candidates = [
                item for item in all_inventory
                if item.source_path == f"checkpoint/{command}/{package}/{layer}"
                and (len(parts) == 4 or item.domain == parts[-3])
            ]
        elif command == "show-nat-rulebase" and len(parts) >= 3:
            package = parts[-1]
            candidates = [
                item for item in all_inventory
                if item.source_path == f"checkpoint/{command}/{package}"
                and (len(parts) == 3 or item.domain == parts[-2])
            ]
        if command == "gaia/show-configuration":
            candidates = gaia_inv
        section.object_count_normalized = sum(
            item.status == ExtractionStatus.NORMALIZED for item in candidates
        )
        counts = {
            status: sum(item.status == status for item in candidates)
            for status in ExtractionStatus
        }
        nonzero = [
            f"{status.value}={count}" for status, count in counts.items()
            if count and status != ExtractionStatus.NORMALIZED
        ]
        if nonzero:
            section.notes.append("Final inventory status counts: " + ", ".join(nonzero))
        if section.status == ExtractionStatus.NORMALIZED and any(
            item.status != ExtractionStatus.NORMALIZED for item in candidates
        ):
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED

    review_items = [
        item for item in all_inventory
        if item.requires_manual_review
        or item.status in {
            ExtractionStatus.PARTIALLY_NORMALIZED,
            ExtractionStatus.UNSUPPORTED,
            ExtractionStatus.PARSE_ERROR,
        }
    ]
    blocking_reasons = list(dict.fromkeys(
        reason
        for item in review_items
        for reason in (item.notes or [f"{item.source_path}:{item.name or '<unnamed>'}"])
    ))
    if all_unsupported and not blocking_reasons:
        blocking_reasons.append("checkpoint-unsupported-source-semantics")
    requires_manual_review = bool(review_items or all_unsupported)
    generation_safe = not blocking_reasons
    canonical_ir.generation_safe = generation_safe
    canonical_ir.generation_blocking_reasons = list(blocking_reasons)
    canonical_ir.requires_manual_review = requires_manual_review

    raw_result = ExtractionResult(
        canonical_ir=canonical_ir,
        source_sections=source_sections,
        inventory_items=all_inventory,
        unsupported_items=all_unsupported,
        requires_manual_review=requires_manual_review,
        migration_complete=not requires_manual_review,
        generation_safe=generation_safe,
        blocking_reasons=blocking_reasons,
    )

    return sanitize_extraction_result(raw_result)
