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
from fwmigrate.ir.core import (
    IRConfig, IRHighAvailability, IRMetadata, IRZone, IRDNSSettings, IRNTPSettings, IRNTPServer,
    IRDHCPServer, IRDHCPIPRange, IRDHCPExcludeRange, IRDHCPReservation,
    IRCheckpointManagementAccess, IRCheckpointPolicyPackage, IRCheckpointAccessLayer,
    IRCheckpointDomain, IRCheckpointGlobalAssignment,
)
from fwmigrate.parsers.checkpoint.authentication import extract_authentication
from fwmigrate.parsers.checkpoint.identity import extract_identity
from fwmigrate.parsers.checkpoint.access import extract_access_rulebase
from fwmigrate.parsers.checkpoint.coverage import (
    authoritative_object_identity,
    aggregate_checkpoint_coverage,
    apply_checkpoint_coverage,
    create_section_result,
)
from fwmigrate.parsers.checkpoint.gaia import parse_gaia_configuration
from fwmigrate.parsers.checkpoint.cluster import extract_clusters
from fwmigrate.parsers.checkpoint.performance import extract_performance_settings
from fwmigrate.parsers.checkpoint.certificates import attach_certificate_usages, extract_certificates
from fwmigrate.parsers.checkpoint.gateways import extract_gateway_topology, extract_sic_metadata
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
from fwmigrate.parsers.checkpoint.objects import extract_address_objects, extract_application_objects
from fwmigrate.parsers.checkpoint.https_inspection import extract_https_inspection_rulebase
from fwmigrate.parsers.checkpoint.resolver import (
    CheckPointObjectResolver,
    SemanticKind,
    infer_semantic_kind,
    iter_dictionary_objects,
)
from fwmigrate.parsers.checkpoint.rulebase import flatten_rulebase
from fwmigrate.parsers.checkpoint.schedules import extract_time_objects
from fwmigrate.parsers.checkpoint.services import extract_service_objects
from fwmigrate.parsers.checkpoint.threat_prevention import extract_threat_prevention
from fwmigrate.parsers.checkpoint.threat_profiles import extract_threat_profiles
from fwmigrate.parsers.checkpoint.vpn import extract_vpn


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


def _extract_policy_context(
    bundle: CheckPointExportBundle,
) -> Tuple[List[IRCheckpointPolicyPackage], List[IRCheckpointAccessLayer], List[IRCheckpointDomain]]:
    """Build explicit package/layer/domain identity from authoritative source references."""
    responses = [r for r in bundle.responses if collection_status_is_success(r.collection_status)]
    def ref_value(value: Any) -> Optional[str]:
        if isinstance(value, dict):
            value = value.get("uid") or value.get("name")
        return str(value) if value is not None else None
    def ref_pair(*values: Any) -> Tuple[Optional[str], Optional[str]]:
        for value in values:
            if isinstance(value, dict):
                return ref_value(value.get("uid")), ref_value(value.get("name"))
            if value is not None:
                return ref_value(value), None
        return None, None
    def response_objects(command: str) -> List[Tuple[CheckPointResponse, Dict[str, Any]]]:
        result = []
        for response in responses:
            if canonicalize_command(response.command) != command:
                continue
            raw_objects = response.data.get("objects", [])
            raw_objects = raw_objects.values() if isinstance(raw_objects, dict) else raw_objects
            result.extend((response, obj) for obj in raw_objects if isinstance(obj, dict))
        return result

    objects = lambda command: [obj for _, obj in response_objects(command)]
    layers = {
        (response.domain or bundle.domain or "global", str(obj["uid"])): (response, obj)
        for response, obj in response_objects("show-access-layers") if obj.get("uid")
    }
    packages: List[IRCheckpointPolicyPackage] = []
    for package_response, raw in response_objects("show-packages"):
        domain_name = raw.get("domain") or package_response.domain or bundle.domain
        package_uid = raw.get("uid")
        package_reasons = [] if package_uid else ["missing-policy-package-uid"]
        refs = raw.get("access-layers") or raw.get("access-layers-settings") or []
        refs = refs.get("objects", refs.get("layers", [])) if isinstance(refs, dict) else refs
        refs = refs if isinstance(refs, list) else []
        layer_uids, layer_names = [], []
        for ref in refs:
            ref = ref if isinstance(ref, dict) else {"name": ref}
            obj = layers.get((domain_name or "global", str(ref.get("uid"))), (None, {}))[1]
            if ref.get("uid"):
                layer_uids.append(str(ref["uid"]))
            name = ref.get("name") or obj.get("name")
            if name:
                layer_names.append(str(name))
            if not ref.get("uid"):
                package_reasons.append("missing-access-layer-uid")
        if not refs:
            package_reasons.append("missing-access-layer-association")
        nat_uid, nat_name = ref_pair(raw.get("nat-policy-uid"), raw.get("nat-policy"), raw.get("nat-policy-name"))
        threat_uid, threat_name = ref_pair(raw.get("threat-prevention-policy-uid"), raw.get("threat-prevention-policy"), raw.get("threat-prevention-policy-name"))
        packages.append(IRCheckpointPolicyPackage(
            uid=package_uid, name=str(raw.get("name") or package_uid or "<unnamed-package>"),
            domain_uid=raw.get("domain-uid") or raw.get("domain_uid"),
            domain_name=domain_name, access_layer_uids=layer_uids,
            access_layer_names=layer_names,
            nat_policy_uid=nat_uid, nat_policy_name=nat_name,
            threat_prevention_policy_uid=threat_uid, threat_prevention_policy_name=threat_name,
            installation_targets=[ref_value(value) for value in (raw.get("installation-targets") or raw.get("install-on") or []) if ref_value(value)],
            global_assignment=raw.get("global-assignment"),
            source_context=f"{domain_name or 'global'}/{raw.get('name') or package_uid or '<unnamed-package>'}",
            migration_status="PARTIALLY_NORMALIZED" if package_reasons else "NORMALIZED",
            requires_manual_review=bool(package_reasons), review_reasons=package_reasons,
            source_attributes=raw,
        ))
    # Preserve rulebase scope when show-packages was not collected.
    known_packages = {(p.domain_name or "global", p.uid or p.name) for p in packages}
    for response in responses:
        if canonicalize_command(response.command) != "show-access-rulebase" or not response.package:
            continue
        domain = response.domain or bundle.domain or "global"
        key = (domain, response.package_uid or response.package)
        if key in known_packages:
            continue
        packages.append(IRCheckpointPolicyPackage(
            uid=response.package_uid, name=response.package, domain_uid=response.domain_uid,
            domain_name=domain, source_context=f"{domain}/{response.package}",
            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
            review_reasons=["missing-policy-package-definition"],
            source_attributes={"source_response": response.model_dump(by_alias=True)},
        ))
        known_packages.add(key)
    layer_models: List[IRCheckpointAccessLayer] = []
    package_by_layer = {
        (p.domain_name or bundle.domain or "global", uid): p
        for p in packages for uid in p.access_layer_uids
    }
    for (layer_domain, uid), (layer_response, raw) in layers.items():
        p = package_by_layer.get((layer_domain, uid))
        layer_reasons = [] if p else ["unresolved-access-layer-package-membership"]
        install_targets = [ref_value(value) for value in (raw.get("installation-targets") or raw.get("install-on") or []) if ref_value(value)]
        layer_models.append(IRCheckpointAccessLayer(
            uid=uid, name=str(raw.get("name") or uid), package_uid=p.uid if p else None,
            package_name=p.name if p else None, domain_uid=raw.get("domain-uid"),
            domain_name=raw.get("domain") or layer_domain, installation_targets=install_targets,
            source_context=f"{layer_domain}/{raw.get('name') or uid}",
            migration_status="PARTIALLY_NORMALIZED" if layer_reasons else "NORMALIZED",
            requires_manual_review=bool(layer_reasons), review_reasons=layer_reasons,
            source_attributes=raw,
        ))
    # Keep rulebases when the authoritative layer-definition call was omitted.
    known_layer_keys = {(l.domain_name or "global", l.uid or l.name) for l in layer_models}
    for response in responses:
        if canonicalize_command(response.command) != "show-access-rulebase":
            continue
        domain = response.domain or bundle.domain or "global"
        uid = response.layer_uid or response.data.get("uid")
        name = response.layer or response.data.get("name") or uid or "<missing-layer>"
        key = (domain, str(uid or name))
        if key in known_layer_keys:
            continue
        layer_models.append(IRCheckpointAccessLayer(
            uid=str(uid) if uid else None, name=str(name),
            package_uid=response.package_uid, package_name=response.package,
            domain_uid=response.domain_uid, domain_name=domain,
            source_context=f"{domain}/{name}",
            migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
            review_reasons=["missing-access-layer-definition"],
            source_attributes={"source_response": response.model_dump(by_alias=True)},
        ))
        known_layer_keys.add(key)
    # Inline relationships are response-scoped and preserve discovery order per layer.
    by_uid = {(layer.domain_name or "global", layer.uid): layer for layer in layer_models if layer.uid}
    for response in responses:
        if canonicalize_command(response.command) != "show-access-rulebase":
            continue
        response_domain = response.domain or bundle.domain or "global"
        parent = by_uid.get((response_domain, response.layer_uid)) or next(
            (l for l in layer_models if (l.domain_name or "global") == response_domain and l.name == response.layer),
            None,
        )
        for rule, _ in flatten_rulebase(response.data.get("rulebase", [])):
            if parent and rule.get("uid") and rule["uid"] not in parent.rule_uids:
                parent.rule_uids.append(str(rule["uid"]))
            ref = rule.get("inline-layer") or rule.get("inline_layer")
            if not isinstance(ref, dict) or not (ref.get("uid") or ref.get("name")):
                continue
            child = by_uid.get((response_domain, str(ref.get("uid")))) or next(
                (l for l in layer_models if (l.domain_name or "global") == response_domain and l.name == ref.get("name")),
                None,
            )
            if child is None:
                child = IRCheckpointAccessLayer(
                    uid=ref.get("uid"), name=str(ref.get("name") or ref.get("uid")), inline=True,
                    domain_name=response_domain, package_uid=response.package_uid,
                    package_name=response.package, migration_status="PARTIALLY_NORMALIZED",
                    requires_manual_review=True, review_reasons=["missing-access-layer-definition"],
                )
                layer_models.append(child)
                if child.uid:
                    by_uid[(response_domain, child.uid)] = child
            child.inline = True
            child.parent_layer_uid = parent.uid if parent else response.layer_uid
            child.parent_layer_name = parent.name if parent else response.layer
            child.parent_rule_uid = rule.get("uid")
            child.parent_rule_number = rule.get("rule-number")
    domains: List[IRCheckpointDomain] = []
    for raw in objects("show-domains"):
        domains.append(IRCheckpointDomain(uid=raw.get("uid"), name=str(raw.get("name") or raw.get("uid")),
            domain_type=raw.get("type"), management_server=bundle.management_server,
            context=raw.get("domain-context") or raw.get("context"),
            source_context=raw.get("domain-context") or raw.get("context"), source_attributes=raw))
    known = {d.uid or d.name for d in domains}
    for response in responses:
        identity = response.domain_uid or response.domain_name or response.domain
        if identity and identity not in known:
            name = response.domain_name or response.domain
            domains.append(IRCheckpointDomain(uid=response.domain_uid, name=name or identity,
                management_server=bundle.management_server, migration_status="PARTIALLY_NORMALIZED",
                requires_manual_review=True, review_reasons=["missing-authoritative-domain-definition"],
                policy_package_names=[p.name for p in packages if p.domain_name == name],
                source_attributes={"source_response": response.model_dump(by_alias=True)}))
            known.add(identity)
    for domain in domains:
        domain.policy_package_uids = [p.uid for p in packages if p.uid and p.domain_name == domain.name]
        domain.policy_package_names = [p.name for p in packages if p.domain_name == domain.name]
    return packages, layer_models, domains


def _extract_global_assignments(
    bundle: CheckPointExportBundle, domains: List[IRCheckpointDomain]
) -> Tuple[List[IRCheckpointGlobalAssignment], List[SourceInventoryItem]]:
    """Extract assignments as relationships; never clone global objects."""
    domain_by_id = {d.uid or d.name: d for d in domains}
    assignments: List[IRCheckpointGlobalAssignment] = []
    inventory: List[SourceInventoryItem] = []
    for response in bundle.responses:
        if canonicalize_command(response.command) != "show-global-assignments":
            continue
        raw_items = response.data.get("objects", response.data.get("assignments", []))
        raw_items = list(raw_items.values()) if isinstance(raw_items, dict) else raw_items
        for index, raw in enumerate(raw_items if isinstance(raw_items, list) else []):
            if not isinstance(raw, dict):
                inventory.append(SourceInventoryItem(
                    domain=response.domain_name or response.domain or "global",
                    source_path="checkpoint/show-global-assignments",
                    name=f"<malformed:{index}>", source_type="checkpoint-domain-context-error",
                    status=ExtractionStatus.PARSE_ERROR, requires_manual_review=True,
                    notes=["malformed-global-assignment"]))
                continue
            target = raw.get("target-domain") or raw.get("target_domain") or raw.get("domain")
            target_uid = target.get("uid") if isinstance(target, dict) else raw.get("target-domain-uid") or raw.get("target_domain_uid")
            target_name = target.get("name") if isinstance(target, dict) else raw.get("target-domain-name") or raw.get("target_domain_name")
            reasons = [] if target_uid and target_uid in domain_by_id else ["unresolved-global-assignment-domain"]
            item = IRCheckpointGlobalAssignment(
                uid=raw.get("uid"), global_domain_uid=raw.get("global-domain-uid") or raw.get("global_domain_uid"),
                global_domain_name=raw.get("global-domain-name") or raw.get("global_domain_name"),
                target_domain_uid=target_uid, target_domain_name=target_name,
                global_package_uid=(raw.get("global-package") or {}).get("uid") if isinstance(raw.get("global-package"), dict) else raw.get("global-package-uid"),
                global_package_name=(raw.get("global-package") or {}).get("name") if isinstance(raw.get("global-package"), dict) else raw.get("global-package-name"),
                local_package_uid=raw.get("local-package-uid"), local_package_name=raw.get("local-package-name"),
                state=raw.get("state"), mode=raw.get("mode"),
                assigned_objects=[str(x.get("uid") or x.get("name") or x) if isinstance(x, dict) else str(x) for x in raw.get("objects", [])],
                assigned_policies=[str(x.get("uid") or x.get("name") or x) if isinstance(x, dict) else str(x) for x in raw.get("policies", [])],
                migration_status="PARTIALLY_NORMALIZED" if reasons else "NORMALIZED",
                requires_manual_review=bool(reasons), review_reasons=reasons, source_attributes=raw)
            assignments.append(item)
            if item.uid and target_uid in domain_by_id:
                domain_by_id[target_uid].global_assignments.append(item.uid)
            inventory.append(SourceInventoryItem(
                domain=target_name or target_uid or "global", source_path="checkpoint/show-global-assignments",
                name=item.uid or f"assignment-{index}", source_id=item.uid, source_type="checkpoint-global-assignment",
                source_attributes=raw, status=ExtractionStatus(item.migration_status),
                requires_manual_review=item.requires_manual_review, notes=list(item.review_reasons)))
    return assignments, inventory


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
    policy_packages, access_layers, checkpoint_domains = _extract_policy_context(bundle)
    global_assignments, global_assignment_inv = _extract_global_assignments(bundle, checkpoint_domains)
    for assignment in global_assignments:
        resolver.register_global_assignment(
            assignment.target_domain_uid,
            assignment.target_domain_name,
            assignment.assigned_objects,
        )
    zone_map = zone_mapping or {}
    parse_responses = [resp for resp in bundle.responses if collection_status_is_success(resp.collection_status)]
    for resp in parse_responses:
        resp.domain = resp.domain or bundle.domain
        resp.domain_name = resp.domain_name or resp.domain
        if resp.domain_uid is None and resp.domain == bundle.domain:
            resp.domain_uid = bundle.domain_uid
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
                    resolver.register_object(obj, domain=domain, domain_uid=resp.domain_uid)

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
    gaia_auth_texts: List[Tuple[str, str]] = []
    performance_settings = []
    performance_inv: List[SourceInventoryItem] = []

    for response_index, resp in enumerate(parse_responses):
        if canonicalize_command(resp.command) == "gaia/show-configuration":
            cli_text = resp.data.get("cli_text", "")
            response_name = resp.source_response or f"response-{response_index + 1}"
            context = f"{resp.domain or bundle.domain or 'global'}:{resp.gateway or bundle.gateway or 'unknown'}:{response_name}"
            gaia_auth_texts.append((response_name, cli_text, context))
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
            parsed_performance, parsed_performance_inv = extract_performance_settings(
                cli_text, domain=resp.domain or bundle.domain, gateway=resp.gateway or bundle.gateway,
                source_response=response_name, cluster_member=resp.cluster_member or resp.data.get("cluster_member"),
            )
            performance_settings.extend(parsed_performance)
            performance_inv.extend(parsed_performance_inv)
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
    dhcp_servers = []
    for source_id, item in enumerate(
        (item for item in gaia_inv if item.source_type == "gaia-dhcp-server" and item.source_attributes.get("subnet")),
        1,
    ):
        attrs = item.source_attributes
        ranges = [
            IRDHCPIPRange(
                source_id=index, start_ip=pool.get("start"), end_ip=pool.get("end"),
                source_context=item.source_context, source_attributes=pool,
            )
            for index, pool in enumerate(attrs.get("pool_ranges", []), 1)
            if pool.get("type") == "include"
        ]
        exclude_ranges = [
            IRDHCPExcludeRange(
                source_id=index, start_ip=pool.get("start"), end_ip=pool.get("end"),
                source_context=item.source_context, source_attributes=pool,
            )
            for index, pool in enumerate(attrs.get("pool_ranges", []), 1)
            if pool.get("type") == "exclude"
        ]
        reservations = [
            IRDHCPReservation(
                source_id=index, ip_address=reservation.get("ip_address"),
                mac_address=reservation.get("mac_address"),
                source_context=item.source_context,
                source_attributes=reservation.get("source_attributes", {}),
            )
            for index, reservation in enumerate(attrs.get("reservations", []), 1)
        ]
        dhcp_servers.append(IRDHCPServer(
            source_id=source_id, enabled=bool(attrs.get("enabled", True)),
            source_context=item.source_context, interface=attrs.get("interface"),
            default_gateway=attrs.get("default_gateway"), netmask=attrs.get("netmask"),
            lease_time_seconds=attrs.get("lease_time_seconds"), domain=attrs.get("domain"),
            dns_servers=list(attrs.get("dns_servers", [])), ip_ranges=ranges,
            exclude_ranges=exclude_ranges, reservations=reservations,
            migration_status="PARTIALLY_NORMALIZED" if item.status != ExtractionStatus.NORMALIZED else "NORMALIZED",
            requires_manual_review=item.requires_manual_review,
            review_reasons=list(item.notes), source_explicit_fields=[
                key for key in ("subnet", "netmask", "interface", "default_gateway", "dns_servers", "domain", "lease_time_seconds")
                if attrs.get(key) not in (None, [], "")
            ], source_attributes=attrs,
        ))

    # VPN communities/gateway properties and authentication are separate from
    # the older object/rule transformers so their source semantics stay visible.
    vpn_communities, vpn_gateways, vpn_inv, vpn_unsupp = extract_vpn(object_responses)
    clusters, cluster_inv = extract_clusters(object_responses)
    # Gaia remains member-local. Only compare when its provenance identifies
    # the same member; retain both values and flag the conflict.
    for cluster in clusters:
        for member_id, addresses in cluster.member_interface_ips.items():
            for interface in gaia_ifaces:
                provenance = interface.source_attributes.get("provenance", {})
                if str(provenance.get("cluster_member")) != str(member_id):
                    continue
                if interface.ip and interface.ip not in addresses:
                    cluster.requires_manual_review = True
                    cluster.migration_status = "PARTIALLY_NORMALIZED"
                    cluster.source_attributes.setdefault("review_reasons", []).append("cluster-member-topology-conflict")
    sic_metadata = extract_sic_metadata(object_responses)
    sic_inventory = [SourceInventoryItem(
        domain=item.source_context or "global", source_path="checkpoint/show-gateways-and-servers",
        name=item.gateway_name, source_id=item.gateway_uid, source_type="checkpoint-sic-metadata",
        source_context=item.source_context, source_attributes=item.source_attributes,
        status=ExtractionStatus.EXTRACT_ONLY, requires_manual_review=True,
        notes=["SIC runtime state is evidence only; no activation or reset operation is generated"],
    ) for item in sic_metadata]
    local_users, user_groups, ldap_servers, radius_servers, tacacs_servers, saml_servers, auth_inv, auth_unsupp = extract_authentication(
        object_responses, gaia_auth_texts,
    )

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
    schedules, schedule_groups, time_inv, time_unsupp = extract_time_objects(
        object_responses, resolver, include_groups=True
    )

    # Step 5: Extract Services and Service groups
    services, service_groups, svc_inv, svc_unsupp = extract_service_objects(object_responses, resolver)

    # Applications are a distinct policy dimension; they are never services.
    applications, application_groups, application_categories, app_inv = extract_application_objects(
        object_responses, resolver
    )

    # Keep source scope on every canonical object without changing target semantics.
    for collection in (addresses, address_groups, services, service_groups, schedules, schedule_groups, applications, application_groups, application_categories):
        for item in collection:
            uid = getattr(item, "source_uuid", None)
            domain_uid, domain_name = resolver.object_domain(uid)
            if hasattr(item, "checkpoint_domain_uid"):
                item.checkpoint_domain_uid = domain_uid
                item.checkpoint_domain_name = domain_name or item.source_context
                source = resolver.by_uid.get(str(uid)) if uid else None
                source = source or {}
                item.checkpoint_origin_scope = (
                    source.get("checkpoint-origin-scope")
                    or source.get("checkpoint_origin_scope")
                    or ("GLOBAL" if (domain_name or "").lower() == "global" else "DOMAIN_LOCAL")
                )
                item.global_source_uid = source.get("global-source-uid") or source.get("global_source_uid")
                item.global_source_name = source.get("global-source-name") or source.get("global_source_name")
                item.local_override_uid = source.get("local-override-uid") or source.get("local_override_uid")
                item.assignment_uid = source.get("assignment-uid") or source.get("assignment_uid")

    # Step 6: Extract Access Control Rulebase
    policies, access_inv, access_unsupp = extract_access_rulebase(
        parse_responses, resolver, scope, rulebase_safety
    )
    policy_context_inv = [
        SourceInventoryItem(
            domain=item.domain_name or "global",
            source_path=f"checkpoint/{'show-packages' if kind == 'package' else 'show-access-layers'}",
            name=item.name, source_id=item.uid,
            source_type=(
                "checkpoint-policy-package" if kind == "package" and not item.requires_manual_review
                else "checkpoint-access-layer" if kind == "layer" and not item.inline and not item.requires_manual_review
                else "checkpoint-inline-access-layer" if kind == "layer" and item.inline
                else "checkpoint-policy-context-error"
            ),
            source_context=item.source_context,
            source_attributes=item.model_dump(exclude={"source_attributes"}) | item.source_attributes,
            status=ExtractionStatus(item.migration_status),
            requires_manual_review=item.requires_manual_review,
            notes=list(item.review_reasons),
        )
        for kind, values in (("package", policy_packages), ("layer", access_layers))
        for item in values
    ]
    has_policy_metadata = any(
        canonicalize_command(response.command) in {"show-packages", "show-access-layers"}
        for response in bundle.responses
    )
    package_by_identity = {(item.domain_name or "global", item.uid): item for item in policy_packages if item.uid}
    layer_by_identity = {(item.domain_name or "global", item.uid): item for item in access_layers if item.uid}
    package_by_name = {}
    layer_by_name = {}
    for item in policy_packages:
        package_by_name.setdefault((item.domain_name or "global", item.name), item)
    for item in access_layers:
        layer_by_name.setdefault((item.domain_name or "global", item.name), item)
    for policy in policies:
        domain = policy.checkpoint_domain_name or "global"
        package = package_by_identity.get((domain, policy.policy_package_uid)) or package_by_name.get((domain, policy.policy_package_name or ""))
        layer = layer_by_identity.get((domain, policy.access_layer_uid)) or layer_by_name.get((domain, policy.access_layer_name or ""))
        if package:
            policy.policy_package_uid = package.uid
            policy.checkpoint_package_uid = package.uid
            policy.checkpoint_package_name = package.name
        if layer:
            policy.access_layer_uid = layer.uid
            policy.checkpoint_layer_uid = layer.uid
            policy.checkpoint_layer_name = layer.name
            policy.access_layer_inline = layer.inline
            policy.access_layer_parent_uid = layer.parent_layer_uid
            policy.access_layer_parent_rule_uid = layer.parent_rule_uid
            policy.checkpoint_parent_layer_uid = layer.parent_layer_uid
            policy.checkpoint_parent_rule_uid = layer.parent_rule_uid

    # Step 7: Extract NAT Rulebase
    nat_rules, nat_inv, nat_unsupp = extract_nat_rulebase(
        parse_responses, resolver, scope, rulebase_safety
    )

    https_inspection_rules, https_inv = extract_https_inspection_rulebase(parse_responses)
    certificates, certificate_inv = extract_certificates(object_responses, [vpn_communities, vpn_gateways])
    attach_certificate_usages(certificates, [https_inspection_rules])

    # Apply zone mapping to policies and NAT rules if configured
    if zone_map:
        for pol in policies:
            pol.from_zone = [zone_map.get(z, z) for z in pol.from_zone]
            pol.to_zone = [zone_map.get(z, z) for z in pol.to_zone]
        for nat in nat_rules:
            nat.from_zone = [zone_map.get(z, z) for z in nat.from_zone]
            nat.to_zone = [zone_map.get(z, z) for z in nat.to_zone]

    # Step 8: Build Source Section accounting
    identity_sources, access_roles, identity_inv = extract_identity(parse_responses)
    threat_rules, threat_rule_inv = extract_threat_prevention(parse_responses)
    threat_profiles, threat_profile_inv = extract_threat_profiles(parse_responses)
    source_sections: List[SourceSectionResult] = []
    grouped = group_response_pages(bundle)

    for (cmd, domain, package, layer, gateway), pages in grouped.items():
        domain_name = pages[0].domain_name or pages[0].domain or bundle.domain or domain
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

        package_name = pages[0].package_name or package
        layer_name = pages[0].layer_name or layer
        source_sections.append(create_section_result(
            command=cmd,
            domain=domain,
            package=package_name,
            layer=layer_name,
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

    # Cluster extraction owns persistent HA identity; gateway inventory remains
    # source accounting and must not synthesize a second cluster model.
    high_availability = list(clusters)
    management_access = [
        IRCheckpointManagementAccess(
            name=item.name, source_context=item.source_context, service=item.source_attributes.get("service", item.source_type.removeprefix("gaia-")),
            enabled=item.source_attributes.get("enabled"), port=item.source_attributes.get("port"),
            interface=item.source_attributes.get("interface"),
            management_interface=item.source_attributes.get("interface") if item.source_type == "gaia-management-interface" else None,
            web_enabled=item.source_attributes.get("enabled") if item.source_type == "gaia-web" else None,
            web_ssl_port=item.source_attributes.get("ssl_port"),
            web_session_timeout=item.source_attributes.get("session_timeout"),
            allowed_clients=[item.source_attributes] if item.source_type == "gaia-management-clients" else [],
            ssh_enabled=item.source_attributes.get("enabled") if item.source_type == "gaia-ssh" else None,
            ssh_port=item.source_attributes.get("port") if item.source_type == "gaia-ssh" else None,
            local_admin=[item.source_attributes["username"]] if item.source_type == "gaia-rbac-role" and item.source_attributes.get("username") else [],
            permitted_clients=list(item.source_attributes.get("permitted_clients", [])),
            roles=list(item.source_attributes.get("roles", [])) + ([item.source_attributes["role"]] if item.source_attributes.get("role") else []),
            authorization=dict(item.source_attributes.get("authorization", {})),
            source_attributes=item.source_attributes,
        )
        for item in gaia_inv if (item.source_type or "").startswith("gaia-") and item.source_path.endswith("/management-access")
    ]

    canonical_ir = IRConfig(
        metadata=IRMetadata(
            hostname=hostname,
            source_vendor="checkpoint",
            source_version=bundle.api_version,
        ),
        interfaces=gaia_ifaces,
        high_availability=high_availability,
        checkpoint_management_access=management_access,
        checkpoint_performance=performance_settings,
        checkpoint_policy_packages=policy_packages,
        checkpoint_access_layers=access_layers,
        checkpoint_domains=checkpoint_domains,
        checkpoint_global_assignments=global_assignments,
        certificates=certificates,
        checkpoint_sic_metadata=sic_metadata,
        zones=gaia_zones,
        addresses=addresses,
        address_groups=address_groups,
        services=services,
        service_groups=service_groups,
        applications=applications,
        application_groups=application_groups,
        application_categories=application_categories,
        schedules=schedules,
        schedule_groups=schedule_groups,
        policies=policies,
        nat_rules=nat_rules,
        routes=gaia_routes,
        dns_settings=dns,
        ntp_settings=ntp,
        dhcp_servers=dhcp_servers,
        vpn_communities=vpn_communities,
        vpn_gateways=vpn_gateways,
        local_users=local_users,
        user_groups=user_groups,
        user_ldap_servers=ldap_servers,
        user_radius_servers=radius_servers,
        user_tacacs_servers=tacacs_servers,
        user_saml_servers=saml_servers,
        checkpoint_identity_sources=identity_sources,
        checkpoint_access_roles=access_roles,
        checkpoint_threat_prevention_rules=threat_rules,
        checkpoint_threat_prevention_profiles=threat_profiles,
        https_inspection_rules=https_inspection_rules,
    )

    object_inventory = addr_inv + time_inv + svc_inv + app_inv + https_inv
    _attach_dictionary_provenance(object_inventory, dictionary_provenance)
    _attach_dictionary_provenance(dictionary_evidence_inv, dictionary_provenance)
    all_inventory = (
        object_inventory + dictionary_evidence_inv + access_inv + nat_inv
        + gaia_inv + gateway_inv + collection_inv
        + vpn_inv + auth_inv
        + performance_inv + cluster_inv + certificate_inv + sic_inventory
        + identity_inv + threat_rule_inv + threat_profile_inv
        + global_assignment_inv
        + (policy_context_inv if has_policy_metadata else [])
    )
    all_unsupported = addr_unsupp + time_unsupp + svc_unsupp + access_unsupp + nat_unsupp + gaia_unsupp + gateway_unsupp + vpn_unsupp + auth_unsupp

    # One final pass owns section status, counts, domains, collection evidence,
    # and duplicate handling after every parser and resolver has completed.
    coverage = aggregate_checkpoint_coverage(
        all_inventory,
        bundle.responses,
        bundle.collection_completeness,
    )
    apply_checkpoint_coverage(source_sections, coverage)

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
        coverage=coverage,
        inventory_items=all_inventory,
        unsupported_items=all_unsupported,
        requires_manual_review=requires_manual_review,
        migration_complete=not requires_manual_review,
        generation_safe=generation_safe,
        blocking_reasons=blocking_reasons,
    )

    return sanitize_extraction_result(raw_result)
