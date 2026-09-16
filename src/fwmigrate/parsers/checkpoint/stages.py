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
from fwmigrate.ir import IRConfig
from fwmigrate.ir.network import (
    IRHighAvailability,
    IRZone,
    IRDNSSettings,
    IRNTPSettings,
    IRNTPServer,
    IRDHCPServer,
    IRDHCPIPRange,
    IRDHCPExcludeRange,
    IRDHCPReservation,
)
from fwmigrate.ir.metadata import (
    IRMetadata,
    IRCheckpointManagementAccess,
)
from fwmigrate.ir.policy import (
    IRCheckpointPolicyPackage,
    IRCheckpointAccessLayer,
    IRCheckpointDomain,
    IRCheckpointGlobalAssignment,
    IRCheckpointAccessRule,
)
from fwmigrate.ir.routing import IRPolicyBasedForwardingRule
from fwmigrate.ir.enums import IRRouteNextHopType
from fwmigrate.parsers.checkpoint.authentication import extract_authentication
from fwmigrate.parsers.checkpoint.identity import extract_identity
from fwmigrate.parsers.checkpoint.access import extract_access_rulebase
from fwmigrate.parsers.checkpoint.coverage import (
    authoritative_object_identity,
    create_section_result,
)
from fwmigrate.parsers.checkpoint.gaia_scope_policy import parse_gaia_configuration
from fwmigrate.parsers.checkpoint.finalization import finalize_checkpoint_extraction
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
from fwmigrate.parsers.checkpoint.ip_pool_nat import extract_ip_pool_nat
from fwmigrate.parsers.checkpoint.dependencies import build_checkpoint_dependencies
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


def _build_gaia_pbr_rules(
    inventory: List[SourceInventoryItem], interface_names: Set[str],
) -> List[IRPolicyBasedForwardingRule]:
    """Promote parsed Gaia PBR inventory without treating it as static routing."""
    tables = {
        str(item.source_attributes.get("table")): item.source_attributes
        for item in inventory if item.source_type == "gaia-pbr-table"
    }
    result: List[IRPolicyBasedForwardingRule] = []
    for item in inventory:
        if item.source_type != "gaia-pbr-rule":
            continue
        attrs = item.source_attributes
        priority = attrs.get("priority")
        table_name = attrs.get("routing_table")
        table = tables.get(str(table_name)) if table_name else None
        table_routes = list(table.get("routes", [])) if table else []
        reasons: List[str] = []
        incoming = attrs.get("incoming_interface")
        if incoming and incoming not in interface_names:
            reasons.append("unresolved-pbr-incoming-interface")
        for route in table_routes:
            if not isinstance(route, dict):
                reasons.append("malformed-pbr-table-route")
                continue
            route_attributes = route.get("source_attributes")
            if isinstance(route_attributes, dict) and route_attributes.get("parse_error"):
                reasons.append(route_attributes["parse_error"])
            table_interface = route.get("outgoing_interface")
            if table_interface and table_interface not in interface_names:
                reasons.append("unresolved-pbr-table-interface")
        if table_name and table is None:
            reasons.append("unresolved-pbr-routing-table")
        action = str(attrs.get("action") or "").strip() or None
        if action and action.lower() not in {"table", "main-table"}:
            reasons.append(f"unsupported-pbr-action:{action}")
        if len(table_routes) > 1:
            reasons.append("pbr-table-multiple-routes-not-flattened")
        effective_table_route = table_routes[0] if len(table_routes) == 1 else {}
        next_hop = effective_table_route.get("next_hop")
        table_interface = effective_table_route.get("outgoing_interface")
        result.append(IRPolicyBasedForwardingRule(
            name=item.name or f"Gaia-PBR-{priority}", source_context=item.source_context,
            source_rule_id=str(priority) if priority is not None else None,
            source_order=int(attrs.get("order") or priority or len(result) + 1),
            rulebase_position="gaia", from_interface=[incoming] if incoming else [],
            source=[attrs["source"]] if attrs.get("source") else [],
            destination=[attrs["destination"]] if attrs.get("destination") else [],
            service=[attrs["service"]] if attrs.get("service") else [],
            action=action, egress_interface=table_interface,
            next_hop_type=IRRouteNextHopType.IP_ADDRESS if next_hop else None,
            next_hop=next_hop, priority=priority, protocol=attrs.get("protocol"),
            destination_port=attrs.get("service"), routing_table=table_name,
            table_next_hop=next_hop, table_output_interface=table_interface,
            enabled=bool(attrs.get("enabled", True)),
            migration_status="PARTIALLY_NORMALIZED" if reasons else "NORMALIZED",
            requires_manual_review=bool(reasons), review_reasons=reasons,
            source_attributes={"rule": attrs, "table": table, "table_routes": table_routes},
        ))
    return sorted(result, key=lambda rule: (rule.priority or 2**31, rule.source_order))


def _checkpoint_ref_labels(value: Any) -> List[str]:
    values = value if isinstance(value, list) else ([] if value is None else [value])
    return [
        str(item.get("name") or item.get("uid") or item)
        if isinstance(item, dict) else str(item)
        for item in values
    ]


def _build_checkpoint_access_rules(
    inventory: List[SourceInventoryItem],
) -> List[IRCheckpointAccessRule]:
    rules: List[IRCheckpointAccessRule] = []
    for item in inventory:
        if item.source_type != "access-rule":
            continue
        attrs = item.source_attributes
        provenance = attrs.get("checkpoint-provenance", {})
        action = attrs.get("action")
        action = action.get("name") or action.get("uid") if isinstance(action, dict) else action
        inline = provenance.get("inline-layer")
        inline_label = _checkpoint_ref_labels(inline)[0] if inline is not None else None
        rule_number = attrs.get("rule-number", provenance.get("rule-number"))
        raw_section_path = provenance.get("section-path")
        section_path = (
            [part for part in raw_section_path.split("/") if part]
            if isinstance(raw_section_path, str) else list(raw_section_path or [])
        )
        resolved_services = attrs.get("checkpoint-resolved-services", [])
        resolved_applications = attrs.get("checkpoint-resolved-applications", [])
        services = _checkpoint_ref_labels(resolved_services)
        applications = _checkpoint_ref_labels(resolved_applications)
        if attrs.get("checkpoint-service-application-any"):
            services = ["any"]
        rules.append(IRCheckpointAccessRule(
            name=item.name or f"Rule_{rule_number or len(rules) + 1}",
            source_uuid=item.source_id,
            rule_number=rule_number,
            source_context=item.source_context,
            domain=provenance.get("domain") or item.domain,
            package=provenance.get("package"), layer=provenance.get("layer"),
            section_path=section_path,
            enabled=attrs.get("enabled"),
            source=_checkpoint_ref_labels(attrs.get("source")),
            destination=_checkpoint_ref_labels(attrs.get("destination")),
            vpn=_checkpoint_ref_labels(attrs.get("vpn")),
            services=services,
            applications=applications,
            access_roles=list(attrs.get("checkpoint-access-role-references", [])),
            action=str(action) if action is not None else None,
            track=attrs.get("track"), time=_checkpoint_ref_labels(attrs.get("time")),
            install_on=_checkpoint_ref_labels(attrs.get("install-on", attrs.get("install_on"))),
            source_negated=attrs.get("source-negate"),
            destination_negated=attrs.get("destination-negate"),
            service_negated=attrs.get("service-negate"),
            content=_checkpoint_ref_labels(attrs.get("content")),
            content_negated=attrs.get("content-negate"),
            inline_layer_reference=inline_label,
            parent_layer=provenance.get("parent-layer") or provenance.get("layer"),
            parent_rule_uid=(
                provenance.get("parent-rule-uid")
                if inline_label or provenance.get("parent-layer") or provenance.get("parent-layer-uid")
                else None
            ),
            comments=attrs.get("comments"), migration_status=item.status.value,
            requires_manual_review=item.requires_manual_review,
            review_reasons=list(item.notes), source_attributes=attrs,
        ))
    return rules




__all__ = ["_dictionary_source_reference","_prepare_dictionary_accounting","_attach_dictionary_provenance","_extract_policy_context","_extract_global_assignments","_build_gaia_pbr_rules","_checkpoint_ref_labels","_build_checkpoint_access_rules"]

