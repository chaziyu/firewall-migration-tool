"""Post-extraction fidelity accounting for Check Point policy and NAT semantics.

The portable IR is intentionally flat in several places where Check Point is
hierarchical. This module enriches already-accounted source records instead of
creating new top-level inventory rows or flattening semantics unsafely.

It preserves:
* Access package ordered-layer order and inline parent/child relationships.
* Automatic NAT object settings and object-to-generated-rule references.
* NAT manual/automatic origin, install targets, proxy-ARP evidence and package.
* Identity/no-translation NAT ordering barriers and their effect on later rules.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fwmigrate.extraction.models import ExtractionResult, SourceInventoryItem


_AUTOMATIC_ENABLE_KEYS = ("auto-rule", "auto_rule", "auto-stat", "auto_stat")
_AUTOMATIC_RULE_KEYS = (
    "auto-generated", "auto_generated", "automatic", "automatic-rule", "automatic_rule",
)
_INSTALL_ON_KEYS = ("install-on", "install_on", "installation-targets", "installation_targets")
_PROXY_ARP_KEYS = (
    "proxy-arp", "proxy_arp", "enable-arp-proxy", "enable_arp_proxy",
    "add-proxy-arp", "add_proxy_arp",
)


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first_present(source: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in source:
            return source[key]
    return None


def _ref_key(value: Any) -> Optional[str]:
    if isinstance(value, dict):
        value = value.get("uid") or value.get("name")
    return str(value) if value not in (None, "") else None


def _ref_label(value: Any) -> str:
    return _ref_key(value) or "<unresolved>"


def _is_original(value: Any) -> bool:
    if isinstance(value, dict):
        return (
            str(value.get("type") or "").strip().lower() == "cpmioriginalobject"
            or str(value.get("uid") or "").strip().lower()
            == "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c"
            or str(value.get("name") or "").strip().lower() == "original"
        )
    return str(value or "").strip().lower() in {
        "original", "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c",
    }


def _rule_number(attributes: Dict[str, Any]) -> Optional[int]:
    provenance = attributes.get("checkpoint-provenance")
    value = provenance.get("rule-number") if isinstance(provenance, dict) else None
    if value is None:
        value = attributes.get("rule-number")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _rule_uid(item: SourceInventoryItem) -> Optional[str]:
    if item.source_id:
        return str(item.source_id)
    provenance = item.source_attributes.get("checkpoint-provenance")
    if isinstance(provenance, dict) and provenance.get("rule-uid"):
        return str(provenance["rule-uid"])
    value = item.source_attributes.get("uid")
    return str(value) if value else None


def _nat_scope(item: SourceInventoryItem) -> Tuple[str, Optional[str]]:
    provenance = item.source_attributes.get("checkpoint-provenance")
    package = provenance.get("package") if isinstance(provenance, dict) else None
    if not package:
        prefix = "checkpoint/show-nat-rulebase/"
        if item.source_path.startswith(prefix):
            package = item.source_path[len(prefix):].split("/", 1)[0]
            if package == "<missing-package>":
                package = None
    return item.domain or "global", str(package) if package else None


def _normalized_install_on(attributes: Dict[str, Any]) -> List[str]:
    raw = _first_present(attributes, _INSTALL_ON_KEYS)
    return [_ref_label(value) for value in _as_list(raw) if value not in (None, "")]


def _proxy_arp_value(attributes: Dict[str, Any]) -> Any:
    return _first_present(attributes, _PROXY_ARP_KEYS)


def _automatic_nat_payload(item: SourceInventoryItem) -> Optional[Dict[str, Any]]:
    settings = item.source_attributes.get("nat-settings")
    if not isinstance(settings, dict):
        return None

    enabled = _first_present(settings, _AUTOMATIC_ENABLE_KEYS)
    method = settings.get("method") or settings.get("nat-method") or settings.get("nat_method")
    if enabled is not True and not method:
        return None

    hide_behind = _first_present(settings, (
        "hide-behind", "hide_behind", "hide-behind-gateway", "hide_behind_gateway",
        "hide-behind-interface", "hide_behind_interface",
    ))
    translated_ipv4 = _first_present(settings, (
        "ipv4-address", "ipv4_address", "translated-ipv4-address", "translated_ipv4_address",
        "translated-address", "translated_address",
    ))
    translated_ipv6 = _first_present(settings, (
        "ipv6-address", "ipv6_address", "translated-ipv6-address", "translated_ipv6_address",
    ))
    install_on = _normalized_install_on(settings)
    proxy_arp = _proxy_arp_value(settings)

    return {
        "object_uid": item.source_id,
        "object_name": item.name,
        "object_type": item.source_type,
        "automatic_nat_enabled": enabled if isinstance(enabled, bool) else None,
        "method": str(method).strip().lower() if method is not None else None,
        "hide_behind": hide_behind,
        "hide_behind_gateway": (
            str(hide_behind).strip().lower()
            in {"gateway", "interface", "gateway/interface", "gateway-interface"}
            if hide_behind is not None else None
        ),
        "translated_ipv4": translated_ipv4,
        "translated_ipv6": translated_ipv6,
        "install_on": install_on,
        "proxy_arp": proxy_arp,
        "raw_nat_settings": dict(settings),
    }


def _annotate_automatic_nat_objects(
    result: ExtractionResult,
) -> Dict[Tuple[str, str], SourceInventoryItem]:
    """Attach a structured automatic-NAT view to the existing owning object row."""
    by_ref: Dict[Tuple[str, str], SourceInventoryItem] = {}
    for item in result.inventory_items:
        payload = _automatic_nat_payload(item)
        if payload is None:
            continue
        item.source_attributes["checkpoint-automatic-nat"] = payload
        if "automatic-nat-settings-preserved" not in item.notes:
            item.notes.append("automatic-nat-settings-preserved")
        for ref in (item.source_id, item.name):
            if ref:
                by_ref[(item.domain, str(ref))] = item
    return by_ref


def _automatic_object_refs_for_rule(
    item: SourceInventoryItem,
    automatic_objects: Dict[Tuple[str, str], SourceInventoryItem],
) -> List[str]:
    refs: List[str] = []
    for field in (
        "original-source", "original-destination", "translated-source", "translated-destination",
    ):
        ref = _ref_key(item.source_attributes.get(field))
        if ref and (item.domain, ref) in automatic_objects and ref not in refs:
            refs.append(ref)
    return refs


def _nat_origin(item: SourceInventoryItem, automatic_object_refs: List[str]) -> str:
    attributes = item.source_attributes
    explicit = _first_present(attributes, _AUTOMATIC_RULE_KEYS)
    if explicit is True:
        return "automatic"
    if explicit is False:
        return "manual"

    provenance = attributes.get("checkpoint-provenance")
    section = provenance.get("section-path") if isinstance(provenance, dict) else None
    section_text = str(section or "").strip().lower()
    if "automatic generated" in section_text or section_text.startswith("nat rules for "):
        return "automatic"
    if "manual" in section_text:
        return "manual"

    # An object can have automatic NAT enabled and still be referenced by a
    # manually authored rule. Do not infer automatic origin from that alone.
    if automatic_object_refs:
        return "unknown"
    return "manual"


def _identity_nat(attributes: Dict[str, Any]) -> bool:
    translated = (
        attributes.get("translated-source"),
        attributes.get("translated-destination"),
        attributes.get("translated-service"),
    )
    return all(value is not None and _is_original(value) for value in translated)


def _gateway_reference_index(result: ExtractionResult) -> Dict[Tuple[str, str], str]:
    refs: Dict[Tuple[str, str], str] = {}
    for item in result.inventory_items:
        if not item.source_path.startswith("checkpoint/show-gateways-and-servers"):
            continue
        target = f"{item.source_path}#{item.source_id or item.name}"
        for ref in (item.source_id, item.name):
            if ref:
                refs[(item.domain, str(ref))] = target
    return refs


def _correlate_nat_inventory(
    result: ExtractionResult,
    automatic_objects: Dict[Tuple[str, str], SourceInventoryItem],
) -> Dict[Tuple[str, Optional[str]], List[SourceInventoryItem]]:
    gateway_refs = _gateway_reference_index(result)
    by_scope: Dict[Tuple[str, Optional[str]], List[SourceInventoryItem]] = defaultdict(list)

    for item in result.inventory_items:
        if item.source_type != "nat-rule":
            continue
        scope = _nat_scope(item)
        by_scope[scope].append(item)
        attributes = item.source_attributes
        automatic_refs = _automatic_object_refs_for_rule(item, automatic_objects)
        origin = _nat_origin(item, automatic_refs)
        install_on = _normalized_install_on(attributes)
        semantic = "identity" if _identity_nat(attributes) else "translation"

        attributes["checkpoint-nat-origin"] = origin
        attributes["checkpoint-nat-semantic"] = semantic
        attributes["checkpoint-rulebase-sequence"] = _rule_number(attributes)
        attributes["checkpoint-install-on"] = install_on
        attributes["checkpoint-proxy-arp"] = _proxy_arp_value(attributes)
        attributes["checkpoint-enforcement-mode"] = (
            "automatic-combinable" if origin == "automatic"
            else "manual-first-match" if origin == "manual"
            else "unknown"
        )
        if semantic == "identity":
            attributes["checkpoint-ordering-barrier"] = True
            if "checkpoint-identity-nat-ordering-barrier" not in item.notes:
                item.notes.append("checkpoint-identity-nat-ordering-barrier")

        if automatic_refs:
            attributes["checkpoint-automatic-nat-object-refs"] = list(automatic_refs)
            for ref in automatic_refs:
                owner = automatic_objects.get((item.domain, ref))
                if owner:
                    rule_link = f"{item.source_path}#{_rule_uid(item) or item.name}"
                    if rule_link not in owner.source_references:
                        owner.source_references.append(rule_link)
                    object_link = f"{owner.source_path}#{owner.source_id or owner.name}"
                    if object_link not in item.source_references:
                        item.source_references.append(object_link)

        for target in install_on:
            gateway_link = gateway_refs.get((item.domain, target))
            if gateway_link and gateway_link not in item.source_references:
                item.source_references.append(gateway_link)

    for items in by_scope.values():
        items.sort(key=lambda item: (
            _rule_number(item.source_attributes) is None,
            _rule_number(item.source_attributes) or 0,
        ))
    return by_scope


def _canonical_nat_key(rule: Any) -> Tuple[Optional[int], str]:
    sequence = getattr(rule, "sequence", None)
    try:
        sequence = int(sequence) if sequence is not None else None
    except (TypeError, ValueError):
        sequence = None
    return sequence, str(getattr(rule, "name", ""))


def _enrich_canonical_nat(
    result: ExtractionResult,
    inventory_by_scope: Dict[Tuple[str, Optional[str]], List[SourceInventoryItem]],
) -> None:
    canonical_rules = list(getattr(result.canonical_ir, "nat_rules", []))
    candidates: Dict[Tuple[Optional[int], str], List[SourceInventoryItem]] = defaultdict(list)
    for items in inventory_by_scope.values():
        for item in items:
            candidates[(_rule_number(item.source_attributes), item.name or "")].append(item)

    for rule in canonical_rules:
        matching = candidates.get(_canonical_nat_key(rule), [])
        if len(matching) != 1:
            continue
        source_item = matching[0]
        domain, package = _nat_scope(source_item)
        source_attributes = dict(getattr(rule, "source_attributes", {}) or {})
        source_attributes.update({
            key: value for key, value in source_item.source_attributes.items()
            if key.startswith("checkpoint-")
        })
        source_attributes["checkpoint-package"] = package
        source_attributes["checkpoint-domain"] = domain
        source_attributes["checkpoint-rule-uid"] = _rule_uid(source_item)
        rule.source_attributes = source_attributes
        rule.source_context = f"{domain}/{package or '<missing-package>'}"
        rule.source_origin = source_item.source_attributes.get("checkpoint-nat-origin")

        sequence = getattr(rule, "sequence", None)
        preceding_identity = [
            {
                "uid": _rule_uid(item),
                "name": item.name,
                "sequence": _rule_number(item.source_attributes),
            }
            for item in inventory_by_scope.get((domain, package), [])
            if item.source_attributes.get("checkpoint-nat-semantic") == "identity"
            and sequence is not None
            and (_rule_number(item.source_attributes) or -1) < sequence
        ]
        if preceding_identity:
            rule.source_attributes["checkpoint-preceding-identity-rules"] = preceding_identity
            rule.requires_manual_review = True
            rule.migration_status = "PARTIALLY_NORMALIZED"
            if "checkpoint-identity-nat-precedence" not in rule.review_reasons:
                rule.review_reasons.append("checkpoint-identity-nat-precedence")

    if any(
        item.source_attributes.get("checkpoint-nat-semantic") == "identity"
        for items in inventory_by_scope.values() for item in items
    ):
        _block_generation(result, "checkpoint-identity-nat-ordering-requires-manual-review")


def _annotate_policy_hierarchy(result: ExtractionResult) -> None:
    ir = result.canonical_ir
    packages = list(getattr(ir, "checkpoint_policy_packages", []))
    layers = list(getattr(ir, "checkpoint_access_layers", []))
    assignments = list(getattr(ir, "checkpoint_global_assignments", []))
    if not packages:
        return

    layer_by_uid = {
        ((getattr(layer, "domain_name", None) or "global"), str(layer.uid)): layer
        for layer in layers if getattr(layer, "uid", None)
    }
    layer_by_name = {
        ((getattr(layer, "domain_name", None) or "global"), str(layer.name)): layer
        for layer in layers
    }
    layer_inventory = {
        (item.domain, str(item.source_id or item.name)): item
        for item in result.inventory_items
        if item.source_path == "checkpoint/show-access-layers"
    }

    for package in packages:
        domain = getattr(package, "domain_name", None) or "global"
        layer_uids = list(getattr(package, "access_layer_uids", []) or [])
        layer_names = list(getattr(package, "access_layer_names", []) or [])
        ordered: List[Dict[str, Any]] = []
        for index in range(max(len(layer_uids), len(layer_names))):
            uid = layer_uids[index] if index < len(layer_uids) else None
            name = layer_names[index] if index < len(layer_names) else None
            layer = (layer_by_uid.get((domain, str(uid))) if uid else None) or (
                layer_by_name.get((domain, str(name))) if name else None
            )
            entry = {
                "position": index + 1,
                "uid": uid or getattr(layer, "uid", None),
                "name": name or getattr(layer, "name", None),
                "inline": bool(getattr(layer, "inline", False)) if layer else False,
                "parent_layer_uid": getattr(layer, "parent_layer_uid", None) if layer else None,
                "parent_rule_uid": getattr(layer, "parent_rule_uid", None) if layer else None,
                "rule_uids": list(getattr(layer, "rule_uids", []) or []) if layer else [],
            }
            ordered.append(entry)
            if layer:
                layer.source_attributes["checkpoint-ordered-layer-position"] = index + 1
                layer.source_attributes["checkpoint-package-uid"] = getattr(package, "uid", None)
                layer.source_attributes["checkpoint-package-name"] = getattr(package, "name", None)
                inv = layer_inventory.get((domain, str(getattr(layer, "uid", None) or layer.name)))
                if inv:
                    inv.source_attributes["checkpoint-ordered-layer-position"] = index + 1
                    inv.source_attributes["checkpoint-package-uid"] = getattr(package, "uid", None)

        inline_layers = [
            {
                "uid": getattr(layer, "uid", None),
                "name": getattr(layer, "name", None),
                "parent_layer_uid": getattr(layer, "parent_layer_uid", None),
                "parent_layer_name": getattr(layer, "parent_layer_name", None),
                "parent_rule_uid": getattr(layer, "parent_rule_uid", None),
                "parent_rule_number": getattr(layer, "parent_rule_number", None),
                "rule_uids": list(getattr(layer, "rule_uids", []) or []),
            }
            for layer in layers
            if bool(getattr(layer, "inline", False))
            and (getattr(layer, "domain_name", None) or "global") == domain
            and (
                getattr(layer, "package_uid", None) == getattr(package, "uid", None)
                or getattr(layer, "package_name", None) == getattr(package, "name", None)
            )
        ]

        relevant_assignments = []
        for assignment in assignments:
            target_uid = getattr(assignment, "target_domain_uid", None)
            target_name = getattr(assignment, "target_domain_name", None)
            local_uid = getattr(assignment, "local_package_uid", None)
            local_name = getattr(assignment, "local_package_name", None)
            if target_uid and target_uid != getattr(package, "domain_uid", None):
                continue
            if target_name and target_name != domain:
                continue
            if local_uid and local_uid != getattr(package, "uid", None):
                continue
            if local_name and local_name != getattr(package, "name", None):
                continue
            relevant_assignments.append({
                "uid": getattr(assignment, "uid", None),
                "global_package_uid": getattr(assignment, "global_package_uid", None),
                "global_package_name": getattr(assignment, "global_package_name", None),
                "assigned_policies": list(getattr(assignment, "assigned_policies", []) or []),
                "assigned_objects": list(getattr(assignment, "assigned_objects", []) or []),
                "state": getattr(assignment, "state", None),
                "mode": getattr(assignment, "mode", None),
            })

        package.source_attributes["checkpoint-access-layer-order"] = ordered
        package.source_attributes["checkpoint-inline-layers"] = inline_layers
        package.source_attributes["checkpoint-global-assignments"] = relevant_assignments
        package_uid = getattr(package, "uid", None)
        package_name = getattr(package, "name", None)
        matching_inventory = [
            item
            for item in result.inventory_items
            if item.source_path == "checkpoint/show-packages"
            and item.domain == domain
            and (
                item.source_id == package_uid
                if package_uid
                else item.name == package_name
            )
        ]
        for inv in matching_inventory:
            inv.source_attributes["checkpoint-access-layer-order"] = ordered
            inv.source_attributes["checkpoint-inline-layers"] = inline_layers
            inv.source_attributes["checkpoint-global-assignments"] = relevant_assignments


def _block_generation(result: ExtractionResult, reason: str) -> None:
    result.requires_manual_review = True
    result.migration_complete = False
    result.generation_safe = False
    if reason not in result.blocking_reasons:
        result.blocking_reasons.append(reason)

    ir = result.canonical_ir
    if hasattr(ir, "generation_safe"):
        ir.generation_safe = False
    reasons = getattr(ir, "generation_blocking_reasons", None)
    if isinstance(reasons, list) and reason not in reasons:
        reasons.append(reason)


def apply_checkpoint_fidelity(result: ExtractionResult) -> ExtractionResult:
    """Attach non-lossy Check Point policy/NAT relationships to existing output."""
    automatic_objects = _annotate_automatic_nat_objects(result)
    inventory_by_scope = _correlate_nat_inventory(result, automatic_objects)
    _enrich_canonical_nat(result, inventory_by_scope)
    _annotate_policy_hierarchy(result)
    return result
