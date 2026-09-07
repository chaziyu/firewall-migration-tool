"""Post-extraction fidelity accounting for Check Point policy and NAT semantics.

This module deliberately enriches source evidence instead of flattening vendor
semantics that the portable IR cannot represent safely.  In particular:

* Ordered/inline Access Layer hierarchy is recorded explicitly.
* Automatic NAT settings are emitted as dedicated source inventory records.
* Manual/automatic NAT origin, install targets, proxy-ARP evidence and native
  rulebase order are correlated back to canonical NAT rows.
* Identity/no-translation NAT rules remain non-deployable ordering barriers so
  later translations cannot be generated without acknowledging their effect.

No target-vendor assumptions belong here.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fwmigrate.extraction.models import ExtractionResult, ExtractionStatus, SourceInventoryItem


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
    if value in (None, ""):
        return None
    return str(value)


def _ref_label(value: Any) -> str:
    key = _ref_key(value)
    return key or "<unresolved>"


def _is_original(value: Any) -> bool:
    if isinstance(value, dict):
        value_type = str(value.get("type") or "").strip().lower()
        value_uid = str(value.get("uid") or "").strip().lower()
        value_name = str(value.get("name") or "").strip().lower()
        return (
            value_type == "cpmioriginalobject"
            or value_uid == "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c"
            or value_name == "original"
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
    attributes = item.source_attributes
    provenance = attributes.get("checkpoint-provenance")
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

    enable_value = _first_present(settings, _AUTOMATIC_ENABLE_KEYS)
    method = settings.get("method") or settings.get("nat-method") or settings.get("nat_method")
    if enable_value is not True and not method:
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
        "automatic_nat_enabled": enable_value if isinstance(enable_value, bool) else None,
        "method": str(method).strip().lower() if method is not None else None,
        "hide_behind": hide_behind,
        "hide_behind_gateway": str(hide_behind).strip().lower() in {
            "gateway", "interface", "gateway/interface", "gateway-interface",
        } if hide_behind is not None else None,
        "translated_ipv4": translated_ipv4,
        "translated_ipv6": translated_ipv6,
        "install_on": install_on,
        "proxy_arp": proxy_arp,
        "raw_nat_settings": dict(settings),
    }


def _automatic_nat_inventory(
    result: ExtractionResult,
) -> Dict[Tuple[str, str], SourceInventoryItem]:
    """Create one explicit automatic-NAT source record per owning object."""
    by_ref: Dict[Tuple[str, str], SourceInventoryItem] = {}
    additions: List[SourceInventoryItem] = []
    existing = {
        (item.domain, item.source_id or item.name)
        for item in result.inventory_items
        if item.source_type == "checkpoint-automatic-nat-settings"
    }

    for item in list(result.inventory_items):
        if item.source_type == "checkpoint-automatic-nat-settings":
            for ref in (item.source_id, item.name):
                if ref:
                    by_ref[(item.domain, str(ref))] = item
            continue
        payload = _automatic_nat_payload(item)
        if payload is None:
            continue

        identity = item.source_id or item.name
        if identity and (item.domain, identity) in existing:
            continue
        notes = ["automatic-nat-settings-preserved"]
        if payload["method"] not in {"hide", "static"}:
            notes.append("automatic-nat-method-requires-review")
        if not payload["install_on"]:
            notes.append("automatic-nat-install-target-not-explicit-in-object-settings")
        record = SourceInventoryItem(
            domain=item.domain,
            domain_uid=item.domain_uid,
            domain_name=item.domain_name,
            source_path=f"{item.source_path}/nat-settings",
            name=item.name,
            source_id=item.source_id,
            source_type="checkpoint-automatic-nat-settings",
            source_context=item.source_context,
            source_attributes=payload,
            source_references=[
                f"{item.source_path}#{item.source_id or item.name}"
            ] if (item.source_id or item.name) else [],
            status=ExtractionStatus.PARTIALLY_NORMALIZED,
            requires_manual_review=True,
            notes=notes,
        )
        additions.append(record)
        for ref in (item.source_id, item.name):
            if ref:
                by_ref[(item.domain, str(ref))] = record

    result.inventory_items.extend(additions)
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

    # Merely referencing an object that has automatic NAT configured does not
    # prove that this particular rule is auto-generated. Keep that ambiguous.
    if automatic_object_refs:
        return "unknown"
    return "manual"


def _identity_nat(attributes: Dict[str, Any]) -> bool:
    translated = [
        attributes.get("translated-source"),
        attributes.get("translated-destination"),
        attributes.get("translated-service"),
    ]
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
        proxy_arp = _proxy_arp_value(attributes)
        semantic = "identity" if _identity_nat(attributes) else "translation"

        attributes["checkpoint-nat-origin"] = origin
        attributes["checkpoint-nat-semantic"] = semantic
        attributes["checkpoint-rulebase-sequence"] = _rule_number(attributes)
        attributes["checkpoint-install-on"] = install_on
        attributes["checkpoint-proxy-arp"] = proxy_arp
        attributes["checkpoint-enforcement-mode"] = (
            "automatic-combinable" if origin == "automatic"
            else "manual-first-match" if origin == "manual"
            else "unknown"
        )
        if automatic_refs:
            attributes["checkpoint-automatic-nat-object-refs"] = list(automatic_refs)
            for ref in automatic_refs:
                automatic_item = automatic_objects.get((item.domain, ref))
                if automatic_item:
                    link = f"{item.source_path}#{_rule_uid(item) or item.name}"
                    if link not in automatic_item.source_references:
                        automatic_item.source_references.append(link)
                    object_link = f"{automatic_item.source_path}#{automatic_item.source_id or automatic_item.name}"
                    if object_link not in item.source_references:
                        item.source_references.append(object_link)
        for target in install_on:
            gateway_link = gateway_refs.get((item.domain, target))
            if gateway_link and gateway_link not in item.source_references:
                item.source_references.append(gateway_link)

        if semantic == "identity":
            attributes["checkpoint-ordering-barrier"] = True
            if "checkpoint-identity-nat-ordering-barrier" not in item.notes:
                item.notes.append("checkpoint-identity-nat-ordering-barrier")
            item.requires_manual_review = True
            if item.status == ExtractionStatus.NORMALIZED:
                item.status = ExtractionStatus.PARTIALLY_NORMALIZED

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
    if not canonical_rules:
        return

    candidates: Dict[Tuple[Optional[int], str], List[SourceInventoryItem]] = defaultdict(list)
    for items in inventory_by_scope.values():
        for item in items:
            candidates[(_rule_number(item.source_attributes), item.name or "")].append(item)

    identity_exists = False
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

        scope_items = inventory_by_scope.get((domain, package), [])
        preceding_identity = [
            {
                "uid": _rule_uid(item),
                "name": item.name,
                "sequence": _rule_number(item.source_attributes),
            }
            for item in scope_items
            if item.source_attributes.get("checkpoint-nat-semantic") == "identity"
            and (_rule_number(item.source_attributes) or -1) < (getattr(rule, "sequence", None) or -1)
        ]
        if preceding_identity:
            identity_exists = True
            rule.source_attributes["checkpoint-preceding-identity-rules"] = preceding_identity
            rule.requires_manual_review = True
            rule.migration_status = "PARTIALLY_NORMALIZED"
            if "checkpoint-identity-nat-precedence" not in rule.review_reasons:
                rule.review_reasons.append("checkpoint-identity-nat-precedence")

    identity_exists = identity_exists or any(
        item.source_attributes.get("checkpoint-nat-semantic") == "identity"
        for items in inventory_by_scope.values() for item in items
    )
    if identity_exists:
        _block_generation(result, "checkpoint-identity-nat-ordering-requires-manual-review")


def _policy_hierarchy_inventory(result: ExtractionResult) -> None:
    ir = result.canonical_ir
    packages = list(getattr(ir, "checkpoint_policy_packages", []))
    layers = list(getattr(ir, "checkpoint_access_layers", []))
    assignments = list(getattr(ir, "checkpoint_global_assignments", []))
    if not packages and not layers:
        return

    layer_by_uid: Dict[Tuple[str, str], Any] = {}
    layer_by_name: Dict[Tuple[str, str], Any] = {}
    for layer in layers:
        domain = getattr(layer, "domain_name", None) or "global"
        if getattr(layer, "uid", None):
            layer_by_uid[(domain, str(layer.uid))] = layer
        layer_by_name[(domain, str(layer.name))] = layer

    existing = {
        (item.domain, item.source_id or item.name)
        for item in result.inventory_items
        if item.source_type == "checkpoint-policy-hierarchy"
    }
    additions: List[SourceInventoryItem] = []

    for package in packages:
        domain = getattr(package, "domain_name", None) or "global"
        ordered: List[Dict[str, Any]] = []
        layer_uids = list(getattr(package, "access_layer_uids", []) or [])
        layer_names = list(getattr(package, "access_layer_names", []) or [])
        refs: List[str] = []
        count = max(len(layer_uids), len(layer_names))
        for index in range(count):
            uid = layer_uids[index] if index < len(layer_uids) else None
            name = layer_names[index] if index < len(layer_names) else None
            layer = (
                layer_by_uid.get((domain, str(uid))) if uid else None
            ) or (
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
                refs.append(f"checkpoint/show-access-layers#{getattr(layer, 'uid', None) or layer.name}")

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
            target_domain_uid = getattr(assignment, "target_domain_uid", None)
            target_domain_name = getattr(assignment, "target_domain_name", None)
            local_package_uid = getattr(assignment, "local_package_uid", None)
            local_package_name = getattr(assignment, "local_package_name", None)
            if target_domain_uid and target_domain_uid != getattr(package, "domain_uid", None):
                continue
            if target_domain_name and target_domain_name != domain:
                continue
            if local_package_uid and local_package_uid != getattr(package, "uid", None):
                continue
            if local_package_name and local_package_name != getattr(package, "name", None):
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
        if inline_layers:
            package.source_attributes["checkpoint-inline-layers"] = inline_layers
        if relevant_assignments:
            package.source_attributes["checkpoint-global-assignments"] = relevant_assignments

        identity = getattr(package, "uid", None) or getattr(package, "name", None)
        if (domain, identity) in existing:
            continue
        review_reasons: List[str] = []
        if len([entry for entry in ordered if not entry["inline"]]) > 1:
            review_reasons.append("ordered-layer-enforcement-not-flattened")
        if inline_layers:
            review_reasons.append("inline-layer-enforcement-not-flattened")
        if any(entry.get("assigned_policies") for entry in relevant_assignments):
            review_reasons.append("global-policy-evaluation-order-not-synthesized")

        additions.append(SourceInventoryItem(
            domain=domain,
            domain_uid=getattr(package, "domain_uid", None),
            domain_name=domain,
            source_path="checkpoint/policy-hierarchy",
            name=getattr(package, "name", None),
            source_id=getattr(package, "uid", None),
            source_type="checkpoint-policy-hierarchy",
            source_context=getattr(package, "source_context", None),
            source_attributes={
                "package_uid": getattr(package, "uid", None),
                "package_name": getattr(package, "name", None),
                "ordered_layers": ordered,
                "inline_layers": inline_layers,
                "installation_targets": list(getattr(package, "installation_targets", []) or []),
                "nat_policy_uid": getattr(package, "nat_policy_uid", None),
                "nat_policy_name": getattr(package, "nat_policy_name", None),
                "global_assignments": relevant_assignments,
            },
            source_references=refs,
            status=(
                ExtractionStatus.PARTIALLY_NORMALIZED if review_reasons
                else ExtractionStatus.NORMALIZED
            ),
            requires_manual_review=bool(review_reasons),
            notes=review_reasons,
        ))

    result.inventory_items.extend(additions)


def _block_generation(result: ExtractionResult, reason: str) -> None:
    result.requires_manual_review = True
    result.migration_complete = False
    result.generation_safe = False
    if reason not in result.blocking_reasons:
        result.blocking_reasons.append(reason)

    ir = result.canonical_ir
    if hasattr(ir, "generation_safe"):
        ir.generation_safe = False
    blocking = getattr(ir, "generation_blocking_reasons", None)
    if isinstance(blocking, list) and reason not in blocking:
        blocking.append(reason)


def apply_checkpoint_fidelity(result: ExtractionResult) -> ExtractionResult:
    """Enrich Check Point extraction with non-lossy policy/NAT relationships."""
    automatic_objects = _automatic_nat_inventory(result)
    inventory_by_scope = _correlate_nat_inventory(result, automatic_objects)
    _enrich_canonical_nat(result, inventory_by_scope)
    _policy_hierarchy_inventory(result)
    return result
