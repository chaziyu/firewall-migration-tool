"""Derived PAN-OS/Panorama effective policy ordering metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem


@dataclass(frozen=True)
class PANEffectivePolicyPosition:
    context: str
    layer: str
    rank: int
    scope_chain: List[str]
    rule_index: int
    complete: bool

    def as_dict(self) -> dict:
        return {
            "effective_policy_layer": self.layer,
            "effective_policy_rank": self.rank,
            "effective_scope_chain": self.scope_chain,
            "effective_rule_index": self.rule_index,
            "effective_order_complete": self.complete,
        }


def _source_index(item: SourceInventoryItem) -> int:
    value = item.source_attributes.get("pan_source_rule_index")
    return value if isinstance(value, int) else 2**31


def _rules(items: Iterable[SourceInventoryItem], kind: str, name: str,
           position: str, defaults: bool = False,
           device_serial: Optional[str] = None) -> List[SourceInventoryItem]:
    allowed = {"default_security_rules"} if defaults else {"policies"}
    return sorted(
        [item for item in items
         if item.domain in allowed
         and item.source_attributes.get("scope_kind") == kind
         and item.source_attributes.get("scope_name") == name
         and item.source_attributes.get("pan_rulebase_position") == position
         and ((device_serial is None and not item.source_attributes.get("scope_device_serial"))
              or (device_serial is not None
                  and item.source_attributes.get("scope_device_serial") == device_serial))],
        key=_source_index,
    )


def _defaults(items: Iterable[SourceInventoryItem], kind: str, name: str,
              device_serial: Optional[str] = None) -> List[SourceInventoryItem]:
    return sorted(
        [item for item in items if item.domain == "default_security_rules"
         and item.source_attributes.get("scope_kind") == kind
         and item.source_attributes.get("scope_name") == name
         and ((device_serial is None and not item.source_attributes.get("scope_device_serial"))
              or (device_serial is not None
                  and item.source_attributes.get("scope_device_serial") == device_serial))],
        key=lambda item: (str(item.name), _source_index(item)),
    )


def _chain(target: str, parents: Dict[str, str]) -> tuple[List[str], bool]:
    chain = [target]
    visited = {target}
    current = target
    complete = True
    while current in parents:
        parent = parents[current]
        if parent in visited:
            complete = False
            break
        visited.add(parent)
        chain.append(parent)
        current = parent
    chain.reverse()
    return chain, complete


def _annotate(sequence: List[tuple[str, SourceInventoryItem]], context: str,
              scope_chain: List[str], complete: bool) -> None:
    for rank, (layer, item) in enumerate(sequence):
        position = PANEffectivePolicyPosition(
            context=context, layer=layer, rank=rank, scope_chain=scope_chain,
            rule_index=rank, complete=complete,
        ).as_dict()
        by_context = item.source_attributes.setdefault("pan_effective_order_by_context", {})
        by_context[context] = position
        # Singular evidence is the object's native/effective context.  It never
        # replaces original position or source index.
        native = f"{item.source_attributes.get('scope_kind')}:{item.source_attributes.get('scope_name')}"
        if context == native or "effective_policy_rank" not in item.source_attributes:
            item.source_attributes.update(position)


def apply_effective_policy_order(extraction, resolver) -> None:
    """Attach deterministic derived order without duplicating terminal records."""
    items = extraction.inventory_items
    parents = dict(resolver._dg_parents)
    hierarchy_errors = any(
        item.domain == "panorama_hierarchy" and item.status == ExtractionStatus.PARSE_ERROR
        for item in items
    )
    device_groups = sorted({
        item.source_attributes.get("scope_name") for item in items
        if item.source_attributes.get("scope_kind") == "device-group"
    } - {None})

    qualified_vsys = sorted({
        (item.source_attributes.get("scope_device_serial"),
         item.source_attributes.get("scope_name"))
        for item in items
        if item.source_attributes.get("scope_kind") == "vsys"
        and item.source_attributes.get("scope_device_serial")
    })
    unqualified_vsys = {
        item.source_attributes.get("scope_name")
        for item in items
        if item.source_attributes.get("scope_kind") == "vsys"
        and not item.source_attributes.get("scope_device_serial")
    }
    qualified_by_dg: Dict[str, List[tuple[str, str]]] = {}
    for serial, vsys in qualified_vsys:
        dg = resolver.device_group_for_vsys(vsys, serial)
        if dg:
            qualified_by_dg.setdefault(dg, []).append((serial, vsys))

    for target in device_groups:
        chain, chain_complete = _chain(target, parents)
        scope_chain = ["shared", *chain]
        sequence: List[tuple[str, SourceInventoryItem]] = []
        sequence += [("shared-pre-rules", item) for item in _rules(items, "shared", "shared", "pre")]
        for dg in chain[:-1]:
            sequence += [("ancestor-device-group-pre-rules", item)
                         for item in _rules(items, "device-group", dg, "pre")]
        sequence += [("current-device-group-pre-rules", item)
                     for item in _rules(items, "device-group", target, "pre")]
        managed_for_target = qualified_by_dg.get(target, [])
        if not managed_for_target:
            for vsys, dg in sorted(resolver._vsys_dg.items()):
                if dg == target:
                    sequence += [("local-firewall-rules", item)
                                 for item in _rules(items, "vsys", vsys, "local")]
        elif len(managed_for_target) == 1:
            serial, vsys = managed_for_target[0]
            sequence += [("local-firewall-rules", item)
                         for item in _rules(items, "vsys", vsys, "local", device_serial=serial)]
            # Some exports keep the Panorama-local VSYS rulebase alongside a
            # managed-device membership record.  It is unqualified and is
            # safe to include only in this single-device preview.
            sequence += [("local-firewall-rules", item)
                         for item in _rules(items, "vsys", vsys, "local")]
        sequence += [("current-device-group-post-rules", item)
                     for item in _rules(items, "device-group", target, "post")]
        for dg in reversed(chain[:-1]):
            sequence += [("ancestor-device-group-post-rules", item)
                         for item in _rules(items, "device-group", dg, "post")]
        sequence += [("shared-post-rules", item) for item in _rules(items, "shared", "shared", "post")]
        # Default override precedence is firewall -> current DG -> ancestors -> shared.
        defaults: Dict[str, SourceInventoryItem] = {}
        for kind, name in [("shared", "shared"), *[("device-group", dg) for dg in chain]]:
            for item in _defaults(items, kind, name):
                defaults[item.name or ""] = item
        if not managed_for_target:
            for vsys, dg in sorted(resolver._vsys_dg.items()):
                if dg == target:
                    for item in _defaults(items, "vsys", vsys):
                        defaults[item.name or ""] = item
        elif len(managed_for_target) == 1:
            serial, vsys = managed_for_target[0]
            for item in _defaults(items, "vsys", vsys, device_serial=serial):
                defaults[item.name or ""] = item
            for item in _defaults(items, "vsys", vsys):
                defaults[item.name or ""] = item
        sequence += [("default-rules", item) for item in sorted(defaults.values(), key=_source_index)]
        _annotate(sequence, f"device-group:{target}", scope_chain,
                  chain_complete and not hierarchy_errors)

    # Panorama effective order is calculated independently for every managed
    # firewall/VSYS.  Local rules from another firewall are never merged into
    # this sequence merely because both devices use the same VSYS name.
    for serial, vsys in qualified_vsys:
        dg = resolver.device_group_for_vsys(vsys, serial)
        if not dg:
            continue
        chain, chain_complete = _chain(dg, parents)
        scope_chain = ["shared", *chain, f"device:{serial}:vsys:{vsys}"]
        sequence: List[tuple[str, SourceInventoryItem]] = []
        sequence += [("shared-pre-rules", item) for item in _rules(items, "shared", "shared", "pre")]
        for ancestor in chain[:-1]:
            sequence += [("ancestor-device-group-pre-rules", item)
                         for item in _rules(items, "device-group", ancestor, "pre")]
        sequence += [("current-device-group-pre-rules", item)
                     for item in _rules(items, "device-group", dg, "pre")]
        sequence += [("local-firewall-rules", item)
                     for item in _rules(items, "vsys", vsys, "local", device_serial=serial)]
        sequence += [("current-device-group-post-rules", item)
                     for item in _rules(items, "device-group", dg, "post")]
        for ancestor in reversed(chain[:-1]):
            sequence += [("ancestor-device-group-post-rules", item)
                         for item in _rules(items, "device-group", ancestor, "post")]
        sequence += [("shared-post-rules", item) for item in _rules(items, "shared", "shared", "post")]
        defaults: Dict[str, SourceInventoryItem] = {}
        for kind, name in [("shared", "shared"), *[("device-group", parent) for parent in chain]]:
            for item in _defaults(items, kind, name):
                defaults[item.name or ""] = item
        for item in _defaults(items, "vsys", vsys, device_serial=serial):
            defaults[item.name or ""] = item
        sequence += [("default-rules", item) for item in sorted(defaults.values(), key=_source_index)]
        complete = chain_complete and not hierarchy_errors
        context = f"device:{serial}:vsys:{vsys}"
        _annotate(sequence, context, scope_chain, complete)
        if len(qualified_vsys) == 1 and vsys not in unqualified_vsys:
            # Existing consumers used this alias for a single managed device.
            _annotate(sequence, f"vsys:{vsys}", ["shared", *chain, f"vsys:{vsys}"], complete)

    # Standalone firewall ordering is complete without Panorama metadata.
    vsys_names = sorted({
        item.source_attributes.get("scope_name") for item in items
        if item.source_attributes.get("scope_kind") == "vsys"
    } - {None})
    for vsys in vsys_names:
        if any(name == vsys for _, name in qualified_vsys) and vsys not in unqualified_vsys:
            continue
        dg = resolver._vsys_dg.get(vsys)
        if dg:
            chain, chain_complete = _chain(dg, parents)
            scope_chain = ["shared", *chain, f"vsys:{vsys}"]
            sequence = []
            sequence += [("shared-pre-rules", item) for item in _rules(items, "shared", "shared", "pre")]
            for ancestor in chain:
                layer = "current-device-group-pre-rules" if ancestor == dg else "ancestor-device-group-pre-rules"
                sequence += [(layer, item) for item in _rules(items, "device-group", ancestor, "pre")]
            sequence += [("local-firewall-rules", item) for item in _rules(items, "vsys", vsys, "local")]
            for ancestor in reversed(chain):
                layer = "current-device-group-post-rules" if ancestor == dg else "ancestor-device-group-post-rules"
                sequence += [(layer, item) for item in _rules(items, "device-group", ancestor, "post")]
            sequence += [("shared-post-rules", item) for item in _rules(items, "shared", "shared", "post")]
            defaults: Dict[str, SourceInventoryItem] = {}
            for kind, name in [("shared", "shared"), *[("device-group", ancestor) for ancestor in chain],
                               ("vsys", vsys)]:
                for item in _defaults(items, kind, name):
                    defaults[item.name or ""] = item
            complete = chain_complete and not hierarchy_errors
        else:
            scope_chain = [f"vsys:{vsys}"]
            sequence = [("local-firewall-rules", item) for item in _rules(items, "vsys", vsys, "local")]
            defaults = {item.name or "": item for item in _defaults(items, "vsys", vsys)}
            complete = True
        sequence += [("default-rules", item) for item in sorted(defaults.values(), key=_source_index)]
        _annotate(sequence, f"vsys:{vsys}", scope_chain, complete)

    # Propagate derived evidence into canonical Security policies by stable ID.
    by_id = {
        item.source_attributes.get("pan_source_rule_id"): item
        for item in items if item.source_attributes.get("pan_source_rule_id")
    }
    for policy in extraction.canonical_ir.policies:
        item = by_id.get(policy.source_rule_id)
        if item:
            for key in ("effective_policy_layer", "effective_policy_rank", "effective_scope_chain",
                        "effective_rule_index", "effective_order_complete", "pan_effective_order_by_context"):
                if key in item.source_attributes:
                    policy.source_extra_settings[key] = item.source_attributes[key]
