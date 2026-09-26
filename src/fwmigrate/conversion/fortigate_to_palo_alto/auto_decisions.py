"""Deterministic, read-only review classification for FortiGate to PAN-OS."""

from enum import Enum

from .decisions import PANDecisionReviewState, PANMigrationDecisionSet
from .interface_candidates import candidate_evidence
from .target_suggestions import _compatible, _device
from .target_candidates import target_vsys_value
from ...vendors.palo_alto.source_model import pan_scope_identity


class AutoDecisionStatus(str, Enum):
    VERIFIED = "VERIFIED"
    DERIVED = "DERIVED"
    CANDIDATE = "CANDIDATE"
    MANUAL = "MANUAL"


def classify_auto_decisions(config, derived, decisions: PANMigrationDecisionSet, target=None, device=None):
    """Return per-key review results; no result here confirms or mutates a decision."""
    results = {}
    interfaces = {(item.vdom or "root", item.name): item for item in getattr(config, "interfaces", ()) if item.name}
    mapped = {(item.source_vdom, item.source_name): item.value for item in decisions.decisions
              if item.source_kind == "interface" and item.target_field == "target_interface"
              and item.review_state == PANDecisionReviewState.CONFIRMED and item.value}
    target_items, topology = [], {}
    if target is not None:
        records = (*target.config.interfaces, *target.config.interface_units)
        devices = {_device(item) for item in records if _device(item)}
        target_items = [item for item in records
                        if item.name and (device is not None and _device(item) == device
                                          or device is None and len(devices) == 1 and _device(item) in devices)]
        topology = {(item.scope, item.interface): item for item in target.derived.interface_topology}
    for decision in decisions.decisions:
        if decision.review_state == PANDecisionReviewState.CONFIRMED:
            results[decision.key] = {"status": AutoDecisionStatus.MANUAL.value, "value": decision.value,
                                     "reason": "Engineer-confirmed value is preserved."}
            continue
        if decision.source_kind != "interface" or decision.target_field != "target_interface":
            results[decision.key] = {"status": AutoDecisionStatus.MANUAL.value, "value": None,
                                     "reason": "No deterministic evidence is available."}
            continue
        source = interfaces.get((decision.source_vdom, decision.source_name))
        if source is None or target is None:
            results[decision.key] = {"status": AutoDecisionStatus.MANUAL.value, "value": None,
                                     "reason": "Source interface or target architecture evidence is unavailable."}
            continue
        parent = mapped.get((decision.source_vdom, source.interface)) if source.interface else None
        target_vsys = target_vsys_value(decisions, decision.source_vdom)
        matches = []
        for item in target_items:
            if not _compatible(source, item):
                continue
            topo = topology.get((pan_scope_identity(item.scope), item.name))
            if target_vsys and (topo is None or target_vsys not in topo.imported_vsys):
                continue
            strong, supporting, conflicting = candidate_evidence(source, item, topo, parent)
            if conflicting:
                continue
            exact_ip = any(value.startswith("exact IP ") or value == "exact IP/prefix" for value in strong)
            vlan_parent = parent and source.vlanid is not None and str(source.vlanid) == str(getattr(item, "tag", None)) and (getattr(item, "parent", None) or getattr(topo, "parent", None)) == parent
            if exact_ip or vlan_parent:
                matches.append((item, topo, AutoDecisionStatus.VERIFIED if exact_ip else AutoDecisionStatus.DERIVED))
        if len(matches) == 1:
            item, topo, status = matches[0]
            results[decision.key] = {"status": status.value, "value": item.name,
                                     "reason": "Exact IP and compatible interface type." if status == AutoDecisionStatus.VERIFIED else "Confirmed parent and matching VLAN."}
        elif len(matches) > 1:
            results[decision.key] = {"status": AutoDecisionStatus.CANDIDATE.value,
                                     "candidates": sorted({item.name for item, _, _ in matches}),
                                     "reason": "Multiple target interfaces satisfy the evidence."}
        else:
            results[decision.key] = {"status": AutoDecisionStatus.MANUAL.value, "value": None,
                                     "reason": "No exact or confirmed-parent match is available."}

    vdom_interfaces = {}
    mapped_for_recomputation = dict(mapped)
    if target is not None:
        mapped_values = {(item.source_vdom, item.value) for item in decisions.decisions
                         if item.source_kind == "interface" and item.target_field == "target_interface"
                         and item.review_state == PANDecisionReviewState.CONFIRMED and item.value}
        mapped_values.update((decision.source_vdom, results[decision.key].get("value"))
                             for decision in decisions.decisions if decision.key in results
                             and results[decision.key]["status"] in {"VERIFIED", "DERIVED"})
        for vdom, name in mapped_values:
            topology_items = [topology.get((pan_scope_identity(item.scope), name)) for item in target_items
                              if item.name == name]
            if len(topology_items) == 1 and topology_items[0] is not None and not topology_items[0].issues:
                vdom_interfaces.setdefault(vdom, []).append(topology_items[0])
        for decision in decisions.decisions:
            result = results.get(decision.key, {})
            if decision.source_kind == "interface" and decision.target_field == "target_interface" \
                    and result.get("status") in {"VERIFIED", "DERIVED"} and result.get("value"):
                mapped_for_recomputation[(decision.source_vdom, decision.source_name)] = result["value"]

    for decision in decisions.decisions:
        if decision.review_state == PANDecisionReviewState.CONFIRMED:
            continue
        if decision.source_kind == "interface" and decision.target_field == "target_zone":
            source = interfaces.get((decision.source_vdom, decision.source_name))
            memberships = [zone.name for zone in getattr(config, "zones", ())
                           if (zone.vdom or "root") == decision.source_vdom and source and source.name in (zone.members or ())]
            if len(memberships) == 1:
                zone_decision = next((item for item in decisions.decisions if item.source_kind == "zone" and item.source_vdom == decision.source_vdom and item.source_name == memberships[0] and item.target_field == "target_zone" and item.review_state == PANDecisionReviewState.CONFIRMED), None)
                if zone_decision:
                    results[decision.key] = {"status": AutoDecisionStatus.DERIVED.value, "value": zone_decision.value,
                                             "reason": "Confirmed source-zone mapping and explicit membership."}
            if target is not None:
                target_name = mapped_for_recomputation.get((decision.source_vdom, decision.source_name))
                assigned = {zone for item in target_items if item.name == target_name
                            for topo in [topology.get((pan_scope_identity(item.scope), item.name))]
                            if topo is not None for zone in topo.zones}
                if len(assigned) == 1:
                    results[decision.key] = {"status": AutoDecisionStatus.DERIVED.value, "value": next(iter(assigned)),
                                             "reason": "Mapped PAN interface has one explicit zone assignment."}
        elif decision.source_kind == "vdom":
            relevant = vdom_interfaces.get(decision.source_vdom, [])
            attribute = "imported_vsys" if decision.target_field == "vsys" else "virtual_routers"
            values = [value for topo in relevant if topo is not None for value in getattr(topo, attribute, ())]
            if relevant and len(values) == len(relevant) and len(set(values)) == 1:
                results[decision.key] = {"status": AutoDecisionStatus.DERIVED.value, "value": values[0],
                                         "reason": f"Consistent mapped interface {decision.target_field} evidence."}
    return results
