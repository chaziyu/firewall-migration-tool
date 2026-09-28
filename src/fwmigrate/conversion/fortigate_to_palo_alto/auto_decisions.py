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


def _interface_matches(source, target_items, topology, parent, target_vsys):
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
        vlan_parent = (
            parent
            and source.vlanid is not None
            and str(source.vlanid) == str(getattr(item, "tag", None))
            and (getattr(item, "parent", None) or getattr(topo, "parent", None)) == parent
        )
        if exact_ip or vlan_parent:
            matches.append((
                item,
                topo,
                AutoDecisionStatus.VERIFIED if exact_ip else AutoDecisionStatus.DERIVED,
            ))
    return matches


def classify_auto_decisions(config, derived, decisions: PANMigrationDecisionSet, target=None, device=None):
    """Return per-key deterministic review results without mutating decisions."""
    del derived
    results = {}
    interfaces = {
        (item.vdom or "root", item.name): item
        for item in getattr(config, "interfaces", ())
        if item.name
    }
    mapped = {
        (item.source_vdom, item.source_name): item.value
        for item in decisions.decisions
        if item.source_kind == "interface"
        and item.target_field == "target_interface"
        and item.review_state == PANDecisionReviewState.CONFIRMED
        and item.value
    }

    target_items, topology = [], {}
    if target is not None:
        records = (*target.config.interfaces, *target.config.interface_units)
        devices = {_device(item) for item in records if _device(item)}
        target_items = [
            item
            for item in records
            if item.name
            and (
                device is not None and _device(item) == device
                or device is None and len(devices) == 1 and _device(item) in devices
            )
        ]
        topology = {
            (item.scope, item.interface): item
            for item in target.derived.interface_topology
        }

    # First classify explicit target-interface decisions.
    for decision in decisions.decisions:
        if decision.review_state == PANDecisionReviewState.CONFIRMED:
            results[decision.key] = {
                "status": AutoDecisionStatus.MANUAL.value,
                "value": decision.value,
                "reason": "Confirmed value is preserved.",
                "uses_target_evidence": False,
            }
            continue
        if decision.source_kind != "interface" or decision.target_field != "target_interface":
            results[decision.key] = {
                "status": AutoDecisionStatus.MANUAL.value,
                "value": None,
                "reason": "No deterministic interface decision is required here.",
                "uses_target_evidence": False,
            }
            continue

        source = interfaces.get((decision.source_vdom, decision.source_name))
        if source is None or target is None:
            results[decision.key] = {
                "status": AutoDecisionStatus.MANUAL.value,
                "value": None,
                "reason": "Source interface or target architecture evidence is unavailable.",
                "uses_target_evidence": False,
            }
            continue

        parent = mapped.get((decision.source_vdom, source.interface)) if source.interface else None
        matches = _interface_matches(
            source,
            target_items,
            topology,
            parent,
            target_vsys_value(decisions, decision.source_vdom),
        )
        if len(matches) == 1:
            item, _, status = matches[0]
            results[decision.key] = {
                "status": status.value,
                "value": item.name,
                "reason": (
                    "Exact IP and compatible interface type."
                    if status == AutoDecisionStatus.VERIFIED
                    else "Confirmed parent and matching VLAN."
                ),
                "uses_target_evidence": True,
            }
        elif len(matches) > 1:
            results[decision.key] = {
                "status": AutoDecisionStatus.CANDIDATE.value,
                "candidates": sorted({item.name for item, _, _ in matches}),
                "reason": "Multiple target interfaces satisfy the evidence.",
                "uses_target_evidence": True,
            }
        else:
            results[decision.key] = {
                "status": AutoDecisionStatus.MANUAL.value,
                "value": None,
                "reason": "No exact or confirmed-parent match is available.",
                "uses_target_evidence": bool(target is not None),
            }

    mapped_for_recomputation = dict(mapped)
    for decision in decisions.decisions:
        result = results.get(decision.key, {})
        if (
            decision.source_kind == "interface"
            and decision.target_field == "target_interface"
            and result.get("status") in {"VERIFIED", "DERIVED"}
            and result.get("value")
        ):
            mapped_for_recomputation[(decision.source_vdom, decision.source_name)] = result["value"]

    # Collect only unique, contradiction-free topology evidence that is relevant
    # to a required interface or zone decision. This allows VSYS/VR derivation
    # without making target_interface a false requirement for security rules.
    vdom_interfaces = {}
    vdom_evidence_sources = {}
    relevant_sources = {}
    for item in decisions.decisions:
        if item.source_kind == "interface" and item.target_field in {"target_interface", "target_zone"}:
            relevant_sources.setdefault(item.source_vdom, set()).add(item.source_name)
    seen_topology = set()

    def add_topology(vdom, source_name, topo):
        if topo is None or topo.issues:
            return
        vdom_evidence_sources.setdefault(vdom, set()).add(source_name)
        marker = (vdom, topo.scope, topo.interface)
        if marker in seen_topology:
            return
        seen_topology.add(marker)
        vdom_interfaces.setdefault(vdom, []).append(topo)

    if target is not None:
        for (vdom, source_name), target_name in mapped_for_recomputation.items():
            matches = [
                topology.get((pan_scope_identity(item.scope), item.name))
                for item in target_items
                if item.name == target_name
            ]
            if len(matches) == 1:
                add_topology(vdom, source_name, matches[0])

        for decision in decisions.decisions:
            if decision.source_kind != "interface" or decision.target_field != "target_zone":
                continue
            source = interfaces.get((decision.source_vdom, decision.source_name))
            if source is None:
                continue
            parent = mapped_for_recomputation.get(
                (decision.source_vdom, source.interface)
            ) if source.interface else None
            matches = _interface_matches(
                source,
                target_items,
                topology,
                parent,
                target_vsys_value(decisions, decision.source_vdom),
            )
            if len(matches) == 1:
                add_topology(decision.source_vdom, decision.source_name, matches[0][1])

    # Then derive zone and VDOM ownership decisions from established evidence.
    for decision in decisions.decisions:
        if decision.review_state == PANDecisionReviewState.CONFIRMED:
            continue

        if decision.source_kind == "interface" and decision.target_field == "target_zone":
            source = interfaces.get((decision.source_vdom, decision.source_name))
            proposals = []

            memberships = [
                zone.name
                for zone in getattr(config, "zones", ())
                if (zone.vdom or "root") == decision.source_vdom
                and source
                and source.name in (zone.members or ())
            ]
            if len(memberships) == 1:
                zone_decision = next((
                    item
                    for item in decisions.decisions
                    if item.source_kind == "zone"
                    and item.source_vdom == decision.source_vdom
                    and item.source_name == memberships[0]
                    and item.target_field == "target_zone"
                    and item.review_state == PANDecisionReviewState.CONFIRMED
                    and item.value
                ), None)
                if zone_decision:
                    proposals.append((
                        zone_decision.value,
                        "Confirmed source-zone mapping and explicit membership.",
                        False,
                    ))

            if target is not None and source is not None:
                target_name = mapped_for_recomputation.get(
                    (decision.source_vdom, decision.source_name)
                )
                if target_name:
                    assigned = {
                        zone
                        for item in target_items
                        if item.name == target_name
                        for topo in [topology.get((pan_scope_identity(item.scope), item.name))]
                        if topo is not None
                        for zone in topo.zones
                    }
                    if len(assigned) == 1:
                        proposals.append((
                            next(iter(assigned)),
                            "Mapped PAN interface has one explicit zone assignment.",
                            True,
                        ))
                else:
                    parent = mapped_for_recomputation.get(
                        (decision.source_vdom, source.interface)
                    ) if source.interface else None
                    matches = _interface_matches(
                        source,
                        target_items,
                        topology,
                        parent,
                        target_vsys_value(decisions, decision.source_vdom),
                    )
                    if len(matches) == 1:
                        _, topo, _ = matches[0]
                        if topo is not None and len(topo.zones) == 1:
                            proposals.append((
                                topo.zones[0],
                                "Unique deterministic PAN interface evidence has one explicit zone.",
                                True,
                            ))

            values = {value for value, _, _ in proposals if value}
            if len(values) == 1:
                value = next(iter(values))
                results[decision.key] = {
                    "status": AutoDecisionStatus.DERIVED.value,
                    "value": value,
                    "reason": "; ".join(
                        reason for proposal, reason, _ in proposals if proposal == value
                    ),
                    "uses_target_evidence": any(
                        uses_target
                        for proposal, _, uses_target in proposals
                        if proposal == value
                    ),
                }
            elif len(values) > 1:
                results[decision.key] = {
                    "status": AutoDecisionStatus.CANDIDATE.value,
                    "candidates": sorted(values),
                    "reason": "Deterministic source and target zone evidence conflicts.",
                    "uses_target_evidence": any(item[2] for item in proposals),
                }

        elif decision.source_kind == "vdom":
            required = relevant_sources.get(decision.source_vdom, set())
            evidenced = vdom_evidence_sources.get(decision.source_vdom, set())
            relevant = vdom_interfaces.get(decision.source_vdom, []) if required and evidenced == required else []
            attribute = (
                "imported_vsys"
                if decision.target_field == "vsys"
                else "virtual_routers"
            )
            values = [
                value
                for topo in relevant
                if topo is not None
                for value in getattr(topo, attribute, ())
            ]
            if relevant and len(values) == len(relevant) and len(set(values)) == 1:
                results[decision.key] = {
                    "status": AutoDecisionStatus.DERIVED.value,
                    "value": values[0],
                    "reason": f"Consistent deterministic interface {decision.target_field} evidence.",
                    "uses_target_evidence": True,
                }

    return results
