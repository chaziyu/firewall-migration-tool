"""Evidence-based suggestions from an uploaded PAN-OS target configuration."""

from dataclasses import replace
from ipaddress import ip_interface

from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANDecisionMode, PANDecisionReviewState, PANMigrationDecisionSet, make_decision_key
from fwmigrate.conversion.fortigate_to_palo_alto.interface_candidates import (
    PANInterfaceCandidate,
    PANInterfaceCandidateClass,
    candidate_evidence,
    viable_candidate,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_candidates import target_vsys_value
from fwmigrate.vendors.palo_alto.source_model import pan_scope_identity


def _device(item):
    scope = getattr(item, "scope", None) or (item if hasattr(item, "kind") else None)
    return (scope.device_serial or scope.device_name) if scope else None


def _candidate(value, scope, strong=(), supporting=()):
    return {"value": value, "target_scope": str(pan_scope_identity(scope)) if scope else None,
            "class": "STRONG" if strong else "POSSIBLE", "strong_evidence": list(strong),
            "supporting_evidence": list(supporting), "contradictions": []}


def target_devices(target):
    config = target.config
    items = (*getattr(config, "interfaces", ()), *getattr(config, "interface_units", ()),
             *getattr(config, "zones", ()), *getattr(config, "virtual_routers", ()),
             *getattr(config, "scopes", ()))
    return sorted({_device(item) for item in items if _device(item)})


def target_device_metadata(target):
    result = []
    for device in target_devices(target):
        interfaces = [item for item in target.config.interfaces if _device(item) == device]
        units = [item for item in target.config.interface_units if _device(item) == device]
        zones = [item for item in target.config.zones if _device(item) == device]
        routers = [item for item in getattr(target.config, "virtual_routers", ()) if _device(item) == device]
        scopes = [item for item in getattr(target.config, "scopes", ()) if _device(item) == device]
        vsys = {scope.vsys for scope in (*[item.scope for item in (*interfaces, *units, *zones, *routers)], *scopes)
                if scope and scope.vsys}
        result.append({"id": device, "name": device, "interfaces": len(interfaces),
                       "interface_units": len(units), "zones": len(zones),
                       "virtual_routers": len(routers), "vsys": len(vsys)})
    return result


def _addresses(value):
    if not value:
        return set()
    values = value if isinstance(value, list) else [value]
    result = set()
    for item in values:
        try:
            parts = item.split()
            address = ip_interface(f"{parts[0]}/{parts[1]}" if len(parts) == 2 else item)
            if not address.ip.is_unspecified:
                result.add(str(address))
        except (ValueError, IndexError, AttributeError):
            continue
    return result


def _compatible(source, target):
    family = getattr(target, "interface_family", None)
    kind = (source.type or "").lower()
    if source.vlanid is not None or kind == "vlan":
        return getattr(target, "tag", None) is not None
    if kind and (getattr(target, "tag", None) is not None or getattr(target, "parent", None)):
        return False
    if kind == "aggregate":
        return family == "aggregate-ethernet"
    if kind == "redundant":
        return False
    if kind == "tunnel":
        return family == "tunnel"
    if kind == "loopback":
        return family == "loopback"
    return family in {"ethernet", "aggregate-ethernet", "vlan", "loopback", "tunnel"} if not kind else family == "ethernet"


def discover_target_candidates(source, decisions: PANMigrationDecisionSet, target, device: str, *, evidence=None,
                              proposed_design=None, review_vsys=None, draft_values=None):
    """Return current target evidence, separate from the persisted decision document."""
    from .target_validation import interface_assignment_index

    reservations = interface_assignment_index(decisions)
    records = [item for item in (*target.config.interfaces, *target.config.interface_units)
               if item.name and _device(item) == device]
    topology = {(item.scope, item.interface): item for item in target.derived.interface_topology}
    scoped = [(item, topology.get((pan_scope_identity(item.scope), item.name))) for item in records]
    by_source = {(item.vdom or "root", item.name): item for item in source.interfaces if item.name}
    mapped = {}
    confirmed_zones = {}
    def draft_vsys(vdom):
        key = make_decision_key(vdom, "vdom", vdom, "vsys")
        return (draft_values or {}).get(key) or target_vsys_value(decisions, vdom, proposed_design=proposed_design)
    for decision in decisions.decisions:
        if decision.source_kind != "interface" or decision.target_field not in {"target_interface", "target_zone"}:
            continue
        value = ((draft_values or {}).get(decision.key) or
                 (proposed_design.provisional_value(decision.key) if proposed_design is not None
                 else decision.value if decision.mode is PANDecisionMode.AUTO
                 or decision.review_state is PANDecisionReviewState.CONFIRMED else None))
        if value and decision.target_field == "target_interface":
            mapped[(decision.source_vdom, decision.source_name)] = value
        elif value and decision.target_field == "target_zone":
            confirmed_zones[(decision.source_vdom, decision.source_name)] = value
    result = {}
    for (vdom, name), item in by_source.items():
        key = make_decision_key(vdom, "interface", name, "target_interface")
        parent = mapped.get((vdom, item.interface)) if item.interface else None
        target_vsys = draft_vsys(vdom)
        found = []
        for target_item, topo in scoped:
            if not _compatible(item, target_item):
                continue
            if target_vsys and (topo is None or target_vsys not in topo.imported_vsys):
                continue
            source_evidence = (evidence or {}).get((vdom, name))
            if source_evidence:
                target_zones = set(getattr(topo, "zones", ()) or ())
                target_evidence = {**source_evidence, "target_policy_usage": {
                    "source_reference_count": sum(bool(target_zones.intersection(policy.from_zones or ()))
                        and _device(policy) == device for policy in getattr(target.config, "policies", ())),
                    "destination_reference_count": sum(bool(target_zones.intersection(policy.to_zones or ()))
                        and _device(policy) == device for policy in getattr(target.config, "policies", ())),
                }}
                if (vdom, name) in confirmed_zones:
                    target_evidence["confirmed_target_zone"] = confirmed_zones[(vdom, name)]
                source_evidence = target_evidence
            strong, supporting, contradicting = candidate_evidence(item, target_item, topo, parent, source_evidence)
            candidate_class = (PANInterfaceCandidateClass.EXCLUDED if contradicting else
                               PANInterfaceCandidateClass.STRONG if strong else
                               PANInterfaceCandidateClass.POSSIBLE)
            owners = tuple((owner.source_vdom, owner.source_name) for owner in reservations.get(target_item.name, ()))
            available = not any(owner != (vdom, name) for owner in owners)
            found.append(PANInterfaceCandidate(
                target_item.name, str(pan_scope_identity(target_item.scope)) if target_item.scope else None,
                candidate_class, strong, supporting, contradicting, owners, available))
        found.sort(key=lambda candidate: (candidate.candidate_class != PANInterfaceCandidateClass.STRONG,
                                          -len(candidate.supporting_evidence),
                                          candidate.value, candidate.target_scope or ""))
        result[key] = [candidate.to_dict() for candidate in found if candidate.candidate_class != PANInterfaceCandidateClass.EXCLUDED]

    claims = {}
    for key, options in result.items():
        strong = [item for item in options if item["class"] == "STRONG" and item["available"]]
        if len(strong) == 1:
            claims.setdefault(strong[0]["value"], []).append(key)
    for options in result.values():
        for item in options:
            item["contested"] = len(claims.get(item["value"], ())) > 1

    # Other decision fields use the same closed, scope-aware candidate contract.
    scope_records = (*getattr(target.config, "scopes", ()),
                     *(getattr(item, "scope", None) for item in (*records, *getattr(target.config, "zones", ()),
                         *getattr(target.config, "virtual_routers", ()))))
    scopes = [scope for scope in scope_records if scope and _device(scope) == device]
    scope_by_id = {pan_scope_identity(scope): scope for scope in scopes}
    scopes = tuple(scope_by_id.values())
    target_vrouters = [item for item in getattr(target.config, "virtual_routers", ()) if item.name and _device(item) == device]
    target_zones = [item for item in getattr(target.config, "zones", ()) if item.name and
                    (_device(item) == device or getattr(getattr(item, "scope", None), "kind", None) == "shared")]
    for decision in decisions.decisions:
        if decision.key in result:
            continue
        candidates = []
        vsys = draft_vsys(decision.source_vdom)
        if not vsys and proposed_design is None:
            vsys = (review_vsys or {}).get(decision.source_vdom)
        if decision.source_kind == "vdom" and decision.target_field == "vsys":
            candidates.extend(_candidate(scope.vsys, scope, supporting=("explicit target VSYS",))
                              for scope in scopes if scope.vsys)
        elif decision.source_kind == "vdom" and decision.target_field == "virtual_router":
            related = {router for (vdom, _), source_item in by_source.items() if vdom == decision.source_vdom
                       for target_item, topo in scoped
                       if (vdom, source_item.name) in mapped and mapped[(vdom, source_item.name)] == target_item.name
                       and topo and (not vsys or vsys in topo.imported_vsys) for router in topo.virtual_routers}
            candidates.extend(_candidate(item.name, item.scope,
                strong=("confirmed interface uses this virtual router",) if item.name in related else (),
                supporting=("explicit target virtual router",)) for item in target_vrouters
                if item.scope and (not vsys or not item.scope.vsys or item.scope.vsys == vsys))
        elif decision.target_field == "target_zone":
            source_zone = next((item for item in source.zones
                if (item.vdom or "root", item.name) == (decision.source_vdom, decision.source_name)), None)
            source_interface = by_source.get((decision.source_vdom, decision.source_name))
            mapped_name = mapped.get((decision.source_vdom, decision.source_name))
            assigned = []
            if mapped_name:
                assigned = [topo for target_item, topo in scoped if target_item.name == mapped_name and topo
                            and (not vsys or vsys in topo.imported_vsys)]
            assigned_zones = {zone for topo in assigned for zone in topo.zones}
            for zone in target_zones:
                if zone.scope and vsys and zone.scope.vsys and zone.scope.vsys != vsys:
                    continue
                strong = ("selected interface has one explicit zone",) if len(assigned_zones) == 1 and zone.name in assigned_zones else ()
                supporting = ["explicit target zone"]
                if source_zone and source_zone.name.casefold() == zone.name.casefold():
                    supporting.append("source and target zone names match")
                candidates.append(_candidate(zone.name, zone.scope, strong, supporting))
        if candidates:
            # Keep duplicate names in separate PAN scopes; AI eligibility rejects them as ambiguous.
            result[decision.key] = candidates
    return result


def suggest_from_target(source, decisions: PANMigrationDecisionSet, target, device: str):
    """Return reviewed-only suggestions and warnings; never confirm a mapping."""
    from .target_validation import interface_assignment_index

    reservations = interface_assignment_index(decisions)
    records = [item for item in (*target.config.interfaces, *target.config.interface_units)
               if item.name and _device(item) == device]
    topology = {(item.scope, item.interface): item for item in target.derived.interface_topology}
    scoped = [(item, topology.get((pan_scope_identity(item.scope), item.name))) for item in records]
    by_source = {(item.vdom or "root", item.name): item for item in source.interfaces if item.name}
    existing = {item.key: item for item in decisions.decisions}
    proposed = {}
    warnings = {}

    def put(vdom, kind, name, field, value, reason, evidence_type, evidence_value=None, target_object=None):
        key = make_decision_key(vdom, kind, name, field)
        if key in existing and value:
            proposed[key] = (value, reason, evidence_type, evidence_value, target_object)

    mapped = {}
    for decision in decisions.decisions:
        if decision.source_kind == "interface" and decision.target_field == "target_interface" and (decision.review_state == PANDecisionReviewState.CONFIRMED or decision.mode == PANDecisionMode.AUTO) and decision.value:
            mapped[(decision.source_vdom, decision.source_name)] = decision.value
    confirmed_mapped = dict(mapped)

    for (vdom, name), item in by_source.items():
        key = make_decision_key(vdom, "interface", name, "target_interface")
        if key not in existing or (vdom, name) in mapped:
            continue
        address = _addresses(item.ip)
        candidates = []
        parent = confirmed_mapped.get((vdom, item.interface)) if item.interface else None
        target_vsys = target_vsys_value(decisions, vdom)
        for target_item, topo in scoped:
            if any((owner.source_vdom, owner.source_name) != (vdom, name) for owner in reservations.get(target_item.name, ())):
                continue
            if not _compatible(item, target_item):
                continue
            if target_vsys and (topo is None or target_vsys not in topo.imported_vsys):
                continue
            valid, strong, supporting, _ = viable_candidate(item, target_item, topo, parent)
            if valid:
                candidates.append((target_item, topo, strong, supporting))
        if len(candidates) == 1:
            target_item, _, strong, supporting = candidates[0]
            exact = address & _addresses(target_item.ipv4_addresses)
            put(vdom, "interface", name, "target_interface", target_item.name,
                f"Target XML: unique interface candidate ({'; '.join((*strong, *supporting))})",
                "TARGET_INTERFACE_ADDRESS" if exact else "TARGET_INTERFACE_EVIDENCE",
                ', '.join(sorted(exact)) if exact else '; '.join((*strong, *supporting)), target_item.name)
            mapped[(vdom, name)] = target_item.name
        elif len(candidates) > 1:
            warnings[key] = "Several target interfaces match strong source evidence; choose one manually."

    for (vdom, name), item in by_source.items():
        if (vdom, name) in mapped or item.vlanid is None or not item.interface:
            continue
        parent = confirmed_mapped.get((vdom, item.interface))
        if not parent:
            continue
        candidates = []
        target_vsys = target_vsys_value(decisions, vdom)
        for target_item, topo in scoped:
            if any((owner.source_vdom, owner.source_name) != (vdom, name) for owner in reservations.get(target_item.name, ())):
                continue
            if not _compatible(item, target_item):
                continue
            if target_vsys and (topo is None or target_vsys not in topo.imported_vsys):
                continue
            valid, strong, supporting, _ = viable_candidate(item, target_item, topo, parent)
            if valid and str(getattr(target_item, "tag", None)) == str(item.vlanid):
                candidates.append((target_item, strong, supporting))
        if len(candidates) == 1:
            target_item, strong, supporting = candidates[0]
            put(vdom, "interface", name, "target_interface", target_item.name,
                f"Target XML: unique VLAN candidate ({'; '.join((*strong, *supporting))})",
                "TARGET_VLAN_PARENT", '; '.join((*strong, *supporting)), target_item.name)
            mapped[(vdom, name)] = target_item.name

    claims = {}
    for identity, value in mapped.items():
        claims.setdefault(value, []).append(identity)
    for value, owners in claims.items():
        if len(owners) < 2:
            continue
        for vdom, name in owners:
            key = make_decision_key(vdom, "interface", name, "target_interface")
            warnings[key] = f"Target interface {value} is contested by " + ", ".join(f"{v} / {n}" for v, n in owners) + ". Choose manually."
            if (vdom, name) not in confirmed_mapped:
                mapped.pop((vdom, name))
                proposed.pop(key, None)

    assignments = {}
    for (vdom, name), target_name in mapped.items():
        target_vsys = target_vsys_value(decisions, vdom)
        candidates = [topo for item, topo in scoped if item.name == target_name and topo and not topo.issues
                      and (not target_vsys or target_vsys in topo.imported_vsys)]
        if len(candidates) != 1:
            if not candidates:
                if target_vsys:
                    warnings[make_decision_key(vdom, "interface", name, "target_interface")] = (
                        f"Target interface {target_name} is not verified as imported into VSYS {target_vsys}."
                    )
                else:
                    warnings[make_decision_key(vdom, "interface", name, "target_interface")] = (
                        f"Target interface {target_name} is absent from the uploaded target XML; confirm whether it will be created."
                    )
            continue
        topo = candidates[0]
        assignments.setdefault(vdom, []).append(topo)
        if len(topo.zones) == 1:
            key = make_decision_key(vdom, "interface", name, "target_zone")
            old = existing.get(key)
            zone = topo.zones[0]
            if old and old.review_state == PANDecisionReviewState.CONFIRMED and old.value != zone:
                warnings[key] = f"Confirmed zone {old.value} differs from target assignment {zone}."
            elif old and old.suggested_value and old.suggested_value != zone:
                warnings[key] = f"Source zone suggestion {old.suggested_value} differs from target assignment {zone}."
            else:
                put(vdom, "interface", name, "target_zone", zone,
                    f"Target XML: {target_name} is explicitly assigned to zone {zone}",
                    "TARGET_ZONE_ASSIGNMENT", zone, target_name)

    for zone in source.zones:
        vdom = zone.vdom or "root"
        key = make_decision_key(vdom, "zone", zone.name, "target_zone")
        if key not in existing:
            continue
        members = [topo for name in zone.members or ()
                   for topo in assignments.get(vdom, ()) if mapped.get((vdom, name)) == topo.interface]
        target_zones = {name for topo in members for name in topo.zones}
        if members and len(members) == len(zone.members or ()) and len(target_zones) == 1:
            value = next(iter(target_zones))
            put(vdom, "zone", zone.name, "target_zone", value,
                f"Target XML: all mapped members belong to zone {value}",
                "TARGET_ZONE_ASSIGNMENT", value, zone.name)
        elif len([item for item in target.config.zones if item.name == zone.name and _device(item) == device
                  and (not target_vsys_value(decisions, vdom) or item.scope.vsys == target_vsys_value(decisions, vdom))]) == 1:
            put(vdom, "zone", zone.name, "target_zone", zone.name,
                f"Target XML: same-name zone {zone.name} exists",
                "TARGET_ZONE_ASSIGNMENT", zone.name, zone.name)

    for vdom, entries in assignments.items():
        for field, attribute in (("vsys", "imported_vsys"), ("virtual_router", "virtual_routers")):
            values = [value for topo in entries for value in getattr(topo, attribute)]
            if len(values) == len(entries) and len(set(values)) == 1:
                old = existing.get(make_decision_key(vdom, "vdom", vdom, field))
                if old and old.review_state == PANDecisionReviewState.CONFIRMED and old.value != values[0]:
                    warnings[old.key] = f"Confirmed {field} {old.value} differs from target assignment {values[0]}."
                put(vdom, "vdom", vdom, field, values[0],
                    f"Target XML: all matched interfaces use {field} {values[0]}",
                    "TARGET_VSYS_ASSIGNMENT" if field == "vsys" else "TARGET_VIRTUAL_ROUTER_ASSIGNMENT",
                    values[0], values[0])

    # A single explicit architecture choice is review prefill, never planner input.
    architecture = discover_target_candidates(source, decisions, target, device)
    review_vsys = {}
    for decision in decisions.decisions:
        if decision.source_kind != "vdom" or decision.target_field != "vsys":
            continue
        options = architecture.get(decision.key, ())
        if decision.key not in proposed and len(options) == 1:
            put(decision.source_vdom, "vdom", decision.source_name, "vsys", options[0]["value"],
                "Target XML: one eligible explicit VSYS; review before confirming.",
                "TARGET_VSYS_CANDIDATE", options[0]["value"], options[0]["value"])
        selected = target_vsys_value(decisions, decision.source_vdom)
        if selected or decision.key in proposed:
            review_vsys[decision.source_vdom] = selected or proposed[decision.key][0]
    architecture = discover_target_candidates(source, decisions, target, device, review_vsys=review_vsys)
    for decision in decisions.decisions:
        if (decision.source_kind == "vdom" and decision.target_field == "virtual_router"
                and decision.source_vdom in review_vsys and decision.key not in proposed):
            options = architecture.get(decision.key, ())
            if len(options) == 1:
                put(decision.source_vdom, "vdom", decision.source_name, "virtual_router", options[0]["value"],
                    "Target XML: one eligible virtual router in the review VSYS; review before confirming.",
                    "TARGET_VIRTUAL_ROUTER_CANDIDATE", options[0]["value"], options[0]["value"])

    updated = []
    for decision in decisions.decisions:
        if decision.review_state == PANDecisionReviewState.CONFIRMED or decision.mode in {PANDecisionMode.AUTO, PANDecisionMode.UNSUPPORTED}:
            updated.append(decision)
        elif decision.key in proposed:
            value, reason, evidence_type, evidence_value, target_object = proposed[decision.key]
            updated.append(replace(decision, mode=PANDecisionMode.SUGGESTED,
                                   suggested_value=value, reason=reason, evidence_source="TARGET",
                                   evidence_type=evidence_type, evidence_value=evidence_value,
                                   target_object=target_object))
        else:
            updated.append(decision)
    return PANMigrationDecisionSet(tuple(updated)), warnings
