"""Evidence-based suggestions from an uploaded PAN-OS target configuration."""

from dataclasses import replace
from ipaddress import ip_interface

from .decisions import PANDecisionMode, PANDecisionReviewState, PANMigrationDecisionSet, make_decision_key
from ...vendors.palo_alto.source_model import pan_scope_identity


def _device(item):
    scope = getattr(item, "scope", None)
    return (scope.device_serial or scope.device_name) if scope else None


def target_devices(target):
    return sorted({_device(item) for item in (*target.config.interfaces, *target.config.interface_units) if _device(item)})


def target_device_metadata(target):
    result = []
    for device in target_devices(target):
        interfaces = [item for item in target.config.interfaces if _device(item) == device]
        units = [item for item in target.config.interface_units if _device(item) == device]
        zones = [item for item in target.config.zones if _device(item) == device]
        vsys = {item.scope.vsys for item in (*interfaces, *units, *zones) if item.scope and item.scope.vsys}
        result.append({"id": device, "name": device, "interfaces": len(interfaces),
                       "interface_units": len(units), "zones": len(zones), "vsys": len(vsys)})
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
    if kind == "aggregate":
        return family == "aggregate-ethernet"
    if kind == "redundant":
        return False
    if kind == "tunnel":
        return family == "tunnel"
    if kind == "loopback":
        return family == "loopback"
    return family in {"ethernet", "aggregate-ethernet", "vlan", "loopback", "tunnel"} if not kind else family == "ethernet"


def suggest_from_target(source, decisions: PANMigrationDecisionSet, target, device: str):
    """Return reviewed-only suggestions and warnings; never confirm a mapping."""
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
        if decision.source_kind == "interface" and decision.target_field == "target_interface" and decision.review_state == PANDecisionReviewState.CONFIRMED and decision.value:
            mapped[(decision.source_vdom, decision.source_name)] = decision.value

    for (vdom, name), item in by_source.items():
        key = make_decision_key(vdom, "interface", name, "target_interface")
        if key not in existing or (vdom, name) in mapped:
            continue
        address = _addresses(item.ip)
        candidates = [(target_item, topo) for target_item, topo in scoped
                      if address and _compatible(item, target_item)
                      and address & _addresses(target_item.ipv4_addresses)
                      and (item.vlanid is None or str(item.vlanid) == str(getattr(target_item, "tag", None)))]
        if len(candidates) == 1:
            target_item, _ = candidates[0]
            put(vdom, "interface", name, "target_interface", target_item.name,
                f"Target XML: unique matching interface address ({', '.join(sorted(address & _addresses(target_item.ipv4_addresses)))})",
                "TARGET_INTERFACE_ADDRESS", ', '.join(sorted(address & _addresses(target_item.ipv4_addresses))), target_item.name)
            mapped[(vdom, name)] = target_item.name
        elif len(candidates) > 1:
            warnings[key] = "Several target interfaces share the source address; choose one manually."

    for (vdom, name), item in by_source.items():
        if (vdom, name) in mapped or item.vlanid is None or not item.interface:
            continue
        parent = mapped.get((vdom, item.interface))
        if not parent:
            continue
        candidates = [target_item for target_item, _ in scoped
                      if getattr(target_item, "parent", None) == parent
                      and str(getattr(target_item, "tag", None)) == str(item.vlanid)]
        if len(candidates) == 1:
            put(vdom, "interface", name, "target_interface", candidates[0].name,
                f"Target XML: VLAN {item.vlanid} under mapped parent {parent}",
                "TARGET_VLAN_PARENT", str(item.vlanid), candidates[0].name)
            mapped[(vdom, name)] = candidates[0].name

    assignments = {}
    for (vdom, name), target_name in mapped.items():
        candidates = [topo for item, topo in scoped if item.name == target_name and topo and not topo.issues]
        if len(candidates) != 1:
            if not candidates:
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
        elif len([item for item in target.config.zones if item.name == zone.name and _device(item) == device]) == 1:
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

    updated = []
    for decision in decisions.decisions:
        if decision.review_state == PANDecisionReviewState.CONFIRMED:
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
