"""Explicit interface-to-zone topology planning for Palo Alto."""

from typing import Any

from .models import PANMigrationStatus, PlannedZone


def plan_topology(source: Any, derived: Any, options: Any, required_zone_keys=None):
    topology = getattr(derived, "topology", None)
    entries = {(item.vdom, item.name): item for item in getattr(topology, "interfaces", ())}
    result = []
    required_zone_keys = set(required_zone_keys) if required_zone_keys is not None else None
    for zone in getattr(source, "zones", ()):
        vdom = zone.vdom or "root"
        if required_zone_keys is not None and (vdom, zone.name) not in required_zone_keys:
            continue
        mappings = getattr(options, "interfaces", {}).get(vdom, {})
        zone_mapping = mappings.get(zone.name)
        target_interfaces = []
        warnings = []
        if zone_mapping is None or not zone_mapping.target_zone:
            warnings.append(f"missing target zone mapping for {zone.name!r}")
        for member in zone.members:
            mapping = mappings.get(member)
            if mapping is None or not mapping.target_interface:
                warnings.append(f"missing target interface mapping for {member!r}")
            else:
                target_interfaces.append(mapping.target_interface)
            entry = entries.get((zone.vdom, member))
            if entry and entry.issues:
                warnings.extend(entry.issues)
        status = PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW
        result.append(PlannedZone(
            source_vdom=vdom, source_kind="zone", source_object_type="zone",
            source_name=zone.name, status=status, warnings=tuple(dict.fromkeys(warnings)),
            target_vsys=getattr(getattr(options, "vdoms", {}).get(vdom), "vsys", None), target_name=getattr(zone_mapping, "target_zone", None),
            interfaces=tuple(target_interfaces),
        ))
    return tuple(result)
