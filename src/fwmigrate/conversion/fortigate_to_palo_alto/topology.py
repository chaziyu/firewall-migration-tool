"""Explicit interface-to-zone topology planning for Palo Alto."""

from typing import Any

from .models import PANMigrationStatus, PlannedZone


def plan_topology(source: Any, derived: Any, options: Any):
    topology = getattr(derived, "topology", None)
    entries = {(item.vdom, item.name): item for item in getattr(topology, "interfaces", ())}
    result = []
    for zone in getattr(source, "zones", ()):
        target_interfaces = []
        warnings = []
        for member in zone.members:
            mapping = getattr(options, "interfaces", {}).get(member)
            if mapping is None or not mapping.target_interface:
                warnings.append(f"missing target interface mapping for {member!r}")
            else:
                target_interfaces.append(mapping.target_interface)
            entry = entries.get((zone.vdom, member))
            if entry and entry.issues:
                warnings.extend(entry.issues)
        status = PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW
        result.append(PlannedZone(
            source_vdom=zone.vdom, source_kind="zone", source_object_type="zone",
            source_name=zone.name, status=status, warnings=tuple(dict.fromkeys(warnings)),
            target_vsys=getattr(getattr(options, "vdoms", {}).get(zone.vdom), "vsys", None), target_name=zone.name,
            interfaces=tuple(target_interfaces),
        ))
    return tuple(result)
