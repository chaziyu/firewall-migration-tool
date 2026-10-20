"""Explicit interface-to-zone topology planning for Palo Alto."""

from typing import Any
from dataclasses import replace

from fwmigrate.conversion.fortigate_to_palo_alto.models import MigrationSourceRef, PANMigrationStatus, PlannedZone
from .interfaces import aggregate_member_owners


def plan_topology(source: Any, derived: Any, options: Any, required_zone_keys=None, *, include_configuration=False):
    topology = getattr(derived, "topology", None)
    entries = {(item.vdom, item.name): item for item in getattr(topology, "interfaces", ())}
    result = []
    required_zone_keys = set(required_zone_keys) if required_zone_keys is not None else None
    for zone in getattr(source, "zones", ()):
        vdom = zone.vdom or "root"
        if required_zone_keys is not None and (vdom, zone.name) not in required_zone_keys:
            continue
        mappings = getattr(options, "interfaces", {}).get(vdom, {})
        zone_mappings = getattr(options, "zones", None)
        zone_mapping = ((zone_mappings or {}).get(vdom, {}).get(zone.name) if zone_mappings is not None
                        else mappings.get(zone.name))
        target_interfaces = []
        warnings = []
        if len(set(zone.members or ())) > 1 and zone.intrazone != 'allow':
            warnings.append('FortiGate intra-zone deny or unknown behavior requires manual target security design')
        if zone_mapping is None or not zone_mapping.target_zone:
            warnings.append(f"missing target zone mapping for {zone.name!r}")
        for member in zone.members or ():
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
    if include_configuration:
        memberships = {(zone.vdom or "root", member) for zone in source.zones for member in zone.members or ()}
        proposed = {}
        aggregate_members = aggregate_member_owners(source)
        for interface in source.interfaces:
            vdom = interface.vdom or "root"
            if (vdom, interface.name) in aggregate_members:
                continue
            if (vdom, interface.name) in memberships:
                continue
            mapping = getattr(options, "interfaces", {}).get(vdom, {}).get(interface.name)
            zone = getattr(mapping, "target_zone", None)
            if not zone:
                continue
            vsys = getattr(getattr(options, "vdoms", {}).get(vdom), "vsys", None)
            group = proposed.setdefault((vdom, vsys, zone), [])
            group.append((interface.name, getattr(mapping, "target_interface", None)))
        for (vdom, vsys, zone), members in proposed.items():
            warnings = tuple(f"missing target interface mapping for {name!r}" for name, target in members if not target)
            result.append(PlannedZone(source_vdom=vdom, source_kind="interface", source_object_type="zone",
                source_name=members[0][0], target_vsys=vsys, target_name=zone,
                interfaces=tuple(target for _, target in members if target), warnings=warnings,
                status=PANMigrationStatus.MANUAL_REVIEW if warnings else PANMigrationStatus.SUPPORTED,
                source_contributors=tuple(MigrationSourceRef(vdom, 'interface', name) for name, _ in members)))
    consolidated = {}
    for item in result:
        contributors = item.source_contributors or (MigrationSourceRef(item.source_vdom, item.source_kind, item.source_name),)
        key = (item.source_vdom, item.target_vsys, item.target_name)
        # Unresolved target names cannot establish a common zone identity.
        if not item.target_name:
            key = (*key, item.source_kind, item.source_name)
        previous = consolidated.get(key)
        if previous is None:
            consolidated[key] = replace(item, source_contributors=contributors)
        else:
            consolidated[key] = replace(previous,
                interfaces=tuple(sorted(set(previous.interfaces) | set(item.interfaces))),
                warnings=tuple(dict.fromkeys((*previous.warnings, *item.warnings))),
                status=PANMigrationStatus.SUPPORTED if previous.status is item.status is PANMigrationStatus.SUPPORTED else PANMigrationStatus.MANUAL_REVIEW,
                source_contributors=tuple(dict.fromkeys((*previous.source_contributors, *contributors))))
    return tuple(replace(item, status=PANMigrationStatus.MANUAL_REVIEW,
        warnings=(*item.warnings, 'Merging distinct source zones or interfaces requires manual intra-zone security design'))
        if len(item.source_contributors) > 1 and len(set(item.interfaces)) > 1 else item
        for item in consolidated.values())
