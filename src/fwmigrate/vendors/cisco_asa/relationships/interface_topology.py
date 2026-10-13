"""Read-only ASA interface topology relationships."""

from dataclasses import dataclass, replace
from typing import Any

from .references import ASAReferenceIndex, ASAReferenceKind, ASAReferenceStatus


@dataclass(frozen=True, slots=True)
class ASAInterfaceTopologyEntry:
    source_context: str | None
    name: str
    nameif: str | None
    kind: str | None
    parent: Any = None
    aggregate: Any = None
    bridge: Any = None
    physical_interfaces: tuple[Any, ...] = ()
    path: tuple[Any, ...] = ()
    zones: tuple[Any, ...] = ()
    issues: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ASAInterfaceTopology:
    interfaces: tuple[ASAInterfaceTopologyEntry, ...] = ()
    issues: tuple[Any, ...] = ()


def build_asa_interface_topology(config: Any, references: ASAReferenceIndex) -> ASAInterfaceTopology:
    from .references import ASAReferenceIssue, source_context_of

    entries = []
    issues = []
    redundant_seen: dict[tuple[str | None, str], Any] = {}
    for item in config.interfaces:
        context = source_context_of(item)
        local = []
        def resolve(name: str | None, kind: ASAReferenceKind, reason: str, field: str):
            if not name:
                return None
            result = references.resolve(context, kind, name)
            if result.status is not ASAReferenceStatus.RESOLVED:
                local.append(reason)
                issues.append(ASAReferenceIssue(context, kind, item.name, name, result.status, reason, field))
            return result.target

        parent = resolve(item.parent_interface, ASAReferenceKind.INTERFACE, "Unresolved subinterface parent reference", "parent-interface")
        aggregate = None
        if item.channel_group is not None:
            aggregate = resolve(f"Port-channel{item.channel_group}", ASAReferenceKind.INTERFACE, "Unresolved Port-channel reference", "channel-group")
        if item.redundant_interface_members:
            for member in item.redundant_interface_members:
                resolve(member, ASAReferenceKind.INTERFACE, "Unresolved redundant-interface member reference", "member-interface")
                key = (context, member.casefold())
                if key in redundant_seen:
                    issues.append(ASAReferenceIssue(context, ASAReferenceKind.INTERFACE, item.name, member, ASAReferenceStatus.AMBIGUOUS, "Duplicate redundant-interface membership", "member-interface"))
                redundant_seen[key] = item
        bridge = None
        if item.interface_type == "bridge-member" and item.bridge_group is not None:
            bridge = resolve(f"BVI{item.bridge_group}", ASAReferenceKind.INTERFACE, "Unresolved bridge-group BVI reference", "bridge-group")
        zones = []
        for zone_name in getattr(item, "traffic_zone_members", ()):
            found = resolve(zone_name, ASAReferenceKind.TRAFFIC_ZONE, "Unresolved traffic-zone reference", "zone-member")
            if found is not None:
                zones.append(found)
        entries.append(ASAInterfaceTopologyEntry(context, item.name, item.nameif, item.interface_type, parent, aggregate, bridge, (), (item,), tuple(zones), tuple(local)))

    for zone in config.traffic_zones:
        for member in getattr(zone, "members", ()):
            result = references.resolve(source_context_of(zone), ASAReferenceKind.INTERFACE, member)
            if result.status is not ASAReferenceStatus.RESOLVED:
                issues.append(ASAReferenceIssue(source_context_of(zone), ASAReferenceKind.INTERFACE, zone.name, member, result.status, "Unresolved traffic-zone interface member", "zone-member"))

    by_name = {(entry.source_context, entry.name.casefold()): entry for entry in entries}
    def ancestry(entry, trail=()):
        key = (entry.source_context, entry.name.casefold())
        if key in trail:
            cycle = trail[trail.index(key):] + (key,)
            issues.append(ASAReferenceIssue(entry.source_context, ASAReferenceKind.INTERFACE, entry.name,
                                            entry.name, ASAReferenceStatus.AMBIGUOUS,
                                            "Interface topology cycle", "topology-cycle"))
            return (entry.name,), ()
        parent = entry.parent or entry.aggregate
        if parent is None:
            return (entry.name,), (entry,)
        target = by_name.get((entry.source_context, parent.name.casefold()))
        if target is None:
            return (entry.name, parent.name), (entry,)
        path, physical = ancestry(target, trail + (key,))
        return (entry.name, *path), physical or (target,)

    resolved_entries = []
    for entry in entries:
        path, physical = ancestry(entry)
        resolved_entries.append(replace(entry, path=path, physical_interfaces=physical))
    return ASAInterfaceTopology(tuple(resolved_entries), tuple(issues))
