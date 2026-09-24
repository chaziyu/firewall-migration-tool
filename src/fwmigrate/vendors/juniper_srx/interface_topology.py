"""Read-only derived Junos interface topology."""

from __future__ import annotations


def build_juniper_interface_topology(context, scope: str) -> tuple[dict, ...]:
    interfaces = context.interfaces
    members: dict[str, list[str]] = {}
    redundant_members: dict[str, list[str]] = {}
    for interface in interfaces.values():
        if interface.aggregate_parent:
            members.setdefault(interface.aggregate_parent, []).append(interface.name)
        if interface.redundant_parent:
            redundant_members.setdefault(interface.redundant_parent, []).append(interface.name)

    def kind(name: str) -> str | None:
        if name.startswith("irb"):
            return "irb"
        if name.startswith("ae"):
            return "aggregate-ethernet"
        if name.startswith("reth"):
            return "redundant-ethernet"
        if name.startswith("lo0"):
            return "loopback"
        return None

    rows = []
    zone_memberships: dict[str, list[str]] = {}
    for zone in context.zones.values():
        for name in zone.interfaces:
            zone_memberships.setdefault(name, []).append(zone.name)
    routing_memberships: dict[str, list[str]] = {}
    for instance in context.routing_instances.values():
        for name in instance.interfaces:
            routing_memberships.setdefault(name, []).append(instance.name)

    names = dict.fromkeys((*interfaces, *members, *redundant_members))
    for name in names:
        interface = interfaces.get(name)
        row = {
            "context": scope,
            "interface": name,
            "unit": None,
            "parent": None,
            "name": name,
            "interface_type": kind(name),
            "aggregate_parent": interface.aggregate_parent if interface else None,
            "redundant_parent": interface.redundant_parent if interface else None,
            "aggregate_members": tuple(members.get(name, ())),
            "redundant_members": tuple(redundant_members.get(name, ())),
            "zone_memberships": tuple(zone_memberships.get(name, ())),
            "routing_instance_memberships": tuple(routing_memberships.get(name, ())),
            "aggregate_parent_resolved": not interface.aggregate_parent or interface.aggregate_parent in interfaces if interface else False,
            "redundant_parent_resolved": not interface.redundant_parent or interface.redundant_parent in interfaces if interface else False,
            "source_present": interface is not None,
        }
        rows.append(row)
        if interface:
            rows.extend({
                **row,
                "unit": unit.unit,
                "parent": name,
                "name": f"{name}.{unit.unit}",
                "zone_memberships": tuple(zone_memberships.get(f"{name}.{unit.unit}", zone_memberships.get(name, ()))),
                "routing_instance_memberships": tuple(routing_memberships.get(f"{name}.{unit.unit}", routing_memberships.get(name, ()))),
            } for unit in interface.units.values())
    return tuple(rows)


__all__ = ["build_juniper_interface_topology"]
