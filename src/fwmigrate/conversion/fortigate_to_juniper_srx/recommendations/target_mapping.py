"""Deterministic new-device placement proposals; approval remains separate."""

from dataclasses import replace

from ..options import SRXInterfaceMapping, SRXMigrationOptions
from ..planning.naming import target_name
from ..requirements import source_vdoms, standalone_interfaces


def propose_new_target(source, derived, options):
    options = options if isinstance(options, SRXMigrationOptions) else SRXMigrationOptions(**options)
    scopes = source_vdoms(source)
    vdom = options.source_vdom or (scopes[0] if len(scopes) == 1 else None)
    if vdom not in scopes:
        raise ValueError("Choose one source VDOM before proposing SRX placement")
    mappings = {scope: dict(rows) for scope, rows in options.interfaces.items()}
    interfaces = mappings.setdefault(vdom, {})
    used = {row.target_interface for row in interfaces.values()}
    topology = {row.name: row for row in derived.topology.interfaces if row.vdom == vdom}
    port = 0
    for interface in source.interfaces:
        row = topology.get(interface.name)
        if interface.vdom != vdom or interface.name in interfaces or row is None or row.issues or row.kind != "physical":
            continue
        while f"ge-0/0/{port}" in used:
            port += 1
        target = f"ge-0/0/{port}"
        interfaces[interface.name] = SRXInterfaceMapping(target, 0)
        used.add(target)
    for interface in source.interfaces:
        row = topology.get(interface.name)
        parent = interfaces.get(interface.interface)
        if (interface.vdom == vdom and interface.name not in interfaces and row is not None
                and row.kind == "vlan" and not row.issues and parent and interface.vlanid is not None
                and 1 <= interface.vlanid <= 4094):
            interfaces[interface.name] = SRXInterfaceMapping(parent.target_interface, interface.vlanid)
    zones = {scope: dict(rows) for scope, rows in options.zones.items()}
    for zone in source.zones:
        if zone.vdom == vdom:
            zones.setdefault(vdom, {}).setdefault(zone.name, target_name("zone", vdom, zone.name))
    interface_zones = {scope: dict(rows) for scope, rows in options.interface_zones.items()}
    for interface in standalone_interfaces(source, vdom):
        interface_zones.setdefault(vdom, {}).setdefault(interface.name, target_name("zone", vdom, f"interface:{interface.name}"))
    return replace(options, source_vdom=vdom, target_context=options.target_context or "root",
        target_version=options.target_version or "25.2R1", target_mode=options.target_mode or "standalone",
        routing_table=options.routing_table or "inet.0", interfaces=mappings, zones=zones, interface_zones=interface_zones)
