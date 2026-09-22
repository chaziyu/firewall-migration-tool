from __future__ import annotations

from dataclasses import dataclass

from ..model.source import PANOSConfig
from ..source_model import pan_scope_identity


@dataclass(frozen=True, slots=True)
class PANInterfaceTopologyEntry:
    interface: str
    scope: str
    units: tuple[str, ...] = ()
    imported_vsys: tuple[str, ...] = ()
    zones: tuple[str, ...] = ()
    virtual_routers: tuple[str, ...] = ()
    issues: tuple[str, ...] = ()
    kind: str = "logical"
    parent: str | None = None
    path: tuple[str, ...] = ()
    aggregate: str | None = None
    physical_interfaces: tuple[str, ...] = ()
    attached_tunnels: tuple[str, ...] = ()


def _kind(family: str | None) -> str:
    return {"aggregate-ethernet": "aggregate", "ethernet": "physical", "vlan": "vlan", "tunnel": "tunnel"}.get(family or "", "logical")


def build_interface_topology(config: PANOSConfig) -> tuple[PANInterfaceTopologyEntry, ...]:
    interfaces = [item for item in config.interfaces if item.name]
    units = [item for item in config.interface_units if item.name]
    objects = {(pan_scope_identity(item.scope), item.name): item for item in [*interfaces, *units]}
    aggregate_members: dict[tuple[str, str], list[str]] = {}
    for item in interfaces:
        if item.aggregate_group:
            members = aggregate_members.setdefault((pan_scope_identity(item.scope), item.aggregate_group), [])
            if item.name and item.name not in members:
                members.append(item.name)

    def scope_for(item):
        return pan_scope_identity(item.scope)

    def parent_for(key: tuple[str, str]) -> str | None:
        item = objects[key]
        parent = getattr(item, "parent", None)
        if parent:
            return parent
        owners = aggregate_owners(key)
        return owners[0] if len(owners) == 1 else None

    def aggregate_owners(key: tuple[str, str]) -> list[str]:
        return [name for (scope, name), members in aggregate_members.items() if scope == key[0] and key[1] in members]

    def chain(key: tuple[str, str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
        path = [key[1]]
        issues: list[str] = []
        seen = {key[1]}
        current = key
        while True:
            parent = parent_for(current)
            if not parent:
                break
            if parent in seen:
                issues.append(f"interface topology cycle detected at {parent!r}")
                break
            seen.add(parent)
            path.append(parent)
            parent_key = (current[0], parent)
            if parent_key not in objects:
                issues.append(f"parent interface {parent!r} was not found")
                break
            current = parent_key
        return tuple(path), tuple(issues)

    def physical(key: tuple[str, str], seen: set[str] | None = None) -> tuple[str, ...]:
        if seen is None:
            seen = set()
        if key[1] in seen:
            return ()
        seen.add(key[1])
        members = aggregate_members.get(key, ())
        if members:
            return tuple(name for member in members for name in physical((key[0], member), seen) or (member,))
        parent = parent_for(key)
        if parent and (key[0], parent) in objects:
            return physical((key[0], parent), seen)
        return (key[1],) if _kind(getattr(objects[key], "interface_family", None)) == "physical" else ()

    entries: list[PANInterfaceTopologyEntry] = []
    for key, item in objects.items():
        path, path_issues = chain(key)
        imports = tuple(item.scope.vsys for item in config.interface_imports if key[1] in (item.interfaces or ()) and item.scope and item.scope.vsys)
        imported_routers = {router for import_item in config.interface_imports if import_item.scope and import_item.scope.vsys in imports for router in import_item.virtual_routers or ()}
        zones = tuple(zone.name for zone in config.zones if key[1] in (zone.members or ()) and zone.scope and zone.scope.vsys in imports and zone.name)
        routers = tuple(router.name for router in config.virtual_routers if key[1] in (router.interfaces or ()) and router.name and (router.name in imported_routers or scope_for(router) == key[0]))
        issues = list(path_issues)
        if not imports and zones:
            issues.append("zone member is not imported into this VSYS")
        if not imports and routers:
            issues.append("virtual-router member is not imported into this VSYS")
        parent = path[1] if len(path) > 1 else None
        aggregate_owners_for_item = aggregate_owners(key)
        aggregate = aggregate_owners_for_item[0] if len(aggregate_owners_for_item) == 1 else None
        tunnel_names = tuple(tunnel.name for tunnel in config.ipsec_tunnels if tunnel.tunnel_interface == key[1] and tunnel.name)
        child_units = tuple(unit.name for unit in units if unit.parent == key[1] and scope_for(unit) == key[0] and unit.name)
        if len(aggregate_owners_for_item) > 1:
            issues.append(f"interface belongs to multiple aggregate interfaces: {', '.join(aggregate_owners_for_item)}")
        entries.append(PANInterfaceTopologyEntry(key[1], key[0], child_units, imports, zones, routers, tuple(dict.fromkeys(issues)), _kind(getattr(item, "interface_family", None)), parent, path, aggregate, physical(key), tunnel_names))

    known = set(objects)
    for item in config.interface_imports:
        for name in item.interfaces or ():
            if (pan_scope_identity(item.scope), name) not in known:
                entries.append(PANInterfaceTopologyEntry(name, pan_scope_identity(item.scope), imported_vsys=(item.scope.vsys,) if item.scope and item.scope.vsys else (), issues=("import of missing interface",)))
    return tuple(entries)
