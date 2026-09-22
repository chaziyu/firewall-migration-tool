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


def build_interface_topology(config: PANOSConfig) -> tuple[PANInterfaceTopologyEntry, ...]:
    entries: list[PANInterfaceTopologyEntry] = []
    for interface in config.interfaces:
        scope = pan_scope_identity(interface.scope)
        units = tuple(unit.name for unit in config.interface_units if unit.parent == interface.name and pan_scope_identity(interface.scope) == scope and unit.name)
        imports = tuple((item.scope.vsys if item.scope else "") for item in config.interface_imports if interface.name in (item.interfaces or ()) and item.scope and item.scope.vsys)
        imported_routers = {name for item in config.interface_imports if item.scope and item.scope.vsys for name in item.virtual_routers or ()}
        zones = tuple(zone.name for zone in config.zones if interface.name in (zone.members or ()) and zone.scope and zone.scope.vsys in imports and zone.name)
        routers = tuple(router.name for router in config.virtual_routers if interface.name in (router.interfaces or ()) and router.name and (router.name in imported_routers or pan_scope_identity(router.scope) == scope))
        issues: list[str] = []
        if interface.name and any(unit.parent == interface.name for unit in config.interface_units) and not units:
            issues.append("unit scope does not match interface scope")
        if not imports and zones:
            issues.append("zone member is not imported into this VSYS")
        if not imports and routers:
            issues.append("virtual-router member is not imported into this VSYS")
        entries.append(PANInterfaceTopologyEntry(interface.name or "", scope, units, imports, zones, routers, tuple(issues)))
    for item in config.interface_imports:
        for name in item.interfaces or ():
            if not any(interface.name == name for interface in config.interfaces):
                entries.append(PANInterfaceTopologyEntry(name, pan_scope_identity(item.scope), imported_vsys=(item.scope.vsys,) if item.scope and item.scope.vsys else (), issues=("import of missing interface",)))
    return tuple(entries)
