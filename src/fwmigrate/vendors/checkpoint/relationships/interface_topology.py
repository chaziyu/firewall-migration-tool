from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..model.gateway import CPCluster, CPGateway, CPInteroperableDevice
from ..model.source import CheckPointConfig
from .references import CPBrokenReference, CPReferenceIndex, CPReferenceKind, CPResolvedReference


@dataclass(frozen=True, slots=True)
class CPInterfaceZoneRelationship:
    device: Any; device_kind: str; interface: Any; zone_reference: Any
    resolved_zone: Any | None; assignment_source: str | None = None; issues: tuple[CPBrokenReference, ...] = ()


@dataclass(frozen=True, slots=True)
class CPGaiaInterfaceRelationship:
    gaia_interface: Any; resolved_device: Any | None = None; management_interface: Any | None = None
    issues: tuple[CPBrokenReference, ...] = ()


@dataclass(frozen=True, slots=True)
class CPInterfaceTopology:
    interfaces: tuple[CPInterfaceZoneRelationship, ...] = (); issues: tuple[CPBrokenReference, ...] = ()
    gaia_interfaces: tuple[CPGaiaInterfaceRelationship, ...] = ()


def build_interface_topology(config: CheckPointConfig, references: CPReferenceIndex | None = None) -> CPInterfaceTopology:
    from .references import build_reference_index
    references = references or build_reference_index(config); rows = []; gaia_rows = []; issues = []
    devices = (*config.gateways, *config.clusters, *config.interoperable_devices)
    for device in devices:
        kind = "cluster" if isinstance(device, CPCluster) else "interoperable_device" if isinstance(device, CPInteroperableDevice) else "gateway"
        for interface in device.interfaces:
            if not interface.zone:
                rows.append(CPInterfaceZoneRelationship(device, kind, interface, None, None)); continue
            result = references.resolve(interface.zone, owner=device, expected_kinds=(CPReferenceKind.SECURITY_ZONE,), source_field="zone")
            if isinstance(result, CPResolvedReference): rows.append(CPInterfaceZoneRelationship(device, kind, interface, interface.zone, result.target))
            else:
                rows.append(CPInterfaceZoneRelationship(device, kind, interface, interface.zone, None, issues=(result,))); issues.append(result)
    device_kinds = (CPReferenceKind.GATEWAY, CPReferenceKind.CLUSTER, CPReferenceKind.INTEROPERABLE_DEVICE)
    for interface in config.gaia_interfaces:
        if not interface.gateway or "gateway" not in interface.explicit_fields:
            gaia_rows.append(CPGaiaInterfaceRelationship(interface))
            continue
        result = references.resolve(interface.gateway, owner=interface, expected_kinds=device_kinds, source_field="gateway")
        if not isinstance(result, CPResolvedReference):
            gaia_rows.append(CPGaiaInterfaceRelationship(interface, issues=(result,)))
            issues.append(result)
            continue
        device = result.target
        matches = [item for item in device.interfaces if interface.name and item.name == interface.name]
        if len(matches) > 1:
            issue = CPBrokenReference(interface, "interface", interface.name or "", status="ambiguous",
                                      message="Gateway has multiple interfaces with the exact Gaia interface name.")
            gaia_rows.append(CPGaiaInterfaceRelationship(interface, device, issues=(issue,)))
            issues.append(issue)
        else:
            gaia_rows.append(CPGaiaInterfaceRelationship(interface, device, matches[0] if matches else None))
    return CPInterfaceTopology(tuple(rows), tuple(issues), tuple(gaia_rows))


__all__ = ["CPGaiaInterfaceRelationship", "CPInterfaceTopology", "CPInterfaceZoneRelationship", "build_interface_topology"]
