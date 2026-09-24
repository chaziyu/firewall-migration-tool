from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..model.gateway import CPCluster, CPGateway, CPInteroperableDevice
from ..model.source import CheckPointConfig
from .references import CPBrokenReference, CPReferenceIndex, CPReferenceKind, CPResolvedReference


@dataclass(frozen=True, slots=True)
class CPInterfaceZoneRelationship:
    device: Any; device_kind: str; interface: Any; zone_reference: Any
    resolved_zone: Any | None; assignment_source: str = "explicit"; issues: tuple[CPBrokenReference, ...] = ()


@dataclass(frozen=True, slots=True)
class CPInterfaceTopology:
    interfaces: tuple[CPInterfaceZoneRelationship, ...] = (); issues: tuple[CPBrokenReference, ...] = ()


def build_interface_topology(config: CheckPointConfig, references: CPReferenceIndex | None = None) -> CPInterfaceTopology:
    from .references import build_reference_index
    references = references or build_reference_index(config); rows = []; issues = []
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
    return CPInterfaceTopology(tuple(rows), tuple(issues))


__all__ = ["CPInterfaceTopology", "CPInterfaceZoneRelationship", "build_interface_topology"]
