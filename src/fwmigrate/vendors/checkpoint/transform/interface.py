"""Read-only Check Point interface migration views."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace

from ..model.gaia import CPGaiaInterface
from ..model.gateway import CPGatewayInterface
from ..model.source import CheckPointConfig
from ..relationships.interface_topology import CPInterfaceTopology


@dataclass(frozen=True, slots=True)
class CPInterfaceTransformIssue:
    message: str
    device_uid: str | None = None
    interface_name: str | None = None


@dataclass(frozen=True, slots=True)
class CPInterfaceView:
    device_uid: str | None
    device_name: str | None
    device_kind: str
    interface_name: str | None
    explicit_ipv4: str | None
    explicit_ipv6: str | None
    resolved_zone_uid: str | None
    resolved_zone_name: str | None
    zone_assignment_source: str | None
    topology: str | None
    management_source: CPGatewayInterface | None = None
    gaia_source: CPGaiaInterface | None = None
    management_source_present: bool = False
    gaia_source_present: bool = False
    issues: tuple[CPInterfaceTransformIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class CPInterfaceTransformResult:
    views: tuple[CPInterfaceView, ...] = ()
    issues: tuple[CPInterfaceTransformIssue, ...] = ()


def transform_interfaces(
    config: CheckPointConfig,
    topology: CPInterfaceTopology,
) -> CPInterfaceTransformResult:
    """Present management interfaces with Gaia correlation when identity resolves."""
    views = []
    issues = []
    management_views = {}
    for relation in topology.interfaces:
        device, source = relation.device, relation.interface
        row_issues = tuple(CPInterfaceTransformIssue(
            f"Zone reference {issue.reference!r} is {issue.status}.",
            device.uid, source.name,
        ) for issue in relation.issues)
        issues.extend(row_issues)
        zone = relation.resolved_zone
        view = CPInterfaceView(
            device.uid, device.name, relation.device_kind, source.name,
            source.ipv4_address, source.ipv6_address,
            zone.uid if zone else None, zone.name if zone else None,
            relation.assignment_source if source.zone else None, source.topology,
            management_source=source, management_source_present=True, issues=row_issues,
        )
        management_views[id(source)] = len(views)
        views.append(view)

    for relation in topology.gaia_interfaces:
        source, device = relation.gaia_interface, relation.resolved_device
        row_issues = tuple(CPInterfaceTransformIssue(issue.message or f"Gateway reference {issue.reference!r} is {issue.status}.",
                                                      device.uid if device else None, source.name)
                           for issue in relation.issues)
        issues.extend(row_issues)
        if relation.management_interface is not None:
            index = management_views[id(relation.management_interface)]
            views[index] = replace(views[index], gaia_source=source, gaia_source_present=True,
                                   issues=(*views[index].issues, *row_issues))
            continue
        kind = ("cluster" if type(device).__name__ == "CPCluster" else
                "interoperable_device" if type(device).__name__ == "CPInteroperableDevice" else "gateway") if device else "gaia_unassociated"
        if not device and not row_issues:
            row_issues = (CPInterfaceTransformIssue(
                "Gaia interface source has no unambiguous management device identity; retained without correlation.",
                interface_name=source.name,
            ),)
            issues.extend(row_issues)
        views.append(CPInterfaceView(
            device.uid if device else None, device.name if device else None, kind, source.name,
            source.ipv4_address, source.ipv6_address, None, None, None, source.topology,
            gaia_source=source, gaia_source_present=True, issues=row_issues,
        ))
    return CPInterfaceTransformResult(tuple(views), tuple(issues))


__all__ = ["CPInterfaceTransformIssue", "CPInterfaceTransformResult", "CPInterfaceView", "transform_interfaces"]
