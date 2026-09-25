"""Read-only Check Point VPN architecture views."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..model.gateway import CPCluster, CPGateway, CPInteroperableDevice
from ..model.gaia import CPVTI
from ..model.vpn import CPVPNCommunity, CPVPNDomain
from ..relationships.references import CPBrokenReference, CPReferenceIndex
from ..relationships.vpn_topology import CPVPNCommunityTopology, CPVPNTopology, CPVTITopology


@dataclass(frozen=True, slots=True)
class CPVPNTransformIssue:
    message: str
    source_uid: str | None = None
    source_name: str | None = None
    source_field: str | None = None
    reference: str | None = None
    relationship_status: str | None = None


@dataclass(frozen=True, slots=True)
class CPVPNMigrationView:
    community_uid: str | None
    community_name: str | None
    community_type: str | None
    member_gateways: tuple[CPGateway, ...] = ()
    member_clusters: tuple[CPCluster, ...] = ()
    member_interoperable_devices: tuple[CPInteroperableDevice, ...] = ()
    center_members: tuple[Any, ...] = ()
    satellite_members: tuple[Any, ...] = ()
    vpn_domains: tuple[CPVPNDomain, ...] = ()
    vtis: tuple[CPVTI, ...] = ()
    vti_topology: tuple[CPVTITopology, ...] = ()
    route_based: bool | None = None
    ike_properties: dict[str, Any] | None = None
    ipsec_properties: dict[str, Any] | None = None
    community_source: CPVPNCommunity | None = None
    gateway_vpn_sources: tuple[CPGateway, ...] = ()
    issues: tuple[CPVPNTransformIssue, ...] = ()


@dataclass(frozen=True, slots=True)
class CPVPNTransformResult:
    views: tuple[CPVPNMigrationView, ...] = ()
    issues: tuple[CPVPNTransformIssue, ...] = ()


def _issue(reference: CPBrokenReference) -> CPVPNTransformIssue:
    source = reference.source
    return CPVPNTransformIssue(
        reference.message or f"Reference {reference.reference!r} is {reference.status}.",
        getattr(source, "uid", None), getattr(source, "name", None),
        reference.source_field, reference.reference, reference.status,
    )


def _devices(items: tuple[Any, ...], kind: type) -> tuple[Any, ...]:
    return tuple(item for item in items if isinstance(item, kind))


def _unique_identity(items: tuple[Any, ...]) -> tuple[Any, ...]:
    result = []
    seen = set()
    for item in items:
        if id(item) not in seen:
            seen.add(id(item))
            result.append(item)
    return tuple(result)


def transform_vpn(topology: CPVPNTopology, references: CPReferenceIndex) -> CPVPNTransformResult:
    """Build community views from resolved relationships and explicit source records."""
    views: list[CPVPNMigrationView] = []
    issues: list[CPVPNTransformIssue] = []
    represented_vtis: set[int] = set()

    def make_view(community_topology: CPVPNCommunityTopology | None,
                  vti_topology: tuple[CPVTITopology, ...]) -> CPVPNMigrationView:
        community = community_topology.community if community_topology else None
        members = community_topology.members if community_topology else ()
        centers = community_topology.centers if community_topology else ()
        satellites = community_topology.satellites if community_topology else ()
        view_issues = [_issue(item) for item in community_topology.issues] if community_topology else []
        view_issues.extend(_issue(item) for relation in vti_topology for item in relation.issues)
        for relation in vti_topology:
            if len(relation.matching_communities) > 1:
                view_issues.append(CPVPNTransformIssue(
                    "VTI matches multiple VPN communities; community correlation is ambiguous.",
                    relation.vti.uid, relation.vti.name, "matching_communities",
                    relation.vti.name, "ambiguous",
                ))
        devices = _unique_identity((*members, *(item.owning_gateway for item in vti_topology if item.owning_gateway)))
        domains = tuple(item.domain for item in topology.vpn_domains
                        if any(member in devices for member in item.members))
        for item in topology.vpn_domains:
            if item.domain in domains:
                view_issues.extend(_issue(issue) for issue in item.issues)
        gateway_sources = tuple(item for item in devices if isinstance(item, CPGateway) and item.vpn is not None)
        member_gateways = tuple(item for item in members if isinstance(item, CPGateway)
                                and not isinstance(item, (CPCluster, CPInteroperableDevice)))
        return CPVPNMigrationView(
            community_uid=community.uid if community else None,
            community_name=community.name if community else None,
            community_type=community.community_type if community else None,
            member_gateways=member_gateways,
            member_clusters=_devices(members, CPCluster),
            member_interoperable_devices=_devices(members, CPInteroperableDevice),
            center_members=centers,
            satellite_members=satellites,
            vpn_domains=domains,
            vtis=tuple(item.vti for item in vti_topology),
            vti_topology=vti_topology,
            route_based=True if vti_topology else None,
            ike_properties=community.ike_properties if community else None,
            ipsec_properties=community.ipsec_properties if community else None,
            community_source=community,
            gateway_vpn_sources=gateway_sources,
            issues=tuple(view_issues),
        )

    for community_topology in topology.communities:
        linked = tuple(item for item in topology.vtis if any(
            community_topology.community is community for community in item.matching_communities
        ))
        represented_vtis.update(id(item) for item in linked)
        view = make_view(community_topology, linked)
        views.append(view)
        issues.extend(view.issues)
    for item in topology.vtis:
        if id(item) not in represented_vtis:
            view = make_view(None, (item,))
            views.append(view)
            issues.extend(view.issues)

    return CPVPNTransformResult(tuple(views), tuple(dict.fromkeys(issues)))


__all__ = ["CPVPNMigrationView", "CPVPNTransformIssue", "CPVPNTransformResult", "transform_vpn"]
