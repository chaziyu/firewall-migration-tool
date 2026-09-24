from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..model.gateway import CPCluster, CPGateway, CPInteroperableDevice
from ..model.source import CheckPointConfig
from .references import CPBrokenReference, CPReferenceIndex, CPReferenceKind, CPResolvedReference


@dataclass(frozen=True, slots=True)
class CPVPNCommunityTopology:
    community: Any; community_type: str | None; members: tuple[Any, ...] = (); centers: tuple[Any, ...] = (); satellites: tuple[Any, ...] = ()
    unresolved_members: tuple[CPBrokenReference, ...] = (); issues: tuple[CPBrokenReference, ...] = ()


@dataclass(frozen=True, slots=True)
class CPVTITopology:
    vti: Any; owning_gateway: Any | None; peer: Any | None; matching_communities: tuple[Any, ...] = (); issues: tuple[CPBrokenReference, ...] = ()


@dataclass(frozen=True, slots=True)
class CPVPNTopology:
    communities: tuple[CPVPNCommunityTopology, ...] = (); vtis: tuple[CPVTITopology, ...] = (); issues: tuple[CPBrokenReference, ...] = ()


def _resolve_many(owner, values, index, kinds, field):
    good = []; bad = []
    for value in values or ():
        result = index.resolve(value, owner=owner, expected_kinds=kinds, source_field=field)
        (good if isinstance(result, CPResolvedReference) else bad).append(result.target if isinstance(result, CPResolvedReference) else result)
    return tuple(good), tuple(bad)


def build_vpn_topology(config: CheckPointConfig, references: CPReferenceIndex | None = None, interface_topology=None) -> CPVPNTopology:
    from .references import build_reference_index
    references = references or build_reference_index(config); communities = []; issues = []
    device_kinds = (CPReferenceKind.GATEWAY, CPReferenceKind.CLUSTER, CPReferenceKind.INTEROPERABLE_DEVICE)
    for community in config.vpn_communities:
        members, bad = _resolve_many(community, (*community.participating_gateways,), references, device_kinds, "participating_gateways")
        centers, bad_center = _resolve_many(community, community.center, references, device_kinds, "center")
        satellites, bad_sat = _resolve_many(community, community.satellites, references, device_kinds, "satellites")
        issues.extend((*bad, *bad_center, *bad_sat)); communities.append(CPVPNCommunityTopology(community, community.community_type, members, centers, satellites, (*bad, *bad_center, *bad_sat), (*bad, *bad_center, *bad_sat)))
    vtis = []
    for vti in config.vtis:
        owner = references.resolve(vti.gateway, owner=vti, expected_kinds=device_kinds, source_field="gateway") if vti.gateway else None
        peer = references.resolve(vti.peer, owner=vti, expected_kinds=device_kinds, source_field="peer") if vti.peer else None
        owner_obj = owner.target if isinstance(owner, CPResolvedReference) else None
        peer_obj = peer.target if isinstance(peer, CPResolvedReference) else None
        vti_issues = tuple(item for item in (owner, peer) if isinstance(item, CPBrokenReference))
        matching = tuple(item.community for item in communities if owner_obj in item.members and (peer_obj is None or peer_obj in item.members))
        vtis.append(CPVTITopology(vti, owner_obj, peer_obj, matching, vti_issues)); issues.extend(vti_issues)
    return CPVPNTopology(tuple(communities), tuple(vtis), tuple(issues))


__all__ = ["CPVPNCommunityTopology", "CPVPNTopology", "CPVTITopology", "build_vpn_topology"]
