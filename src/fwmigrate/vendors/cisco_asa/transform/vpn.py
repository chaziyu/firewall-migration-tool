"""ASA-native VPN topology composed from resolved relationships."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ASAVPNTopologyEntry:
    source_context: str | None
    topology_type: str
    source_identity: Any
    crypto_map: str | None = None
    crypto_map_sequence: int | None = None
    crypto_acl: Any = None
    peers: tuple[Any, ...] = ()
    tunnel_groups: tuple[Any, ...] = ()
    transform_sets: tuple[Any, ...] = ()
    ikev2_proposals: tuple[Any, ...] = ()
    interface: Any = None
    physical_interfaces: tuple[Any, ...] = ()
    tunnel_interface: Any = None
    tunnel_source: str | None = None
    tunnel_destination: str | None = None
    ipsec_profile: str | None = None
    resolution_status: str | None = None
    group_policy: Any = None
    address_pools: tuple[Any, ...] = ()
    trustpoint: Any = None
    issues: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ASAVPNTransformResult:
    topologies: tuple[ASAVPNTopologyEntry, ...] = ()
    issues: tuple[str, ...] = ()


def build_vpn_topology(config: Any, relationships: Any, interface_topology: Any) -> ASAVPNTransformResult:
    by_source = {id(row.source): row for row in relationships.relationships}
    interfaces = {(row.source_context, row.name): row for row in interface_topology.interfaces}
    entries, issues = [], []
    for source in config.crypto_maps:
        rel = by_source.get(id(source)); targets = {}
        if rel:
            for key, value in rel.targets: targets.setdefault(key, []).append(value)
        interface = (targets.get("interface") or [None])[0]
        topology = interfaces.get((source.source_context, getattr(interface, "name", None)))
        local = tuple(issue.reason for issue in (rel.issues if rel else ()))
        entries.append(ASAVPNTopologyEntry(source.source_context, "policy-based", source,
            source.map_name or source.name, source.sequence, (targets.get("crypto-acl") or [None])[0],
            tuple(source.peers or ([source.peer] if source.peer else ())), tuple(targets.get("peer", ())),
            tuple(targets.get("transform-set", ())), tuple(targets.get("ikev2-proposal", ())), interface,
            tuple(topology.physical_interfaces) if topology else (), issues=local))
        issues.extend(local)
    for source in config.interfaces:
        if source.interface_type != "tunnel" and not (source.tunnel_source or source.ipsec_profile): continue
        entries.append(ASAVPNTopologyEntry(source.source_context, "vti", source, interface=source,
            tunnel_interface=source.name, tunnel_source=source.tunnel_source, tunnel_destination=source.tunnel_destination,
            ipsec_profile=source.ipsec_profile, resolution_status="SOURCE_ONLY" if source.ipsec_profile else None))
    for source in config.tunnel_groups:
        rel = by_source.get(id(source)); targets = {}
        if rel:
            for key, value in rel.targets: targets.setdefault(key, []).append(value)
        if any(targets.get(key) for key in ("group-policy", "address-pool", "trustpoint")):
            local = tuple(issue.reason for issue in rel.issues) if rel else ()
            entries.append(ASAVPNTopologyEntry(source.source_context, "remote-access", source,
                tunnel_groups=(source,), group_policy=(targets.get("group-policy") or [None])[0],
                address_pools=tuple(targets.get("address-pool", ())), trustpoint=(targets.get("trustpoint") or [None])[0], issues=local))
            issues.extend(local)
    return ASAVPNTransformResult(tuple(entries), tuple(issues))
