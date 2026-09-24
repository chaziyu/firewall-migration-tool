"""ASA policy VPN and remote-access source dependencies."""

from dataclasses import dataclass
from typing import Any

from .references import ASAReferenceIndex


@dataclass(frozen=True, slots=True)
class ASAVPNRelationship:
    source: Any
    targets: tuple[tuple[str, Any], ...] = ()
    issues: tuple[Any, ...] = ()
    source_only: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ASAVPNRelationships:
    relationships: tuple[ASAVPNRelationship, ...] = ()
    issues: tuple[Any, ...] = ()


def build_vpn_relationships(config: Any, references: ASAReferenceIndex) -> ASAVPNRelationships:
    from .references import ASAReferenceIssue, ASAReferenceKind, ASAReferenceStatus
    rows = []; all_issues = []
    def make(source, fields, peer=False):
        ctx = getattr(source, "source_context", None); targets = []; issues = []
        for kind, names, field in fields:
            for name in names if isinstance(names, (list, tuple)) else (names,):
                if not name: continue
                result = references.resolve(ctx, kind, str(name))
                if result.status is ASAReferenceStatus.RESOLVED:
                    targets.append((field, result.target)); continue
                if kind is ASAReferenceKind.TUNNEL_GROUP and peer:
                    candidates = [g for g in config.tunnel_groups if getattr(g, "source_context", None) == ctx and (g.name == name or getattr(g, "peer_address", None) == name)]
                    if len(candidates) == 1:
                        targets.append((field, candidates[0])); continue
                    status = ASAReferenceStatus.AMBIGUOUS if len(candidates) > 1 else ASAReferenceStatus.UNRESOLVED
                else: status = result.status
                issues.append(ASAReferenceIssue(ctx, kind, source.name, str(name), status, f"Unresolved {kind.value} reference", field))
        rows.append(ASAVPNRelationship(source, tuple(targets), tuple(issues))); all_issues.extend(issues)
    for item in config.crypto_maps:
        interface = item.interface_attachment or next((candidate.interface_attachment for candidate in config.crypto_maps
                        if candidate.name == item.name and getattr(candidate, "source_context", None) == getattr(item, "source_context", None)
                        and candidate.interface_attachment), None)
        make(item, [(ASAReferenceKind.ACL, item.acl_name, "crypto-acl"), (ASAReferenceKind.IPSEC_TRANSFORM_SET, item.transform_sets, "transform-set"), (ASAReferenceKind.IKEV2_PROPOSAL, item.ikev2_proposals, "ikev2-proposal"), (ASAReferenceKind.INTERFACE, interface, "interface"), (ASAReferenceKind.CRYPTO_MAP, item.dynamic_map, "dynamic-map"), (ASAReferenceKind.TUNNEL_GROUP, item.peers or ([item.peer] if item.peer else []), "peer")], True)
    for item in config.tunnel_groups:
        make(item, [(ASAReferenceKind.GROUP_POLICY, getattr(item, "default_group_policy", None), "group-policy"), (ASAReferenceKind.VPN_ADDRESS_POOL, getattr(item, "address_pools", ()), "address-pool"), (ASAReferenceKind.TRUSTPOINT, getattr(item, "trustpoint", None), "trustpoint")])
    for item in config.group_policies:
        make(item, [(ASAReferenceKind.GROUP_POLICY, getattr(item, "parent", None), "parent"), (ASAReferenceKind.VPN_ADDRESS_POOL, getattr(item, "address_pools", ()), "address-pool"), (ASAReferenceKind.ACL, getattr(item, "split_tunnel_acl", None), "split-tunnel-acl")])
    for item in config.interfaces:
        if getattr(item, "ipsec_profile", None):
            rows.append(ASAVPNRelationship(item, (), (), ("ipsec-profile",)))
    return ASAVPNRelationships(tuple(rows), tuple(all_issues))
