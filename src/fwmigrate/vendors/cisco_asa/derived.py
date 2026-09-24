"""Read-only composition of Cisco ASA relationships."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .relationships.references import (ASAReferenceIndex, ASAReferenceIssue, ASAReferenceStatus,
                                      ASAGroupRelationships, build_asa_reference_index,
                                      build_group_relationships)
from .relationships.interface_topology import ASAInterfaceTopology, build_asa_interface_topology
from .relationships.acl import ASAACLRelationships, build_acl_relationships
from .relationships.nat import ASANATRelationships, build_nat_relationships
from .relationships.mpf import ASAMPFRelationships, build_mpf_relationships
from .relationships.routing import ASARoutingRelationships, build_routing_relationships
from .relationships.identity import ASAIdentityRelationships, build_identity_relationships
from .relationships.vpn import ASAVPNRelationships, build_vpn_relationships
from .transform.nat import ASANATTransformResult, transform_nat
from .transform.routes import ASARouteTransformResult, transform_routes
from .transform.vpn import ASAVPNTransformResult, build_vpn_topology


@dataclass(frozen=True, slots=True)
class ASATransformIssue:
    category: str
    source_context: str | None
    source_object: str | None
    message: str


@dataclass(frozen=True)
class ASADerivedViews:
    references: ASAReferenceIndex
    interface_topology: ASAInterfaceTopology
    acl_relationships: ASAACLRelationships
    nat_relationships: ASANATRelationships
    mpf_relationships: ASAMPFRelationships
    routing_relationships: ASARoutingRelationships
    identity_relationships: ASAIdentityRelationships
    vpn_relationships: ASAVPNRelationships
    nat: ASANATTransformResult = field(default_factory=ASANATTransformResult)
    vpn: ASAVPNTransformResult = field(default_factory=ASAVPNTransformResult)
    routes: ASARouteTransformResult = field(default_factory=ASARouteTransformResult)
    group_address_families: dict[str, str | None] = field(default_factory=dict)
    object_group_memberships: dict[str, tuple[str, ...]] = field(default_factory=dict)
    relationship_issues: tuple[ASAReferenceIssue, ...] = ()
    transform_issues: tuple["ASATransformIssue", ...] = ()
    group_relationships: ASAGroupRelationships = field(default_factory=ASAGroupRelationships)



def build_asa_derived_views(config: Any) -> ASADerivedViews:
    references = build_asa_reference_index(config)
    groups = build_group_relationships(config, references)
    topology = build_asa_interface_topology(config, references)
    acl = build_acl_relationships(config, references)
    nat = build_nat_relationships(config, references)
    mpf = build_mpf_relationships(config, references)
    routing = build_routing_relationships(config, references)
    identity = build_identity_relationships(config, references)
    vpn = build_vpn_relationships(config, references)
    nat_transform = transform_nat(config, nat)
    vpn_transform = build_vpn_topology(config, vpn, topology)
    route_transform = transform_routes(config, routing)

    issues = []
    for issue in (*groups.issues, *topology.issues, *acl.issues, *nat.issues, *mpf.issues,
                  *routing.issues, *identity.issues, *vpn.issues):
        issues.append(issue)
    issues.extend(ASAReferenceIssue(duplicate.source_context, duplicate.reference_kind,
                                    duplicate.source_name, duplicate.source_name,
                                    ASAReferenceStatus.AMBIGUOUS,
                                    f"Duplicate {duplicate.reference_kind.value} definition")
                  for duplicate in references.duplicates)
    transform_issue_rows = [
        ASATransformIssue(category, row.source_context,
                          getattr(getattr(row, "source_rule", None), "name", None)
                          or getattr(getattr(row, "source_route", None), "name", None)
                          or getattr(getattr(row, "source_identity", None), "name", None)
                          or getattr(getattr(row, "tunnel_group", None), "name", None), message)
        for category, rows in (("nat", (*nat_transform.rules, *nat_transform.source_nat_pools, *nat_transform.vips)),
                               ("vpn", (*vpn_transform.topologies, *vpn_transform.remote_access)),
                               ("routes", route_transform.routes))
        for row in rows for message in row.issues
    ]
    transform_issue_rows.extend(ASATransformIssue("nat", None, None, message) for message in nat_transform.issues)
    transform_issues = tuple(dict.fromkeys(transform_issue_rows))
    memberships = {
        f"{getattr(group, 'source_context', None) or '__global__'}:{group.name}": tuple(
            entry.get("value", "") if isinstance(entry, dict) else getattr(entry, "value", "")
            for entry in (getattr(group, "member_entries", None) or group.members)
        ) for group in config.network_groups
    }
    families = {f"{context or '__global__'}:{name}": family
                for context in references.contexts
                for name, family in references.group_address_families(context).items()}
    return ASADerivedViews(references, topology, acl, nat, mpf, routing, identity, vpn,
                           nat_transform, vpn_transform, route_transform, families, memberships,
                           tuple(issues), transform_issues, groups)


__all__ = ["ASADerivedViews", "build_asa_derived_views"]
