"""Read-only composition of Cisco ASA relationships."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .relationships.references import (ASAReferenceIndex, ASAReferenceKind, ASAReferenceStatus,
                                      build_asa_reference_index, source_context_of)
from .relationships.interface_topology import build_asa_interface_topology
from .relationships.acl import build_acl_relationships
from .relationships.nat import build_nat_relationships
from .relationships.mpf import build_mpf_relationships
from .relationships.routing import build_routing_relationships
from .relationships.identity import build_identity_relationships
from .relationships.vpn import build_vpn_relationships
from .reference_validation import ReferenceIssue
from .transform.nat import ASANATTransformResult, transform_nat
from .transform.routes import ASARouteTransformResult, transform_routes
from .transform.vpn import ASAVPNTransformResult, build_vpn_topology


@dataclass(frozen=True)
class ASADerivedViews:
    references: ASAReferenceIndex
    interface_topology: Any
    acl_relationships: Any
    nat_relationships: Any
    mpf_relationships: Any
    routing_relationships: Any
    identity_relationships: Any
    vpn_relationships: Any
    nat: ASANATTransformResult = field(default_factory=ASANATTransformResult)
    vpn: ASAVPNTransformResult = field(default_factory=ASAVPNTransformResult)
    routes: ASARouteTransformResult = field(default_factory=ASARouteTransformResult)
    group_address_families: dict[str, str | None] = field(default_factory=dict)
    object_group_memberships: dict[str, tuple[str, ...]] = field(default_factory=dict)
    reference_issues: tuple[ReferenceIssue, ...] = ()

    @property
    def interface_nameifs(self) -> dict[str, str]:
        return {entry.name: entry.nameif for entry in self.interface_topology.interfaces if entry.nameif}

    @property
    def acl_bindings(self) -> dict[str, tuple[Any, ...]]:
        return {name: tuple(row.binding for row in self.acl_relationships.bindings if row.acl_name == name)
                for name in {row.acl_name for row in self.acl_relationships.bindings}}


def build_asa_derived_views(config: Any) -> ASADerivedViews:
    references = build_asa_reference_index(config)
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
    for issue in (*topology.issues, *acl.issues, *nat.issues, *mpf.issues,
                  *routing.issues, *identity.issues, *vpn.issues):
        issues.append(ReferenceIssue(issue.reference_kind.value, issue.source_object,
                                     issue.reference_name, issue.status.value == "RESOLVED",
                                     issue.reason, issue.source_context, issue.reference_context))
    for group in config.network_groups:
        for entry in getattr(group, "member_entries", ()):
            get = entry.get if isinstance(entry, dict) else lambda key, default=None: getattr(entry, key, default)
            kinds = {"network_object": (ASAReferenceKind.NETWORK_OBJECT,),
                     "network_group": (ASAReferenceKind.NETWORK_GROUP,),
                     "nested_group": (ASAReferenceKind.NETWORK_GROUP,)}.get(get("type"), ())
            name = get("value", "")
            for kind in kinds:
                result = references.resolve(source_context_of(group), kind, name)
                if result.status is not ASAReferenceStatus.RESOLVED:
                    issues.append(ReferenceIssue(kind.value, group.name, name, False,
                                                 f"Unresolved {kind.value.replace('_', ' ')} reference",
                                                 source_context_of(group)))
    issues.extend(ReferenceIssue(duplicate.reference_kind.value, duplicate.source_name,
                                duplicate.source_name, False,
                                f"Duplicate {duplicate.reference_kind.value} definition",
                                duplicate.source_context)
                  for duplicate in references.duplicates)
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
                           nat_transform, vpn_transform, route_transform, families, memberships, tuple(issues))


__all__ = ["ASADerivedViews", "build_asa_derived_views"]
