"""Check Point relationships and read-only derived views."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model.source import CheckPointConfig
from .relationships.identity import CPIdentityRelationships, build_identity_relationships
from .relationships.interface_topology import CPInterfaceTopology, build_interface_topology
from .relationships.policy_structure import CPPolicyStructure, build_policy_structure
from .relationships.references import CPReferenceIndex, build_memberships, build_reference_index, collect_broken_references
from .relationships.vpn_topology import CPVPNTopology, build_vpn_topology


@dataclass(frozen=True)
class CheckPointDerivedViews:
    references: CPReferenceIndex = field(default_factory=CPReferenceIndex)
    policy_structure: CPPolicyStructure = field(default_factory=CPPolicyStructure)
    interface_topology: CPInterfaceTopology = field(default_factory=CPInterfaceTopology)
    vpn_topology: CPVPNTopology = field(default_factory=CPVPNTopology)
    identity: CPIdentityRelationships = field(default_factory=CPIdentityRelationships)
    broken_references: tuple[Any, ...] = ()
    collection_incomplete: tuple[Any, ...] = ()

    @property
    def by_uid(self): return self.references.by_uid

    @property
    def by_name(self): return self.references.by_name

    @property
    def group_memberships(self):
        result = {}
        for edge in build_memberships_from_index(self.references):
            key = edge.owner.uid or f"{edge.owner.domain_uid or edge.owner.domain or 'global'}:{edge.owner.name}"
            result.setdefault(key, []).append(edge.member_reference)
        return {key: tuple(value) for key, value in result.items()}

    @property
    def package_layers(self): return self.policy_structure.package_layer_map

    @property
    def inline_layers(self): return self.policy_structure.inline_layer_map

    @property
    def unresolved_references(self): return tuple({"command": getattr(item.source, "command", None), "uid": getattr(item.source, "uid", None), "reference": item.reference} for item in self.broken_references)


def build_memberships_from_index(index):
    # The index deliberately contains no source aggregate, so this compatibility
    # view is populated by the builder below and replaced on each build.
    return getattr(index, "memberships", ())


def build_checkpoint_derived_views(config: CheckPointConfig, collection: tuple[Any, ...] = ()) -> CheckPointDerivedViews:
    references = build_reference_index(config)
    references.memberships = build_memberships(config, references)
    policy = build_policy_structure(config, references)
    interface = build_interface_topology(config, references)
    identity = build_identity_relationships(config, references)
    vpn = build_vpn_topology(config, references, interface)
    broken = (*collect_broken_references(config, references), *policy.issues, *interface.issues, *identity.issues, *vpn.issues)
    unique = []
    for item in broken:
        if item not in unique: unique.append(item)
    return CheckPointDerivedViews(references, policy, interface, vpn, identity, tuple(unique), tuple(item for item in collection if not item.complete))


__all__ = ["CheckPointDerivedViews", "build_checkpoint_derived_views"]
