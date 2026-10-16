"""Check Point relationships and read-only derived views."""

from __future__ import annotations

from dataclasses import dataclass, field

from .model.source import CheckPointConfig
from .model.common import CheckPointSourceObject
from .models import CheckPointCollectionDiagnostic
from .policy_context import CPPolicyContextRecord
from .relationships.identity import CPIdentityRelationships, build_identity_relationships
from .relationships.interface_topology import CPInterfaceTopology, build_interface_topology
from .relationships.policy_structure import CPPolicyStructure, build_policy_structure
from .relationships.references import CPBrokenReference, CPReferenceIndex, build_memberships, build_reference_index, collect_broken_references
from .relationships.vpn_topology import CPVPNTopology, build_vpn_topology
from .transform.nat import CPNATTransformResult, transform_nat
from .transform.policy import CPPolicyTraversalResult, build_policy_traversal
from .transform.interface import CPInterfaceTransformResult, transform_interfaces
from .transform.vpn import CPVPNTransformResult, transform_vpn


@dataclass(frozen=True, slots=True)
class DerivedSourceCompleteness:
    complete: bool = True
    incomplete_commands: tuple[str, ...] = ()
    unknown: bool = False


@dataclass(frozen=True)
class CheckPointDerivedViews:
    references: CPReferenceIndex = field(default_factory=CPReferenceIndex)
    broken_references: tuple[CPBrokenReference, ...] = ()
    policy_structure: CPPolicyStructure = field(default_factory=CPPolicyStructure)
    interface_topology: CPInterfaceTopology = field(default_factory=CPInterfaceTopology)
    vpn_topology: CPVPNTopology = field(default_factory=CPVPNTopology)
    identity: CPIdentityRelationships = field(default_factory=CPIdentityRelationships)
    nat: CPNATTransformResult = field(default_factory=CPNATTransformResult)
    policy_traversal: CPPolicyTraversalResult = field(default_factory=CPPolicyTraversalResult)
    interface_views: CPInterfaceTransformResult = field(default_factory=CPInterfaceTransformResult)
    vpn_views: CPVPNTransformResult = field(default_factory=CPVPNTransformResult)
    nat_completeness: DerivedSourceCompleteness = field(default_factory=DerivedSourceCompleteness)
    policy_completeness: DerivedSourceCompleteness = field(default_factory=DerivedSourceCompleteness)
    interface_completeness: DerivedSourceCompleteness = field(default_factory=DerivedSourceCompleteness)
    vpn_completeness: DerivedSourceCompleteness = field(default_factory=DerivedSourceCompleteness)
    collection_incomplete: tuple[CheckPointCollectionDiagnostic, ...] = ()

    @property
    def by_uid(self) -> dict[str, CheckPointSourceObject]:
        return self.references.by_uid

    @property
    def by_name(self) -> dict[tuple[str | None, str], tuple[CheckPointSourceObject, ...]]:
        return self.references.by_name

    @property
    def group_memberships(self) -> dict[str, tuple[str, ...]]:
        result: dict[str, list[str]] = {}
        for edge in self.references.memberships:
            owner = edge.owner
            key = owner.uid or f"{owner.domain_uid or owner.domain or 'global'}:{owner.name}"
            result.setdefault(key, []).append(edge.member_reference)
        return {key: tuple(value) for key, value in result.items()}

    @property
    def package_layers(self) -> dict[str, tuple[str, ...]]:
        return self.policy_structure.package_layer_map

    @property
    def inline_layers(self) -> dict[str, str]:
        return self.policy_structure.inline_layer_map

    @property
    def unresolved_references(self) -> tuple[dict[str, str | None], ...]:
        return tuple({
            "command": getattr(item.source, "command", None),
            "uid": getattr(item.source, "uid", None),
            "reference": item.reference,
        } for item in self.broken_references)


def build_checkpoint_derived_views(
    config: CheckPointConfig,
    collection: tuple[CheckPointCollectionDiagnostic, ...] = (),
    policy_context: tuple[CPPolicyContextRecord, ...] = (),
) -> CheckPointDerivedViews:
    references = build_reference_index(config)
    references.memberships = build_memberships(config, references)
    policy_structure = build_policy_structure(config, references, policy_context)
    interface_topology = build_interface_topology(config, references)
    identity = build_identity_relationships(config, references)
    vpn_topology = build_vpn_topology(config, references, interface_topology)
    broken = (*collect_broken_references(config, references), *policy_structure.issues,
              *interface_topology.issues, *identity.issues, *vpn_topology.issues)
    unique_broken = []
    for issue in broken:
        if issue not in unique_broken:
            unique_broken.append(issue)
    broken_references = tuple(unique_broken)

    nat = transform_nat(config, references)
    policy_traversal = build_policy_traversal(policy_structure)
    interface_views = transform_interfaces(config, interface_topology)
    vpn_views = transform_vpn(vpn_topology, references)
    nat_completeness = _derived_completeness(collection, {
        "show-nat-rulebase",
        "show-hosts", "show-networks", "show-address-ranges",
        "show-groups", "show-groups-with-exclusion",
        "show-services-tcp", "show-services-udp", "show-services-sctp",
        "show-services-icmp", "show-services-icmp6", "show-services-other",
        "show-services-citrix-tcp", "show-services-dce-rpc", "show-services-rpc",
        "show-services-gtp", "show-services-compound-tcp", "show-service-groups",
        "show-gateways-and-servers", "show-simple-gateways", "show-simple-clusters",
    }, source_plane="management")
    policy_completeness = _derived_completeness(collection, {
        "show-packages", "show-access-layers", "show-access-rulebase",
    }, source_plane="management")
    interface_completeness = _derived_completeness(collection, {
        "show-gateways-and-servers", "show-simple-gateways", "show-simple-clusters",
        "show-interoperable-devices", "show-security-zones", "gaia/show-configuration",
    }, source_plane="management")
    vpn_completeness = _derived_completeness(collection, {
        "show-vpn-communities-star", "show-vpn-communities-meshed",
        "show-vpn-communities-remote-access",
        "show-gateways-and-servers", "show-simple-gateways",
        "show-simple-clusters", "show-interoperable-devices",
        "gaia/show-configuration", "gaia/show-vpn-tunnels",
    }, source_plane="management")
    return CheckPointDerivedViews(
        references=references,
        broken_references=broken_references,
        policy_structure=policy_structure,
        interface_topology=interface_topology,
        vpn_topology=vpn_topology,
        identity=identity,
        nat=nat,
        policy_traversal=policy_traversal,
        interface_views=interface_views,
        vpn_views=vpn_views,
        nat_completeness=nat_completeness,
        policy_completeness=policy_completeness,
        interface_completeness=interface_completeness,
        vpn_completeness=vpn_completeness,
        collection_incomplete=tuple(item for item in collection if not item.complete),
    )


def _derived_completeness(
    collection: tuple[CheckPointCollectionDiagnostic, ...],
    dependencies: set[str],
    *, source_plane: str | None = None,
) -> DerivedSourceCompleteness:
    """Use both failed and absent required operations as incomplete evidence."""
    relevant = tuple(item for item in collection if item.command in dependencies
                     and (source_plane is None or item.source_plane == source_plane or item.command.startswith("gaia/")))
    incomplete = tuple(sorted({
        item.command
        for item in relevant
        if not item.complete or item.status.value not in {"SUCCESS_WITH_DATA", "SUCCESS_EMPTY", "OK"}
    }))
    present = {item.command for item in relevant}
    attempted_plane = {item.source_plane for item in collection}
    # A diagnostic stream reports work the collector attempted; absence from a
    # scope-specific manifest is unknown unless that source plane was requested.
    management_manifest = bool(attempted_plane & {"management", "management-api"})
    gaia_manifest = "gaia" in attempted_plane
    missing = set()
    if source_plane in (None, "management") and management_manifest and len(attempted_plane) > 1:
        missing.update(item for item in dependencies if not item.startswith("gaia/") and item not in present)
    if any(item.startswith("gaia/") for item in dependencies) and gaia_manifest and len(attempted_plane) > 1:
        missing.update(item for item in dependencies if item.startswith("gaia/") and item not in present)
    incomplete = tuple(sorted(set(incomplete) | missing))
    unknown = not collection or any(item.status.value == "UNKNOWN" for item in collection)
    if not unknown and relevant and not incomplete:
        unknown = False
    return DerivedSourceCompleteness(not incomplete and not unknown, incomplete, unknown)


__all__ = [
    "CheckPointDerivedViews",
    "DerivedSourceCompleteness",
    "build_checkpoint_derived_views",
]
