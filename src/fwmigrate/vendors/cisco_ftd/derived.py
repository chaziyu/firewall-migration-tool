"""FTD relationships and read-only views over vendor source state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import CiscoFTDConfig


@dataclass(frozen=True)
class FTDReferenceIssue:
    owner: str
    field: str
    reference: str
    source_plane: str


@dataclass(frozen=True)
class FTDDerivedViews:
    object_index: dict[str, Any] = field(default_factory=dict)
    zone_interfaces: dict[str, tuple[str, ...]] = field(default_factory=dict)
    acp_relationships: tuple[dict[str, Any], ...] = ()
    nat_relationships: tuple[dict[str, Any], ...] = ()
    unresolved_references: tuple[FTDReferenceIssue, ...] = ()
    source_plane_completeness: dict[str, str] = field(default_factory=dict)
    identity_relationships: tuple[dict[str, Any], ...] = ()
    vpn_relationships: tuple[dict[str, Any], ...] = ()


def build_ftd_derived_views(config: CiscoFTDConfig) -> FTDDerivedViews:
    index = {}
    source_collections = (config.managed_objects, config.object_groups, config.services,
        config.security_zones, config.source_interfaces, config.acp_policies, config.time_ranges, config.intrusion_policies,
        config.file_policies, config.decryption_policies, config.dns_policies, config.fmc_user_roles,
        config.fmc_users, config.dhcp_servers, config.realms, config.realm_user_groups, config.realm_users,
        config.local_realm_users, config.s2s_vpn_topologies, config.s2s_vpn_endpoints, config.ike_policies,
        config.ipsec_proposals, config.ra_vpn_policies, config.ra_vpn_connection_profiles, config.native_resources)
    for collection in source_collections:
        for item in collection:
            index[item.name] = item
            if item.source_id:
                index[item.source_id] = item

    issues: list[FTDReferenceIssue] = []

    def check(owner: str, field: str, values: list[str]) -> None:
        for value in values:
            if value and value not in index and value.lower() not in {"any", "any-ip", "any4", "any6"}:
                issues.append(FTDReferenceIssue(owner, field, value, config.source_plane))

    memberships = {}
    for group in config.object_groups:
        memberships[group.name] = tuple(group.members)
        check(group.name, "members", group.members)
    for rule in config.acp_rules:
        check(rule.name, "source", rule.source)
        check(rule.name, "destination", rule.destination)
        check(rule.name, "services", rule.services)
    for rule in config.nat_policies:
        refs = []
        for value in (*rule.original.values(), *rule.translated.values()):
            if isinstance(value, dict):
                refs.extend(str(value[key]) for key in ("id", "name") if value.get(key))
            elif value and str(value).lower() not in {"host", "network", "securityzone", "security-zone", "any"}:
                refs.append(str(value))
        check(rule.name, "nat", refs)

    def raw_refs(record, *keys):
        for key in keys:
            value = record.raw.get(key)
            values = value if isinstance(value, list) else [value]
            for item in values:
                ref = item.get("name") or item.get("id") if isinstance(item, dict) else item
                if ref:
                    check(record.name, key, [str(ref)])

    for user in config.fmc_users:
        raw_refs(user, "role", "roles")
    for item in (*config.realm_user_groups, *config.realm_users, *config.local_realm_users):
        raw_refs(item, "realm")
    for rule in config.acp_rules:
        raw_refs(rule, "timeRange", "realmUsers", "realmUserGroups", "applications", "urlCategories", "intrusionPolicy", "filePolicy")
    for route in config.routes:
        raw_refs(route, "network", "gateway", "slaMonitor", "interfaceName")
    for server in config.dhcp_servers:
        raw_refs(server, "interface", "interfaceName", "addressPool")
    for endpoint in config.s2s_vpn_endpoints:
        raw_refs(endpoint, "device", "ikePolicy", "ipsecProposal", "protectedNetworks", "vti")
    for vpn in config.s2s_vpn_topologies:
        raw_refs(vpn, "endpoints", "ikePolicy", "ipsecProposal")
    for vpn in (*config.ra_vpn_policies, *config.ra_vpn_connection_profiles):
        raw_refs(vpn, "realm", "addressPool", "groupPolicy", "certificate", "interface")

    zone_interfaces = {
        zone.name: tuple(zone.interfaces)
        for zone in config.security_zones
    }
    for zone, interfaces in zone_interfaces.items():
        for interface in interfaces:
            if interface not in index:
                issues.append(FTDReferenceIssue(zone, "interfaces", interface, config.source_plane))

    expected = {
        "managed_objects": "present" if config.managed_objects or config.object_groups or config.services else "not_available",
        "security_zones": "present" if config.security_zones else "not_available",
        "interfaces": "present" if config.source_interfaces or config.interfaces else "not_available",
        "acp": "present" if config.acp_rules else "not_available_from_source_plane",
        "nat": "present" if config.nat_policies else "not_available_from_source_plane",
        **{key: "present" if getattr(config, field_name) else "not_available_from_source_plane" for field_name, key in (
            ("time_ranges", "time_ranges"), ("intrusion_policies", "intrusion"), ("file_policies", "file_policy"),
            ("decryption_policies", "decryption"), ("dns_policies", "dns"), ("fmc_users", "administration"),
            ("realms", "identity"), ("routes", "routing"), ("dhcp_servers", "dhcp"),
            ("s2s_vpn_topologies", "s2s_vpn"), ("ra_vpn_policies", "ra_vpn"),
            ("native_resources", "sdwan_related_native_resources"))},
    }
    collection = config.source_metadata.get("collection", {})
    for part in collection.get("parts", []):
        expected[f"collection:{part.get('name', 'unknown')}"] = "present" if part.get("complete") else "incomplete"
    return FTDDerivedViews(
        object_index=index,
        zone_interfaces=zone_interfaces,
        acp_relationships=tuple({"policy": item.policy, "rule": item.name,
                                 "source": item.source, "destination": item.destination}
                                for item in config.acp_rules),
        nat_relationships=tuple({"policy": item.policy, "rule": item.name,
                                 "original": item.original, "translated": item.translated}
                                for item in config.nat_policies),
        unresolved_references=tuple(issues),
        source_plane_completeness=expected,
        identity_relationships=tuple({"user": user.name, "role": user.raw.get("role") or user.raw.get("roles")} for user in config.fmc_users),
        vpn_relationships=tuple({"topology": vpn.name, "endpoints": [x.name for x in config.s2s_vpn_endpoints
            if x.source_attributes.get("parent_topology_id") == vpn.source_id]} for vpn in config.s2s_vpn_topologies),
    )


__all__ = ["FTDDerivedViews", "FTDReferenceIssue", "build_ftd_derived_views"]
