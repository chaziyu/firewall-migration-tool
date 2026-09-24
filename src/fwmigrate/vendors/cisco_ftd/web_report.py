from __future__ import annotations

from typing import Any

from .source_report import FTDSourceResult
from .reporting_counts import count_acp_rules, count_nat_rules


def build_ftd_preview(result: FTDSourceResult) -> dict[str, Any]:
    config = result.config
    return {
        "vendor": "cisco_ftd",
        "input_source_type": config.input_source_type,
        "source_plane": config.source_plane,
        "summary": {
            "network_addresses": len(config.network_addresses),
            "network_address_overrides": len(config.network_address_overrides),
            "network_groups": len(config.network_groups),
            "protocol_port_objects": len(config.protocol_port_objects),
            "port_object_groups": len(config.port_object_groups),
            "applications": len(config.applications),
            "security_zones": len(config.security_zones),
            "interfaces": len(config.device_interfaces) + len(config.source_interfaces) + len(config.interfaces),
            "routes": len(config.routes) + len(config.static_routes),
            "access_control_policies": len(config.access_control_policies),
            "access_control_default_actions": len(config.access_control_default_actions),
            "access_policy_inheritance_settings": len(config.access_policy_inheritance_settings),
            "policy_assignments": len(config.policy_assignments),
            "acp_rules": count_acp_rules(config),
            "nat_policies": len(config.nat_policies),
            "nat_rules": count_nat_rules(config),
            "time_ranges": len(config.time_ranges), "intrusion_policies": len(config.intrusion_policies),
            "intrusion_rule_groups": len(config.intrusion_rule_groups),
            "intrusion_rule_behaviors": len(config.intrusion_rule_behaviors),
            "intrusion_rule_overrides": len(config.intrusion_rule_overrides),
            "file_policies": len(config.file_policies),
            "file_rules": sum(len(item.rules or []) for item in config.file_policies),
            "decryption_policies": len(config.decryption_policies),
            "decryption_rules": sum(len(item.rules or []) for item in config.decryption_policies),
            "dns_policies": len(config.dns_policies),
            "dns_rules": sum(len(item.rules or []) for item in config.dns_policies), "fmc_users": len(config.fmc_users),
            "fmc_user_roles": len(config.fmc_user_roles), "realms": len(config.realms),
            "realm_user_groups": len(config.realm_user_groups), "realm_users": len(config.realm_users),
            "local_realm_users": len(config.local_realm_users),
            "s2s_vpn_topologies": len(config.s2s_vpn_topologies),
            "s2s_vpn_endpoints": len(config.s2s_vpn_endpoints),
            "ikev1_policies": sum(item.ike_version == "IKEv1" for item in config.ike_policies),
            "ikev2_policies": sum(item.ike_version == "IKEv2" for item in config.ike_policies),
            "ikev1_ipsec_proposals": sum(item.ike_version == "IKEv1" for item in config.ipsec_proposals),
            "ikev2_ipsec_proposals": sum(item.ike_version == "IKEv2" for item in config.ipsec_proposals),
            "ra_vpn_policies": len(config.ra_vpn_policies),
            "ra_vpn_connection_profiles": len(config.ra_vpn_connection_profiles),
            "virtual_routers": len(config.virtual_routers), "policy_based_routes": len(config.policy_based_routes),
            "ecmp_zones": len(config.ecmp_zones), "sla_monitors": len(config.sla_monitors),
            "certificates": len(config.certificates), "certificate_maps": len(config.certificate_maps),
            "certificate_enrollments": len(config.certificate_enrollments), "address_pools": len(config.address_pools),
            "group_policies": len(config.group_policies), "s2s_ike_settings": len(config.s2s_ike_settings),
            "s2s_ipsec_settings": len(config.s2s_ipsec_settings), "s2s_advanced_settings": len(config.s2s_advanced_settings),
            "ra_vpn_children": sum(map(len, (config.ra_vpn_ipsec_settings, config.ldap_attribute_maps,
                config.ra_vpn_load_balance_settings, config.ra_vpn_address_assignment_settings,
                config.secure_client_settings, config.ra_vpn_ipsec_crypto_maps))),
            "prefilter_policies": len(config.prefilter_policies), "prefilter_rules": len(config.prefilter_rules),
            "network_analysis_policies": len(config.network_analysis_policies),
            "inspector_configs": len(config.inspector_configs),
            "dhcp_servers": len(config.dhcp_servers), "native_resources": len(config.native_resources),
            "dhcp_relay_settings": len(config.dhcp_relay_settings),
        },
        "source_metadata": config.source_metadata,
        "capability_coverage": config.source_metadata.get("coverage", {}),
        "source_plane_completeness": result.derived.source_plane_completeness,
        "interface_topology": [{"name": item.name, "kind": item.kind, "parent": item.parent,
            "aggregate": item.aggregate, "physical_interfaces": item.physical_interfaces}
            for item in result.derived.interface_topology.interfaces],
        "normalized_routes": [item.__dict__ for item in result.derived.normalized_routes],
        "unresolved_references": [item.__dict__ for item in result.derived.unresolved_references],
        "identity_relationships": result.derived.identity_relationships,
        "vpn_relationships": result.derived.vpn_relationships,
        "ra_vpn_relationships": result.derived.ra_vpn_relationships,
        "ra_vpn": {name: [item.model_dump(exclude_none=True) for item in getattr(config, name)]
            for name in ("ra_vpn_policies", "ra_vpn_connection_profiles", "group_policies",
                         "address_pools", "certificates", "certificate_maps", "secure_client_settings",
                         "ra_vpn_address_assignment_settings", "ra_vpn_ipsec_settings")},
        "inspection_relationships": result.derived.inspection_relationships,
        "policy_relationships": result.derived.policy_relationships,
        "unsupported": config.unsupported_evidence,
        "validation": [issue.__dict__ for issue in result.validation.issues],
    }


__all__ = ["build_ftd_preview"]
