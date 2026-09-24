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
            "network_groups": len(config.network_groups),
            "protocol_port_objects": len(config.protocol_port_objects),
            "port_object_groups": len(config.port_object_groups),
            "applications": len(config.applications),
            "security_zones": len(config.security_zones),
            "interfaces": len(config.device_interfaces) + len(config.source_interfaces) + len(config.interfaces),
            "routes": len(config.routes) + len(config.static_routes),
            "access_control_policies": len(config.access_control_policies),
            "acp_rules": count_acp_rules(config),
            "nat_policies": len(config.nat_policies),
            "nat_rules": count_nat_rules(config),
            "time_ranges": len(config.time_ranges), "intrusion_policies": len(config.intrusion_policies),
            "file_policies": len(config.file_policies), "decryption_policies": len(config.decryption_policies),
            "dns_policies": len(config.dns_policies), "fmc_users": len(config.fmc_users),
            "realms": len(config.realms), "realm_users": len(config.realm_users),
            "s2s_vpn_topologies": len(config.s2s_vpn_topologies), "ra_vpn_policies": len(config.ra_vpn_policies),
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
        },
        "source_metadata": config.source_metadata,
        "source_plane_completeness": result.derived.source_plane_completeness,
        "interface_topology": [{"name": item.name, "kind": item.kind, "parent": item.parent,
            "aggregate": item.aggregate, "physical_interfaces": item.physical_interfaces}
            for item in result.derived.interface_topology.interfaces],
        "normalized_routes": [item.__dict__ for item in result.derived.normalized_routes],
        "unresolved_references": [item.__dict__ for item in result.derived.unresolved_references],
        "identity_relationships": result.derived.identity_relationships,
        "vpn_relationships": result.derived.vpn_relationships,
        "unsupported": config.unsupported_evidence,
        "validation": [issue.__dict__ for issue in result.validation.issues],
    }


__all__ = ["build_ftd_preview"]
