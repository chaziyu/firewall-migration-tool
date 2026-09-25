from __future__ import annotations

from .recommendations import PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod, recommendation_key, source_facts, target_names


def build_ssl_vpn_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    portals = target_names(target, "globalprotect_portals", target_device)
    gateways = target_names(target, "globalprotect_gateways", target_device)
    for index, settings in enumerate(getattr(source, "ssl_vpn_settings", ())):
        name = f"settings-{settings.vdom or 'root'}-{index}"
        result.append(PANMigrationRecommendation(
            recommendation_key(settings.vdom or "root", "ssl_vpn_settings", name, "PAN_GLOBALPROTECT"), "SSL VPN", settings.vdom or "root", "ssl_vpn_settings", name,
            "PAN_GLOBALPROTECT", "SSL VPN architecture", "Design a GlobalProtect portal and gateway; FortiGate SSL VPN is not a direct object-for-object conversion.",
            PANRecommendationMethod.TARGET_EVIDENCE if portals or gateways else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.LOW, source_facts(settings, ("status", "ssl_min_proto_ver", "ssl_max_proto_ver", "dns_server1", "dns_server2", "default_portal", "port")),
            tuple(dict.fromkeys((*portals, *gateways))), (), ("GlobalProtect portal required", "GlobalProtect gateway required", "Target tunnel interface and zone required", "Authentication and certificate design required"), ()))
    for portal in getattr(source, "ssl_vpn_portals", ()):
        result.append(PANMigrationRecommendation(
            recommendation_key(portal.vdom or "root", "ssl_vpn_portal", portal.name, "PAN_GLOBALPROTECT_PORTAL"), "SSL VPN", portal.vdom or "root", "ssl_vpn_portal", portal.name,
            "PAN_GLOBALPROTECT_PORTAL", f"GlobalProtect portal for {portal.name}", "Reuse a same-name target portal only as evidence; confirm the portal, gateway, tunnel, zone, pool, DNS, and authentication design.",
            PANRecommendationMethod.TARGET_EVIDENCE if portal.name in portals else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.LOW, source_facts(portal, ("tunnel_mode", "ip_pools", "split_tunneling", "split_tunneling_routing_address", "web_mode")),
            portals, (), ("GlobalProtect gateway required", "Target tunnel interface and zone required", "Authentication/user-group design required"), ()))
    return tuple(result)
