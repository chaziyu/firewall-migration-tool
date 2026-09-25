from __future__ import annotations

from .recommendations import (
    PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod,
    PANRecommendationReadiness, decision_key_if_present, decision_value, recommendation_key,
    candidate_names, scoped_target_candidates, source_facts, unique,
)


def build_ssl_vpn_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    for index, settings in enumerate(getattr(source, "ssl_vpn_settings", ())):
        name = f"settings-{settings.vdom or 'root'}-{index}"
        vdom = settings.vdom or "root"
        candidates = (
            *scoped_target_candidates(target, "globalprotect_portals", "globalprotect-portal", name, vdom, decisions, target_device),
            *scoped_target_candidates(target, "globalprotect_gateways", "globalprotect-gateway", name, vdom, decisions, target_device),
        )
        source_interfaces = unique((
            *settings.source_interface,
            *(interface for rule in settings.authentication_rules for interface in rule.source_interface),
        ))
        decision_keys = []
        blockers = ["GlobalProtect portal required", "GlobalProtect gateway required", "Target tunnel interface and zone required", "Authentication and certificate design required"]
        for interface in source_interfaces:
            decision_key = decision_key_if_present(decisions, vdom, "interface", interface, "target_interface")
            if decision_key:
                decision_keys.append(decision_key)
            if not decision_value(decisions, decision_key):
                blockers.append(f"Target interface mapping required for {interface}")
        evidence = source_facts(settings, ("status", "ssl_min_proto_ver", "ssl_max_proto_ver", "dns_server1", "dns_server2", "default_portal", "port", "source_interface"))
        evidence += tuple(
            f"Authentication rule {rule.id if rule.id is not None else rule_index} source interfaces = {', '.join(rule.source_interface)}"
            for rule_index, rule in enumerate(settings.authentication_rules)
            if rule.source_interface
        )
        result.append(PANMigrationRecommendation(
            recommendation_key(vdom, "ssl_vpn_settings", name, "PAN_GLOBALPROTECT"), "SSL VPN", vdom, "ssl_vpn_settings", name,
            "PAN_GLOBALPROTECT", "SSL VPN architecture", "Design a GlobalProtect portal and gateway; FortiGate SSL VPN is not a direct object-for-object conversion.",
            PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.LOW, evidence,
            candidate_names(candidates), tuple(dict.fromkeys(decision_keys)), tuple(dict.fromkeys(blockers)), (),
            PANRecommendationReadiness.MANUAL_DESIGN, target_candidates=candidates))
    for portal in getattr(source, "ssl_vpn_portals", ()):
        vdom = portal.vdom or "root"
        candidates = scoped_target_candidates(target, "globalprotect_portals", "globalprotect-portal", portal.name, vdom, decisions, target_device)
        result.append(PANMigrationRecommendation(
            recommendation_key(vdom, "ssl_vpn_portal", portal.name, "PAN_GLOBALPROTECT_PORTAL"), "SSL VPN", vdom, "ssl_vpn_portal", portal.name,
            "PAN_GLOBALPROTECT_PORTAL", f"GlobalProtect portal for {portal.name}", "Reuse a same-name target portal only as evidence; confirm the portal, gateway, tunnel, zone, pool, DNS, and authentication design.",
            PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.LOW, source_facts(portal, ("tunnel_mode", "ip_pools", "split_tunneling", "split_tunneling_routing_address", "web_mode")),
            candidate_names(candidates), (), ("GlobalProtect gateway required", "Target tunnel interface and zone required", "Authentication/user-group design required"), (),
            PANRecommendationReadiness.MANUAL_DESIGN, target_candidates=candidates))
    return tuple(result)
