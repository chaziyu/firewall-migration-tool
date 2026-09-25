from __future__ import annotations

from .recommendations import (
    PANMigrationRecommendation,
    PANRecommendationConfidence,
    PANRecommendationMethod,
    PANRecommendationReadiness,
    decision_key_if_present,
    decision_value,
    candidate_names,
    recommendation_key,
    scoped_target_candidates,
    source_facts,
)


def build_dhcp_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    for index, server in enumerate(getattr(source, "dhcp_servers", ())):
        vdom = server.vdom or "root"
        name = str(server.id if server.id is not None else server.interface or index)
        decision_key = decision_key_if_present(decisions, vdom, "interface", server.interface, "target_interface") if server.interface else None
        mapped = decision_value(decisions, decision_key)
        blockers = []
        if server.interface and not mapped:
            blockers.append("Target interface mapping required")
        if getattr(server, "exclude_ranges", ()):
            blockers.append("FortiGate exclude-range behavior requires manual target review")
        candidates = scoped_target_candidates(target, "dhcp_servers", "dhcp-server", name, vdom, decisions, target_device)
        evidence = source_facts(server, ("interface", "default_gateway", "netmask", "lease_time", "dns_server1", "dns_server2"))
        evidence += tuple(
            f"IP pool = {pool.start_ip}-{pool.end_ip}"
            for pool in server.ip_ranges
            if pool.start_ip or pool.end_ip
        )
        evidence += tuple(
            f"Reservation = {item.ip}"
            for item in server.reserved_addresses
            if item.ip
        )
        result.append(PANMigrationRecommendation(
            key=recommendation_key(vdom, "dhcp_server", name, "PAN_DHCP_SERVER"),
            family="DHCP", source_vdom=vdom, source_kind="dhcp_server", source_name=name,
            target_object_type="PAN_DHCP_SERVER", title=f"DHCP server {name}",
            summary=f"Map the FortiGate interface-scoped DHCP server to PAN-OS network dhcp interface{f' {mapped}' if mapped else ''} server.",
            method=PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC,
            confidence=PANRecommendationConfidence.HIGH if server.interface else PANRecommendationConfidence.MEDIUM,
            evidence=evidence, candidate_target_objects=candidate_names(candidates), target_candidates=candidates,
            required_decision_keys=(decision_key,) if decision_key else (), blockers=tuple(blockers),
            readiness=(
                PANRecommendationReadiness.MANUAL_DESIGN if server.exclude_ranges
                else PANRecommendationReadiness.REQUIRES_DECISION if server.interface and not mapped
                else PANRecommendationReadiness.INCOMPLETE_EVIDENCE if not server.interface
                else PANRecommendationReadiness.SUGGEST
            ),
        ))
    return tuple(result)
