from __future__ import annotations

from .recommendations import (
    PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod,
    PANRecommendationReadiness, decision_key_if_present, decision_value,
    recommendation_key, source_facts, target_names,
)


def build_sdwan_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    for sdwan in getattr(source, "sdwans", ()):
        vdom = sdwan.vdom or "root"
        for member in sdwan.members:
            name = str(member.seq_num if member.seq_num is not None else member.interface or "member")
            key = decision_key_if_present(decisions, vdom, "interface", member.interface, "target_interface") if member.interface else None
            mapped_interface = decision_value(decisions, key)
            blockers = ("Target interface mapping required",) if member.interface and not mapped_interface else ()
            result.append(PANMigrationRecommendation(
                recommendation_key(vdom, "sdwan_member", name, "PAN_SDWAN_INTERFACE_PROFILE"), "SD-WAN", vdom, "sdwan_member", name,
                "PAN_SDWAN_INTERFACE_PROFILE", f"SD-WAN member {name}", "Bind the source member to a PAN-OS SD-WAN interface profile after confirming the target interface.",
                PANRecommendationMethod.DETERMINISTIC, PANRecommendationConfidence.MEDIUM,
                source_facts(member, ("interface", "zone", "gateway", "source", "priority", "cost", "weight", "status")),
                target_names(target, "sdwan_interface_profiles", target_device), (key,) if key else (), blockers, (),
                PANRecommendationReadiness.REQUIRES_DECISION if blockers else
                PANRecommendationReadiness.INCOMPLETE_EVIDENCE if not member.interface else PANRecommendationReadiness.SUGGEST))
        for health in sdwan.health_checks:
            result.append(PANMigrationRecommendation(
                recommendation_key(vdom, "sdwan_health_check", health.name, "PAN_SDWAN_PATH_QUALITY"), "SD-WAN", vdom, "sdwan_health_check", health.name,
                "PAN_SDWAN_PATH_QUALITY", f"SD-WAN health check {health.name}", "Design a PAN-OS path-quality profile; FortiGate server/protocol timers are not silently converted to latency, loss, or jitter thresholds.",
                PANRecommendationMethod.DETERMINISTIC, PANRecommendationConfidence.LOW,
                source_facts(health, ("protocol", "server", "members", "interval", "failtime", "recoverytime")),
                target_names(target, "sdwan_path_quality_profiles", target_device), (), ("Target path-quality design required",), ()))
        for service in sdwan.services:
            name = str(service.id if service.id is not None else service.name or "service")
            result.append(PANMigrationRecommendation(
                recommendation_key(vdom, "sdwan_service", name, "PAN_SDWAN_RULE"), "SD-WAN", vdom, "sdwan_service", name,
                "PAN_SDWAN_RULE", f"SD-WAN service {name}", "Preserve source match criteria and references while designing a PAN-OS SD-WAN rulebase object.",
                PANRecommendationMethod.DETERMINISTIC, PANRecommendationConfidence.LOW,
                source_facts(service, ("name", "mode", "status", "src", "dst", "priority_members", "priority_zone", "health_check")),
                target_names(target, "sdwan_rules", target_device), (), ("Target SD-WAN rulebase design required",), ()))
    return tuple(result)
