from __future__ import annotations

from fwmigrate.conversion.fortigate_to_palo_alto.recommendations.recommendations import (
    PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod,
    PANRecommendationReadiness, candidate_names, decision_key_if_present, decision_value,
    recommendation_key, scoped_target_candidates, source_facts,
)


def build_sdwan_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    for sdwan in getattr(source, "sdwans", ()):
        vdom = sdwan.vdom or "root"
        settings = source_facts(sdwan, ("status", "load_balance_mode"))
        if sdwan.raw_extra:
            settings += (f"additional preserved settings = {len(sdwan.raw_extra)}",)
        if settings:
            result.append(PANMigrationRecommendation(
                key=recommendation_key(vdom, "sdwan_settings", "sdwan", "PAN_SDWAN_DESIGN"),
                family="SD-WAN", source_vdom=vdom, source_kind="sdwan_settings", source_name="sdwan",
                target_object_type="PAN_SDWAN_DESIGN", title="SD-WAN settings",
                summary="Review explicitly configured SD-WAN status, load balancing and preserved settings; no equivalent target settings are emitted.",
                method=PANRecommendationMethod.DETERMINISTIC, confidence=PANRecommendationConfidence.LOW,
                evidence=settings, blockers=("Target SD-WAN settings require manual design",)))
        for zone in sdwan.zones:
            evidence = source_facts(zone, ("minimum_sla_meet_members",))
            if zone.raw_extra:
                evidence += (f"additional preserved settings = {len(zone.raw_extra)}",)
            result.append(PANMigrationRecommendation(
                key=recommendation_key(vdom, "sdwan_zone", zone.name, "PAN_SDWAN_DESIGN"),
                family="SD-WAN", source_vdom=vdom, source_kind="sdwan_zone", source_name=zone.name,
                target_object_type="PAN_SDWAN_DESIGN", title=f"SD-WAN zone {zone.name}",
                summary="Preserve the SD-WAN zone and its explicit SLA settings for manual target design; an SD-WAN zone is not automatically a PAN-OS security zone.",
                method=PANRecommendationMethod.DETERMINISTIC, confidence=PANRecommendationConfidence.LOW,
                evidence=evidence, blockers=("Target SD-WAN zone semantics require manual design",)))
        for member in sdwan.members:
            name = str(member.seq_num if member.seq_num is not None else member.interface or "member")
            key = decision_key_if_present(decisions, vdom, "interface", member.interface, "target_interface") if member.interface else None
            mapped_interface = decision_value(decisions, key)
            blockers = ("Target interface mapping required",) if member.interface and not mapped_interface else ()
            candidates = scoped_target_candidates(target, "sdwan_interface_profiles", "sdwan-interface-profile", name, vdom, decisions, target_device)
            result.append(PANMigrationRecommendation(
                recommendation_key(vdom, "sdwan_member", name, "PAN_SDWAN_INTERFACE_PROFILE"), "SD-WAN", vdom, "sdwan_member", name,
                "PAN_SDWAN_INTERFACE_PROFILE", f"SD-WAN member {name}", "Bind the source member to a PAN-OS SD-WAN interface profile after confirming the target interface.",
                PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC, PANRecommendationConfidence.MEDIUM,
                source_facts(member, ("interface", "zone", "gateway", "source", "priority", "cost", "weight", "status")),
                candidate_names(candidates), (key,) if key else (), blockers, (),
                PANRecommendationReadiness.REQUIRES_DECISION if blockers else
                PANRecommendationReadiness.INCOMPLETE_EVIDENCE if not member.interface else PANRecommendationReadiness.SUGGEST,
                target_candidates=candidates))
        for health in sdwan.health_checks:
            candidates = scoped_target_candidates(target, "sdwan_path_quality_profiles", "sdwan-path-quality-profile", health.name, vdom, decisions, target_device)
            result.append(PANMigrationRecommendation(
                recommendation_key(vdom, "sdwan_health_check", health.name, "PAN_SDWAN_PATH_QUALITY"), "SD-WAN", vdom, "sdwan_health_check", health.name,
                "PAN_SDWAN_PATH_QUALITY", f"SD-WAN health check {health.name}", "Design a PAN-OS path-quality profile; FortiGate server/protocol timers are not silently converted to latency, loss, or jitter thresholds.",
                PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC, PANRecommendationConfidence.LOW,
                source_facts(health, ("protocol", "server", "members", "interval", "failtime", "recoverytime")),
                candidate_names(candidates), (), ("Target path-quality design required",), (), target_candidates=candidates))
        for service in sdwan.services:
            name = str(service.id if service.id is not None else service.name or "service")
            candidates = scoped_target_candidates(target, "sdwan_rules", "sdwan-rule", name, vdom, decisions, target_device)
            result.append(PANMigrationRecommendation(
                recommendation_key(vdom, "sdwan_service", name, "PAN_SDWAN_RULE"), "SD-WAN", vdom, "sdwan_service", name,
                "PAN_SDWAN_RULE", f"SD-WAN service {name}", "Preserve source match criteria and references while designing a PAN-OS SD-WAN rulebase object.",
                PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC, PANRecommendationConfidence.LOW,
                source_facts(service, ("name", "mode", "status", "src", "dst", "priority_members", "priority_zone", "health_check")),
                candidate_names(candidates), (), ("Target SD-WAN rulebase design required",), (), target_candidates=candidates))
    return tuple(result)
