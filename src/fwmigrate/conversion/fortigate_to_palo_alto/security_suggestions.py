from __future__ import annotations

from .recommendations import (
    PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod,
    candidate_names, recommendation_key, scoped_target_candidates, source_facts,
)


def build_security_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    for sensor in getattr(source, "ips_sensors", ()):
        vdom = sensor.vdom or "root"
        candidates = scoped_target_candidates(target, "vulnerability_profiles", "vulnerability-profile", sensor.name, vdom, decisions, target_device)
        entries = tuple(sensor.entries)
        blockers = ("FortiGate CVE/signature filters require manual PAN-OS threat review",) if any(entry.cve or entry.rule or entry.vuln_type for entry in entries) else ()
        evidence = source_facts(sensor, ("comment", "block_malicious_url", "scan_botnet_connections", "extended_log"))
        evidence += tuple(f"entries configured = {len(entries)}",) if entries else ()
        evidence += tuple(f"configured actions = {', '.join(sorted({entry.action for entry in entries if entry.action}))}",) if any(entry.action for entry in entries) else ()
        result.append(PANMigrationRecommendation(
            recommendation_key(vdom, "ips_sensor", sensor.name, "PAN_VULNERABILITY_PROFILE"), "Security", vdom, "ips_sensor", sensor.name,
            "PAN_VULNERABILITY_PROFILE", f"IPS sensor {sensor.name}", "Use a PAN-OS vulnerability protection profile as the closest documented equivalent.",
            PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.MEDIUM, evidence, candidate_names(candidates), (), blockers, (), target_candidates=candidates))
    for group in getattr(source, "profile_groups", ()):
        vdom = group.vdom or "root"
        candidates = scoped_target_candidates(target, "security_profile_groups", "security-profile-group", group.name, vdom, decisions, target_device)
        refs = tuple(field for field in ("av_profile", "webfilter_profile", "dnsfilter_profile", "ssl_ssh_profile", "casb_profile", "dlp_profile") if getattr(group, field, None))
        result.append(PANMigrationRecommendation(
            recommendation_key(vdom, "profile_group", group.name, "PAN_SECURITY_PROFILE_GROUP"), "Security", vdom, "profile_group", group.name,
            "PAN_SECURITY_PROFILE_GROUP", f"Security profile group {group.name}", "Create a PAN-OS security profile group only for target profiles with documented equivalents.",
            PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.MEDIUM, source_facts(group, ("application_list", "ips_sensor", "av_profile", "webfilter_profile", "dnsfilter_profile")),
            candidate_names(candidates), (), ("Profile families without a verified PAN-OS equivalent require manual review",) if refs else (), (),
            target_candidates=candidates))
    return tuple(result)
