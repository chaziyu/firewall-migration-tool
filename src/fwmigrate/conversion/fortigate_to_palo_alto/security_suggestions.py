from __future__ import annotations

from .recommendations import PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod, recommendation_key, source_facts, target_names


def build_security_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    target_profiles = target_names(target, "vulnerability_profiles", target_device)
    for sensor in getattr(source, "ips_sensors", ()):
        entries = tuple(sensor.entries)
        blockers = ("FortiGate CVE/signature filters require manual PAN-OS threat review",) if any(entry.cve or entry.rule or entry.vuln_type for entry in entries) else ()
        evidence = source_facts(sensor, ("comment", "block_malicious_url", "scan_botnet_connections", "extended_log"))
        evidence += tuple(f"entries configured = {len(entries)}",) if entries else ()
        evidence += tuple(f"configured actions = {', '.join(sorted({entry.action for entry in entries if entry.action}))}",) if any(entry.action for entry in entries) else ()
        result.append(PANMigrationRecommendation(
            recommendation_key(sensor.vdom or "root", "ips_sensor", sensor.name, "PAN_VULNERABILITY_PROFILE"), "Security", sensor.vdom or "root", "ips_sensor", sensor.name,
            "PAN_VULNERABILITY_PROFILE", f"IPS sensor {sensor.name}", "Use a PAN-OS vulnerability protection profile as the closest documented equivalent.",
            PANRecommendationMethod.TARGET_EVIDENCE if sensor.name in target_profiles else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.MEDIUM, evidence, target_profiles, (), blockers, ()))
    profile_targets = target_names(target, "security_profile_groups", target_device)
    for group in getattr(source, "profile_groups", ()):
        refs = tuple(field for field in ("av_profile", "webfilter_profile", "dnsfilter_profile", "ssl_ssh_profile", "casb_profile", "dlp_profile") if getattr(group, field, None))
        result.append(PANMigrationRecommendation(
            recommendation_key(group.vdom or "root", "profile_group", group.name, "PAN_SECURITY_PROFILE_GROUP"), "Security", group.vdom or "root", "profile_group", group.name,
            "PAN_SECURITY_PROFILE_GROUP", f"Security profile group {group.name}", "Create a PAN-OS security profile group only for target profiles with documented equivalents.",
            PANRecommendationMethod.TARGET_EVIDENCE if group.name in profile_targets else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.MEDIUM, source_facts(group, ("application_list", "ips_sensor", "av_profile", "webfilter_profile", "dnsfilter_profile")),
            profile_targets, (), ("Profile families without a verified PAN-OS equivalent require manual review",) if refs else (), ()))
    return tuple(result)
