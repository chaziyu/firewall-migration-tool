from __future__ import annotations

from .recommendations import (
    PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod,
    candidate_names, recommendation_key, scoped_target_candidates, source_facts,
)


def build_admin_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    roles = {item.name: item for item in getattr(source, "admin_profiles", ())}
    for admin in getattr(source, "administrators", ()):
        blockers = ["Manual credential required; password material is never suggested"] if admin.password_configured else []
        if admin.accprofile:
            blockers.append("FortiGate granular permissions require manual PAN-OS role review")
        vdom = "root"
        candidates = scoped_target_candidates(target, "administrators", "administrator", admin.name, vdom, decisions, target_device)
        result.append(PANMigrationRecommendation(
            recommendation_key(vdom, "administrator", admin.name, "PAN_ADMINISTRATOR"), "Users/Admin", vdom, "administrator", admin.name,
            "PAN_ADMINISTRATOR", f"Administrator {admin.name}", "Create the administrator object and review its target authentication and role settings.",
            PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.MEDIUM, source_facts(admin, ("accprofile", "remote_auth", "remote_group", "two_factor", "schedule")) + (("password configured = Yes",) if admin.password_configured else ()),
            candidate_names(candidates), (), tuple(blockers), (), target_candidates=candidates))
    for profile in roles.values():
        candidates = scoped_target_candidates(target, "admin_roles", "admin-role", profile.name, "root", decisions, target_device)
        result.append(PANMigrationRecommendation(
            recommendation_key("root", "admin_profile", profile.name, "PAN_ADMIN_ROLE"), "Users/Admin", "root", "admin_profile", profile.name,
            "PAN_ADMIN_ROLE", f"Administrator role {profile.name}", "Create or select a PAN-OS custom admin role after reviewing the permission hierarchy.",
            PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.LOW, source_facts(profile, ("scope", "cli_config", "cli_diagnose", "cli_exec", "cli_get", "cli_show")),
            candidate_names(candidates), (), ("Granular FortiGate permissions require manual target review",), (), target_candidates=candidates))
    return tuple(result)
