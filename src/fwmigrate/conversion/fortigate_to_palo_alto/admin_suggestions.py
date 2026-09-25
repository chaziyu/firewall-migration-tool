from __future__ import annotations

from .recommendations import PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod, recommendation_key, source_facts, target_names


def build_admin_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    roles = {item.name: item for item in getattr(source, "admin_profiles", ())}
    for admin in getattr(source, "administrators", ()):
        blockers = ["Manual credential required; password material is never suggested"] if admin.password_configured else []
        if admin.accprofile:
            blockers.append("FortiGate granular permissions require manual PAN-OS role review")
        vdom = "root"
        candidates = target_names(target, "administrators", target_device)
        result.append(PANMigrationRecommendation(
            recommendation_key(vdom, "administrator", admin.name, "PAN_ADMINISTRATOR"), "Users/Admin", vdom, "administrator", admin.name,
            "PAN_ADMINISTRATOR", f"Administrator {admin.name}", "Create the administrator object and review its target authentication and role settings.",
            PANRecommendationMethod.TARGET_EVIDENCE if admin.name in candidates else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.MEDIUM, source_facts(admin, ("accprofile", "remote_auth", "remote_group", "two_factor", "schedule")) + (("password configured = Yes",) if admin.password_configured else ()),
            candidates, (), tuple(blockers), ()))
    for profile in roles.values():
        result.append(PANMigrationRecommendation(
            recommendation_key("root", "admin_profile", profile.name, "PAN_ADMIN_ROLE"), "Users/Admin", "root", "admin_profile", profile.name,
            "PAN_ADMIN_ROLE", f"Administrator role {profile.name}", "Create or select a PAN-OS custom admin role after reviewing the permission hierarchy.",
            PANRecommendationMethod.TARGET_EVIDENCE if profile.name in target_names(target, "admin_roles", target_device) else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.LOW, source_facts(profile, ("scope", "cli_config", "cli_diagnose", "cli_exec", "cli_get", "cli_show")),
            target_names(target, "admin_roles", target_device), (), ("Granular FortiGate permissions require manual target review",), ()))
    return tuple(result)
