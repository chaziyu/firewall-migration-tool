from __future__ import annotations

from .recommendations import (
    PANMigrationRecommendation, PANRecommendationConfidence, PANRecommendationMethod,
    candidate_names, recommendation_key, scoped_target_candidates, source_facts,
)


def build_identity_recommendations(source, derived, decisions, target=None, target_device=None):
    result = []
    for user in getattr(source, "local_users", ()):
        blockers = []
        if user.password_configured:
            blockers.append("Manual credential required; password material is never suggested")
        if any(getattr(user, field, None) for field in ("ldap_server", "radius_server", "tacacs_server")):
            blockers.append("Remote authentication requires separate PAN-OS authentication design")
        name, vdom = user.name, user.vdom or "root"
        candidates = scoped_target_candidates(target, "local_users", "local-user", name, vdom, decisions, target_device)
        evidence = source_facts(user, ("status", "type", "two_factor", "ldap_server", "radius_server", "tacacs_server"))
        if user.password_configured:
            evidence += ("password configured = Yes",)
        result.append(PANMigrationRecommendation(
            recommendation_key(vdom, "local_user", name, "PAN_LOCAL_USER"), "Users/Admin", vdom, "local_user", name,
            "PAN_LOCAL_USER", f"Local user {name}", "Create a PAN-OS local-user-database user with the same username.",
            PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC,
            PANRecommendationConfidence.HIGH, evidence, candidate_names(candidates), (), tuple(blockers), (),
            target_candidates=candidates))
    for group in getattr(source, "user_groups", ()):
        blockers = ("Directory-backed group mapping requires separate PAN-OS group-mapping design",) if group.matches else ()
        vdom = group.vdom or "root"
        candidates = scoped_target_candidates(target, "local_user_groups", "local-user-group", group.name, vdom, decisions, target_device)
        result.append(PANMigrationRecommendation(
            recommendation_key(vdom, "user_group", group.name, "PAN_LOCAL_USER_GROUP"), "Users/Admin", vdom, "user_group", group.name,
            "PAN_LOCAL_USER_GROUP", f"User group {group.name}", "Create a PAN-OS local user group only for local FortiGate membership.",
            PANRecommendationMethod.TARGET_EVIDENCE if candidates else PANRecommendationMethod.DETERMINISTIC, PANRecommendationConfidence.MEDIUM,
            source_facts(group, ("group_type", "members")) + ((f"External matches = {len(group.matches)}",) if group.matches else ()),
            candidate_names(candidates), (), blockers, (), target_candidates=candidates))
    return tuple(result)
