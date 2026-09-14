from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_66_to_1_67(payload: dict[str, Any]) -> dict[str, Any]:
    """Add optional typed NAT fidelity fields."""
    if payload.get("schema_version") != "1.66":
        return dict(payload)

    migrated = dict(payload)
    for rule in migrated.get("nat_rules", []):
        if not isinstance(rule, dict):
            continue
        rule.setdefault("service_matches", [])
        rule.setdefault("destination_translation_distribution", None)
        rule.setdefault("destination_dns_rewrite", None)
        rule.setdefault("source_device_binding", None)
    for policy in migrated.get("policies", []):
        if not isinstance(policy, dict):
            continue
        for field in (
            "source_policy_expiry", "source_effective_policy_expiry", "source_policy_expiry_date",
            "source_policy_expiry_date_utc", "source_schedule_timeout", "source_effective_schedule_timeout",
            "source_reputation_direction", "source_effective_reputation_direction",
            "source_reputation_direction6", "source_effective_reputation_direction6",
            "source_reputation_minimum", "source_effective_reputation_minimum", "source_reputation_minimum6",
            "source_effective_reputation_minimum6", "source_match_vip", "source_effective_match_vip",
            "source_match_vip_only", "source_effective_match_vip_only",
        ):
            policy.setdefault(field, None)
        policy.setdefault("source_extra_setting_commands", [])
    for rule in migrated.get("nat_rules", []):
        if not isinstance(rule, dict):
            continue
        rule.setdefault("source_policy_effective_match_vip", None)
        rule.setdefault("source_policy_effective_match_vip_only", None)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
