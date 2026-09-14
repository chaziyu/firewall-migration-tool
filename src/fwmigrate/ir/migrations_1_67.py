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
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
