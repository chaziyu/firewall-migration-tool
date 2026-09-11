from __future__ import annotations

from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_60_to_1_61(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.60":
        return dict(payload)

    migrated = dict(payload)
    zones = []
    for zone in migrated.get("zones", []):
        if not isinstance(zone, dict):
            zones.append(zone)
            continue
        migrated_zone = dict(zone)
        if (
            migrated_zone.get("zone_type", "system") == "system"
            and migrated_zone.get("source_path") == "system zone"
            and "source_effective_intrazone" not in migrated_zone
        ):
            configured = migrated_zone.get("source_intrazone")
            migrated_zone["source_effective_intrazone"] = (
                configured
                if configured in {"allow", "deny"}
                else "deny" if configured is None else None
            )
        zones.append(migrated_zone)
    if "zones" in migrated:
        migrated["zones"] = zones
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
