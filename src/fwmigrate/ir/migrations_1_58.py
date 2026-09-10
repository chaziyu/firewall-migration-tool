from __future__ import annotations

from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_57_to_1_58(payload: dict[str, Any]) -> dict[str, Any]:
    """Migrate payloads after adding effective PBR match fields."""
    if payload.get("schema_version") != "1.57":
        return dict(payload)
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
