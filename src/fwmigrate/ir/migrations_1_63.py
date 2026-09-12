from __future__ import annotations

from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_62_to_1_63(payload: dict[str, Any]) -> dict[str, Any]:
    """Promote 1.62 payloads after additive typed PAN-OS fields."""
    if payload.get("schema_version") != "1.62":
        return dict(payload)
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
