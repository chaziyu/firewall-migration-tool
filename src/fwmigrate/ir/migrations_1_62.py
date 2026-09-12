from __future__ import annotations

from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_61_to_1_62(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.61":
        return dict(payload)
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
