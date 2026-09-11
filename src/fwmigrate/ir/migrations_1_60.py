from __future__ import annotations

from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_59_to_1_60(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.59":
        return dict(payload)
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
