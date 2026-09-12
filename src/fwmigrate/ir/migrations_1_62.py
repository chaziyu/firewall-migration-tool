from __future__ import annotations

from typing import Any

def migrate_1_61_to_1_62(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "1.61":
        return dict(payload)
    migrated = dict(payload)
    migrated["schema_version"] = "1.62"
    return migrated
