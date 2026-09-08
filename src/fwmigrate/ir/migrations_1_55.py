from __future__ import annotations

from typing import Any


def migrate_1_54_to_1_55(payload: dict[str, Any]) -> dict[str, Any]:
    migrated = dict(payload)
    migrated["schema_version"] = "1.55"
    return migrated
