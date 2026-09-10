from __future__ import annotations

from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_56_to_1_57(payload: dict[str, Any]) -> dict[str, Any]:
    """Migrate payloads after adding the canonical multicast policy collection."""
    if payload.get("schema_version") != "1.56":
        return dict(payload)
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
