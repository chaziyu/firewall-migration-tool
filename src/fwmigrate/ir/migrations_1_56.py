from __future__ import annotations

from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_55_to_1_56(payload: dict[str, Any]) -> dict[str, Any]:
    """Promote 1.55 payloads after additive IP-pool provenance fields."""
    if payload.get("schema_version") != "1.55":
        return dict(payload)
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
