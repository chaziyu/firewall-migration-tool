from __future__ import annotations

from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_52_to_1_53(payload: dict[str, Any]) -> dict[str, Any]:
    """Promote 1.52 payloads after additive TLS reference fields."""
    if payload.get("schema_version") != "1.52":
        return dict(payload)
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
