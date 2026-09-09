from __future__ import annotations

from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_53_to_1_54(payload: dict[str, Any]) -> dict[str, Any]:
    """Promote 1.53 payloads after additive PAN-OS completeness fields."""
    if payload.get("schema_version") != "1.53":
        return dict(payload)
    migrated = dict(payload)
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
