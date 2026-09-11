from __future__ import annotations

from typing import Any

def migrate_1_58_to_1_59(payload: dict[str, Any]) -> dict[str, Any]:
    """Promote payloads after additive PAN-OS fidelity fields."""
    if payload.get("schema_version") != "1.58":
        return dict(payload)
    migrated = dict(payload)
    migrated["schema_version"] = "1.59"
    return migrated
