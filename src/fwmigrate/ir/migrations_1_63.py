from __future__ import annotations

from typing import Any

def migrate_1_62_to_1_63(payload: dict[str, Any]) -> dict[str, Any]:
    """Promote 1.62 payloads after additive typed route fields."""
    if payload.get("schema_version") != "1.62":
        return dict(payload)
    migrated = dict(payload)
    for route in migrated.get("routes", []):
        if isinstance(route, dict):
            next_hop = route.get("next_hop")
            route.setdefault("next_hops", [next_hop] if next_hop else [])
    migrated["schema_version"] = "1.63"
    return migrated
