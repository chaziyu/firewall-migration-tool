from typing import Any

from fwmigrate.ir.version import IR_SCHEMA_VERSION


def migrate_1_63_to_1_64(payload: dict[str, Any]) -> dict[str, Any]:
    """Add the lossless IRRoute next-hop collection."""
    if payload.get("schema_version") != "1.63":
        return dict(payload)
    migrated = dict(payload)
    for route in migrated.get("routes", []):
        if isinstance(route, dict):
            next_hop = route.get("next_hop")
            route.setdefault("next_hops", [next_hop] if next_hop else [])
    migrated["schema_version"] = IR_SCHEMA_VERSION
    return migrated
