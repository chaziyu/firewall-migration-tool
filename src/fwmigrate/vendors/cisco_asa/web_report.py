"""Cisco ASA source preview serialization."""

from __future__ import annotations

from typing import Any

from .source_report import ASASourceResult


def build_asa_preview(result: ASASourceResult) -> dict[str, Any]:
    config = result.config
    return {
        "vendor": "cisco_asa",
        "hostname": config.hostname,
        "summary": {
            "interfaces": len(config.interfaces),
            "network_objects": len(config.network_objects),
            "network_groups": len(config.network_groups),
            "access_rules": len(config.access_rules),
            "nat_rules": len(config.nat_rules),
            "routes": len(config.static_routes),
            "contexts": len(config.contexts),
        },
        "source_sections": [item.model_dump() for item in result.source_sections],
        "inventory": [item.model_dump() for item in result.inventory_items],
        "unsupported": [item.model_dump() for item in result.unsupported_items],
        "validation": [issue.__dict__ for issue in result.validation.issues],
        "relationships": {
            "object_groups": result.derived.object_group_memberships,
            "interface_nameifs": result.derived.interface_nameifs,
            "acl_bindings": {key: [item.model_dump() for item in value] for key, value in result.derived.acl_bindings.items()},
        },
    }


__all__ = ["build_asa_preview"]

