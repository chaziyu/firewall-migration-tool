"""Junos source preview serialization."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes


def _project(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="python")
    elif is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return sanitize_source_attributes({str(key): _project(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return [_project(item) for item in value]
    return value


def build_juniper_preview(result: Any) -> dict[str, Any]:
    config = result.config
    return {
        "vendor": "juniper_srx",
        "hostname": config.hostname,
        "summary": {"contexts": len(config.contexts), "groups": len(config.configuration_groups),
                     "unsupported": len(config.unsupported_commands),
                     "interfaces": len(result.derived.interface_topology),
                     "policies": len(result.derived.policies), "nat_rule_sets": len(result.derived.nat_rule_sets)},
        "source_sections": _project(result.source_sections),
        "inventory": _project(result.inventory_items),
        "unsupported": _project(result.unsupported_items),
        "relationships": _project({"interfaces": result.derived.interface_topology,
                           "zones": result.derived.zone_memberships,
                           "routing_instances": result.derived.routing_instances,
                           "policies": result.derived.policies,
                           "nat": result.derived.nat_rule_sets,
                           "vpn": result.derived.vpn_relationships}),
        "validation": _project(result.validation.issues),
    }


__all__ = ["build_juniper_preview"]
