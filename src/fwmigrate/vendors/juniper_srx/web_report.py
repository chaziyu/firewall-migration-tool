"""Junos source preview serialization."""

from __future__ import annotations

from typing import Any


def build_juniper_preview(result: Any) -> dict[str, Any]:
    config = result.config
    return {
        "vendor": "juniper_srx",
        "hostname": config.hostname,
        "summary": {"contexts": len(config.contexts), "groups": len(config.configuration_groups),
                     "unsupported": len(config.unsupported_commands),
                     "interfaces": len(result.derived.interface_topology),
                     "policies": len(result.derived.policies), "nat_rule_sets": len(result.derived.nat_rule_sets)},
        "source_sections": result.source_sections,
        "inventory": result.inventory_items,
        "unsupported": result.unsupported_items,
        "relationships": {"interfaces": result.derived.interface_topology,
                           "zones": result.derived.zone_memberships,
                           "routing_instances": result.derived.routing_instances,
                           "policies": result.derived.policies,
                           "nat": result.derived.nat_rule_sets,
                           "vpn": result.derived.vpn_relationships},
        "validation": [issue.__dict__ for issue in result.validation.issues],
    }


__all__ = ["build_juniper_preview"]
