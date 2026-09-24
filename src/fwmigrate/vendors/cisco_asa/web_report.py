"""Cisco ASA source preview serialization."""

from __future__ import annotations

from typing import Any

from .source_report import ASASourceResult


def _name(value: Any) -> Any:
    return getattr(value, "name", value)


def build_asa_preview(result: ASASourceResult) -> dict[str, Any]:
    config, derived = result.config, result.derived
    return {
        "vendor": "cisco_asa", "hostname": config.hostname,
        "summary": {"interfaces": len(config.interfaces), "network_objects": len(config.network_objects),
                    "network_groups": len(config.network_groups), "access_rules": len(config.access_rules),
                    "nat_rules": len(config.nat_rules), "routes": len(config.static_routes), "contexts": len(config.contexts)},
        "source_sections": [item.model_dump() for item in result.source_sections],
        "inventory": [item.model_dump() for item in result.inventory_items],
        "unsupported": [item.model_dump() for item in result.unsupported_items],
        "validation": [issue.__dict__ for issue in result.validation.issues],
        "relationships": {
            "object_groups": derived.object_group_memberships,
            "interface_topology": [
                {"name": item.name, "nameif": item.nameif, "kind": item.kind,
                 "parent": _name(item.parent), "aggregate": _name(item.aggregate),
                 "physical_interfaces": [_name(value) for value in item.physical_interfaces],
                 "issues": item.issues}
                for item in derived.interface_topology.interfaces
            ],
            "acl_bindings": [
                {"acl_name": item.acl_name, "scope": item.scope, "direction": item.direction,
                 "interface": item.interface, "rules": [rule.source_order for rule in item.rules],
                 "issues": [issue.reason for issue in item.issues]}
                for item in derived.acl_relationships.bindings
            ],
            "nat": [{"source_context": row.source_context, "source_rule": row.rule.name,
                     "owning_object": _name(row.owning_object), "source_interface": _name(row.source_interface),
                     "destination_interface": _name(row.destination_interface), "issues": row.issues}
                    for row in derived.nat_relationships.rules],
            "vpn": [{"source_context": row.source.source_context, "source": row.source.name,
                     "targets": {key: _name(value) for key, value in row.targets},
                     "source_only": row.source_only, "issues": [issue.reason for issue in row.issues]}
                    for row in derived.vpn_relationships.relationships],
        },
        "derived": {
            "nat": [{"source_context": row.source_context, "source_rule": row.source_rule.name,
                     "source_order": row.source_order, "effective_order": row.effective_order,
                     "ordering_status": row.ordering_status, "section": row.section,
                     "translation_semantics": row.translation_semantics, "issues": row.issues}
                    for row in derived.nat.rules],
            "vpn": [{"source_context": row.source_context, "type": row.topology_type,
                     "source": row.source_identity.name, "crypto_map": row.crypto_map,
                     "sequence": row.crypto_map_sequence, "crypto_acl": _name(row.crypto_acl),
                     "peers": row.peers, "tunnel_groups": [_name(v) for v in row.tunnel_groups],
                     "interface": _name(row.interface), "transform_sets": [_name(v) for v in row.transform_sets],
                     "ikev2_proposals": [_name(v) for v in row.ikev2_proposals],
                     "tunnel_interface": row.tunnel_interface, "tunnel_source": row.tunnel_source,
                     "tunnel_destination": row.tunnel_destination, "ipsec_profile": row.ipsec_profile,
                     "resolution_status": row.resolution_status, "group_policy": _name(row.group_policy),
                     "address_pools": [_name(v) for v in row.address_pools], "trustpoint": _name(row.trustpoint),
                     "issues": row.issues} for row in derived.vpn.topologies],
            "routes": [{"source_context": row.source_context, "destination": row.configured_destination,
                        "mask": row.configured_mask, "normalized_destination": row.normalized_destination,
                        "interface": row.interface, "gateway": row.gateway,
                        "configured_administrative_distance": row.configured_administrative_distance,
                        "effective_administrative_distance": row.effective_administrative_distance,
                        "track_id": row.track_id, "issues": row.issues} for row in derived.routes.routes],
        },
    }


__all__ = ["build_asa_preview"]
