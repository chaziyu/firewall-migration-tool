"""Cisco ASA relationships and read-only derived views."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .reference_validation import (
    ReferenceIssue,
    build_reference_indexes,
    derive_group_address_families,
    validate_references,
)


def _context(item: Any) -> str | None:
    return getattr(item, "source_context", None) or getattr(item, "source_attributes", {}).get("source_context")


@dataclass(frozen=True)
class ASADerivedViews:
    reference_indexes: dict[str, dict[str, Any]] = field(default_factory=dict)
    group_address_families: dict[str, str | None] = field(default_factory=dict)
    object_group_memberships: dict[str, tuple[str, ...]] = field(default_factory=dict)
    interface_nameifs: dict[str, str] = field(default_factory=dict)
    acl_bindings: dict[str, tuple[Any, ...]] = field(default_factory=dict)
    acl_rules: dict[str, tuple[Any, ...]] = field(default_factory=dict)
    nat_rules: tuple[Any, ...] = ()
    route_interfaces: tuple[str | None, ...] = ()
    vpn_relationships: tuple[dict[str, Any], ...] = ()
    reference_issues: tuple[ReferenceIssue, ...] = ()


def build_asa_derived_views(config: Any) -> ASADerivedViews:
    """Build relationships without changing the authoritative source model."""
    contexts = {None}
    for collection in (config.interfaces, config.network_objects, config.network_groups,
                       config.service_objects, config.service_groups, config.access_rules,
                       config.acl_bindings, config.nat_rules, config.static_routes,
                       config.crypto_maps):
        contexts.update(_context(item) for item in collection)

    indexes: dict[str, dict[str, Any]] = {}
    group_address_families: dict[str, str | None] = {}
    for context in sorted(contexts, key=lambda value: value or ""):
        key = context or "__global__"
        indexes[key] = build_reference_indexes(config, context)
        group_address_families.update({
            f"{key}:{name}": family
            for name, family in derive_group_address_families(indexes[key]).items()
        })

    memberships = {
        f"{_context(group) or '__global__'}:{group.name}": tuple(
            entry.get("value", "") if isinstance(entry, dict) else getattr(entry, "value", "")
            for entry in (group.member_entries or group.members)
        )
        for group in config.network_groups
    }
    bindings: dict[str, list[Any]] = {}
    for binding in config.acl_bindings:
        bindings.setdefault(binding.acl_name, []).append(binding)
    rules: dict[str, list[Any]] = {}
    for rule in config.access_rules:
        rules.setdefault(rule.acl_name, []).append(rule)

    vpn_relationships = tuple({
        "crypto_map": item.name,
        "sequence": item.sequence,
        "tunnel_group": getattr(item, "tunnel_group", None),
        "access_list": getattr(item, "access_list", None),
        "source_context": _context(item),
    } for item in config.crypto_maps)

    issues = tuple(validate_references(config))
    return ASADerivedViews(
        reference_indexes=indexes,
        group_address_families=group_address_families,
        object_group_memberships=memberships,
        interface_nameifs={item.name: item.nameif for item in config.interfaces if item.nameif},
        acl_bindings={name: tuple(items) for name, items in bindings.items()},
        acl_rules={name: tuple(items) for name, items in rules.items()},
        nat_rules=tuple(config.nat_rules),
        route_interfaces=tuple(item.interface for item in config.static_routes),
        vpn_relationships=vpn_relationships,
        reference_issues=issues,
    )


__all__ = ["ASADerivedViews", "build_asa_derived_views"]

