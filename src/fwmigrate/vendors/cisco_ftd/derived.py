"""FTD relationships and read-only views over vendor source state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import CiscoFTDConfig


@dataclass(frozen=True)
class FTDReferenceIssue:
    owner: str
    field: str
    reference: str
    source_plane: str


@dataclass(frozen=True)
class FTDDerivedViews:
    object_index: dict[str, Any] = field(default_factory=dict)
    zone_interfaces: dict[str, tuple[str, ...]] = field(default_factory=dict)
    acp_relationships: tuple[dict[str, Any], ...] = ()
    nat_relationships: tuple[dict[str, Any], ...] = ()
    unresolved_references: tuple[FTDReferenceIssue, ...] = ()
    source_plane_completeness: dict[str, str] = field(default_factory=dict)


def build_ftd_derived_views(config: CiscoFTDConfig) -> FTDDerivedViews:
    index = {}
    for collection in (config.managed_objects, config.object_groups, config.services,
                       config.security_zones, config.source_interfaces):
        for item in collection:
            index[item.name] = item
            if item.source_id:
                index[item.source_id] = item

    issues: list[FTDReferenceIssue] = []

    def check(owner: str, field: str, values: list[str]) -> None:
        for value in values:
            if value and value not in index and value.lower() not in {"any", "any-ip", "any4", "any6"}:
                issues.append(FTDReferenceIssue(owner, field, value, config.source_plane))

    memberships = {}
    for group in config.object_groups:
        memberships[group.name] = tuple(group.members)
        check(group.name, "members", group.members)
    for rule in config.acp_rules:
        check(rule.name, "source", rule.source)
        check(rule.name, "destination", rule.destination)
        check(rule.name, "services", rule.services)
    for rule in config.nat_policies:
        refs = []
        for value in (*rule.original.values(), *rule.translated.values()):
            if isinstance(value, dict):
                refs.extend(str(value[key]) for key in ("id", "name") if value.get(key))
            elif value and str(value).lower() not in {"host", "network", "securityzone", "security-zone", "any"}:
                refs.append(str(value))
        check(rule.name, "nat", refs)

    zone_interfaces = {
        zone.name: tuple(zone.interfaces)
        for zone in config.security_zones
    }
    for zone, interfaces in zone_interfaces.items():
        for interface in interfaces:
            if interface not in index:
                issues.append(FTDReferenceIssue(zone, "interfaces", interface, config.source_plane))

    expected = {
        "managed_objects": "present" if config.managed_objects or config.object_groups or config.services else "not_available",
        "security_zones": "present" if config.security_zones else "not_available",
        "interfaces": "present" if config.source_interfaces or config.interfaces else "not_available",
        "acp": "present" if config.acp_rules else "not_available_from_source_plane",
        "nat": "present" if config.nat_policies else "not_available_from_source_plane",
    }
    return FTDDerivedViews(
        object_index=index,
        zone_interfaces=zone_interfaces,
        acp_relationships=tuple({"policy": item.policy, "rule": item.name,
                                 "source": item.source, "destination": item.destination}
                                for item in config.acp_rules),
        nat_relationships=tuple({"policy": item.policy, "rule": item.name,
                                 "original": item.original, "translated": item.translated}
                                for item in config.nat_policies),
        unresolved_references=tuple(issues),
        source_plane_completeness=expected,
    )


__all__ = ["FTDDerivedViews", "FTDReferenceIssue", "build_ftd_derived_views"]
