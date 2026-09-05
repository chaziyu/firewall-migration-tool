from __future__ import annotations

from dataclasses import dataclass, asdict
import re
from typing import Any, Dict, Iterable, List, Optional, Set


@dataclass(frozen=True)
class ReferenceIssue:
    reference_type: str
    source_object: str
    reference_name: str
    resolved: bool
    reason: str
    source_context: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _index(items: Iterable[Any]) -> Dict[str, Any]:
    return {item.name: item for item in items if getattr(item, "name", None)}


def build_reference_indexes(config: Any) -> Dict[str, Dict[str, Any]]:
    return {
        "network_object": _index(config.network_objects),
        "network_group": _index(config.network_groups),
        "service_object": _index(config.service_objects),
        "service_group": _index(config.service_groups),
        "protocol_group": _index(config.protocol_groups),
        "icmp_group": _index(config.icmp_type_groups),
        "acl": {name: name for name in {item.acl_name for item in config.access_rules}},
        "time_range": {name: name for name in {item.name for item in config.time_ranges}},
        "route_map": _index(config.route_maps),
        "interface": _index(config.interfaces),
        "nameif": {item.nameif: item for item in config.interfaces if item.nameif},
        "ike_policy": _index(config.ike_policies),
        "crypto_map": _index(config.crypto_maps),
        "tunnel_group": _index(config.tunnel_groups),
        "group_policy": _index(config.group_policies),
        "aaa_server_group": {
            item.name: item for item in config.aaa_records
            if item.source_attributes.get("raw_command", "").lower().startswith("aaa-server ")
        },
    }


def _issue(kind: str, source: str, name: str, indexes: Dict[str, Dict[str, Any]], context: Optional[str] = None) -> ReferenceIssue:
    resolved = name in indexes[kind]
    return ReferenceIssue(
        kind, source, name, resolved,
        "resolved" if resolved else f"Unresolved {kind.replace('_', ' ')} reference",
        context,
    )


def _cycle_issues(kind: str, groups: Iterable[Any], indexes: Dict[str, Dict[str, Any]]) -> List[ReferenceIssue]:
    by_name = _index(groups)
    edges: Dict[str, List[str]] = {}
    for group in groups:
        values = group.members
        if getattr(group, "member_entries", None):
            values = [entry.get("value", "") for entry in group.member_entries]
        edges[group.name] = [value for value in values if value in by_name]

    issues: List[ReferenceIssue] = []
    visiting: List[str] = []
    visited: Set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            cycle = visiting[visiting.index(name):] + [name]
            issues.append(ReferenceIssue(
                kind, name, name, False, f"Cycle detected: {' -> '.join(cycle)}"
            ))
            return
        if name in visited:
            return
        visiting.append(name)
        for child in edges.get(name, []):
            visit(child)
        visiting.pop()
        visited.add(name)

    for name in sorted(edges):
        visit(name)
    return issues


def validate_references(config: Any) -> List[ReferenceIssue]:
    indexes = build_reference_indexes(config)
    issues: List[ReferenceIssue] = []

    def add(kind: str, source: str, name: Optional[str], context: Optional[str] = None) -> None:
        if name and name not in {"any", "any4", "any6"}:
            issues.append(_issue(kind, source, name, indexes, context))

    for group in config.network_groups:
        for entry in group.member_entries:
            kind = {"network_object": "network_object", "network_group": "network_group"}.get(entry.get("type"))
            if kind:
                add(kind, group.name, entry.get("value"))
        if not group.member_entries:
            for name in group.members:
                add("network_group" if name in indexes["network_group"] else "network_object", group.name, name)

    for group in config.service_groups:
        for name in group.members:
            add("service_group" if name in indexes["service_group"] else "service_object", group.name, name)
        for member in group.service_objects:
            for port in (member.destination, member.source):
                add("service_object", group.name, port.object_name if port else None)

    for group, kind in [(config.protocol_groups, "protocol_group"), (config.icmp_type_groups, "icmp_group")]:
        for item in group:
            for name in item.members:
                add(kind, item.name, name)

    for rule in config.access_rules:
        add("time_range", rule.acl_name, rule.time_range)
        add("protocol_group", rule.acl_name, rule.protocol_object)
        add("icmp_group", rule.acl_name, rule.icmp_object_group)
        for endpoint in (rule.source_endpoint, rule.destination_endpoint):
            if endpoint and endpoint.type in {"object", "object-group"}:
                add("network_group" if endpoint.type == "object-group" else "network_object", rule.acl_name, endpoint.value)

    for binding in config.acl_bindings:
        add("acl", "access-group", binding.acl_name)
        add("interface", "access-group", binding.interface)

    for route_map in config.route_maps:
        for rule in route_map.rules:
            add("acl", route_map.name, rule.match_acl)
    for interface in config.interfaces:
        for route_map in interface.policy_route_maps:
            add("route_map", interface.name, route_map)
    for item in config.crypto_maps:
        add("acl", item.name, item.acl_name)
    for item in config.tunnel_groups:
        policy = item.ipsec_attributes.get("default_group_policy")
        if not policy:
            for command in item.ipsec_attributes.get("raw_subcommands", []):
                match = re.match(r"(?:default-)?group-policy\s+(\S+)", command, re.I)
                if match:
                    policy = match.group(1)
                    break
        add("group_policy", item.name, policy)
    for item in config.aaa_records:
        raw = item.source_attributes.get("raw_command", "")
        if raw.lower().startswith("aaa-server "):
            item.source_attributes["aaa_server_group"] = item.name
        else:
            match = re.match(r"aaa\s+(?:authentication|authorization|accounting)\s+\S+\s+(\S+)", raw, re.I)
            add("aaa_server_group", item.name, match.group(1) if match else None)

    issues.extend(_cycle_issues("network_group", config.network_groups, indexes))
    issues.extend(_cycle_issues("service_group", config.service_groups, indexes))
    issues.extend(_cycle_issues("protocol_group", config.protocol_groups, indexes))
    return issues


def apply_reference_issues(config: Any, issues: List[ReferenceIssue]) -> None:
    config.reference_issues = [issue.as_dict() for issue in issues]
    for issue in issues:
        if issue.resolved:
            continue
        for collection in (config.network_groups, config.service_groups, config.protocol_groups,
                           config.icmp_type_groups, config.access_rules, config.acl_bindings,
                           config.route_maps, config.interfaces, config.crypto_maps,
                           config.tunnel_groups, config.aaa_records):
            for item in collection:
                if getattr(item, "name", None) != issue.source_object and getattr(item, "acl_name", None) != issue.source_object:
                    continue
                if hasattr(item, "migration_status"):
                    item.migration_status = "PARTIALLY_NORMALIZED"
                if hasattr(item, "requires_manual_review"):
                    item.requires_manual_review = True
                if hasattr(item, "review_reasons"):
                    reason = f"{issue.reference_type}: {issue.reason} ({issue.reference_name})"
                    if reason not in item.review_reasons:
                        item.review_reasons.append(reason)
                if hasattr(item, "source_attributes"):
                    item.source_attributes.setdefault("reference_issues", []).append(issue.as_dict())
                break
