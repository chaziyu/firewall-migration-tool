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


def _entry_get(entry: Any, key: str, default: Any = None) -> Any:
    return entry.get(key, default) if isinstance(entry, dict) else getattr(entry, key, default)


def _entry_set(entry: Any, key: str, value: Any) -> None:
    if isinstance(entry, dict):
        entry[key] = value
    else:
        setattr(entry, key, value)


def _entry_reason(entry: Any, reason: str) -> None:
    reasons = _entry_get(entry, "review_reasons")
    if reasons is not None and reason not in reasons:
        reasons.append(reason)


def build_reference_indexes(config: Any) -> Dict[str, Dict[str, Any]]:
    interfaces = _index(config.interfaces)
    interfaces.update({item.nameif: item for item in config.interfaces if getattr(item, "nameif", None)})
    return {
        "network_object": _index(config.network_objects),
        "network_group": _index(config.network_groups),
        "service_object": _index(config.service_objects),
        "service_group": _index(config.service_groups),
        "protocol_group": _index(config.protocol_groups),
        "icmp_group": _index(config.icmp_type_groups),
        "acl": {name: name for name in {item.acl_name for item in config.access_rules}},
        "time_range": _index(config.time_ranges),
        "route_map": _index(config.route_maps),
        "interface": interfaces,
        "nameif": {item.nameif: item for item in config.interfaces if item.nameif},
        "ike_policy": _index(config.ike_policies),
        "ikev2_proposal": _index(config.ikev2_proposals),
        "ipsec_transform_set": _index(config.ipsec_transform_sets),
        "vpn_address_pool": _index(config.vpn_address_pools),
        "crypto_map": _index(config.crypto_maps),
        "tunnel_group": _index(config.tunnel_groups),
        "group_policy": _index(config.group_policies),
        "aaa_server_group": _index(config.aaa_server_groups) or {
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
            allowed = {"network_group", "nested_group"}
            if kind == "service_group":
                allowed = {"service_group"}
            elif kind == "protocol_group":
                allowed = {"protocol_group"}
            values = [
                _entry_get(entry, "value", "")
                for entry in group.member_entries
                if _entry_get(entry, "type") in allowed
            ]
        edges[group.name] = [value for value in values if value in by_name]

    issues: List[ReferenceIssue] = []
    visiting: List[str] = []
    visited: Set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            cycle = visiting[visiting.index(name):] + [name]
            reason = f"Cycle detected: {' -> '.join(cycle)}"
            issues.extend(ReferenceIssue(kind, participant, name, False, reason) for participant in cycle[:-1])
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


def _resolve_network_group_families(indexes: Dict[str, Dict[str, Any]]) -> None:
    groups = indexes["network_group"]
    resolved: Dict[str, Optional[str]] = {}
    visiting: Set[str] = set()

    def visit(name: str) -> Optional[str]:
        if name in resolved:
            return resolved[name]
        if name in visiting:
            return None
        group = groups[name]
        visiting.add(name)
        families: Set[str] = set()
        uncertain = False
        for entry in group.member_entries:
            kind = _entry_get(entry, "type")
            if kind in {"host", "inline_network"}:
                family = _entry_get(entry, "address_family")
            elif kind == "network_object":
                target = indexes["network_object"].get(_entry_get(entry, "value"))
                family = getattr(target, "address_family", None) if target is not None else None
                uncertain = uncertain or target is None or family is None
            elif kind == "network_group":
                target_name = _entry_get(entry, "value")
                target = groups.get(target_name)
                family = visit(target_name) if target is not None else None
                uncertain = uncertain or target is None or family is None
                _entry_set(entry, "address_family", family)
            else:
                continue
            if family == "mixed":
                families.update({"ipv4", "ipv6"})
            elif family in {"ipv4", "ipv6"}:
                families.add(family)
            else:
                uncertain = True
        visiting.remove(name)
        family = None if uncertain else (next(iter(families)) if len(families) == 1 else "mixed" if families else None)
        resolved[name] = family
        group.address_family = family
        if uncertain and group.member_entries:
            group.requires_manual_review = True
            if group.migration_status != "PARSE_ERROR":
                group.migration_status = "PARTIALLY_NORMALIZED"
            reason = "Network-group address family is unresolved"
            if reason not in group.review_reasons:
                group.review_reasons.append(reason)
        return family

    for name in sorted(groups):
        visit(name)


def validate_references(config: Any) -> List[ReferenceIssue]:
    indexes = build_reference_indexes(config)
    issues: List[ReferenceIssue] = []

    def add(kind: str, source: str, name: Optional[str], context: Optional[str] = None) -> None:
        if name and name not in {"any", "any4", "any6"}:
            issues.append(_issue(kind, source, name, indexes, context))

    for group in config.network_groups:
        for entry in group.member_entries:
            kind = {"network_object": "network_object", "network_group": "network_group"}.get(_entry_get(entry, "type"))
            if kind:
                name = _entry_get(entry, "value")
                target = indexes[kind].get(name)
                if target is None:
                    _entry_set(entry, "resolved", False)
                    _entry_set(entry, "address_family", None)
                    reason = f"Unresolved {kind.replace('_', ' ')} reference: {name}"
                    _entry_reason(entry, reason)
                    add(kind, group.name, name)
                else:
                    _entry_set(entry, "resolved", True)
                    _entry_set(entry, "resolved_target_type", kind)
                    _entry_set(entry, "address_family", getattr(target, "address_family", None))
        if not group.member_entries:
            for name in group.members:
                add("network_group" if name in indexes["network_group"] else "network_object", group.name, name)

    _resolve_network_group_families(indexes)

    for group in config.service_groups:
        if group.member_entries:
            for entry in group.member_entries:
                kind = {"service_object": "service_object", "service_group": "service_group"}.get(_entry_get(entry, "type"))
                if kind:
                    name = _entry_get(entry, "value")
                    target = indexes[kind].get(name)
                    _entry_set(entry, "resolved", target is not None)
                    if target is not None:
                        _entry_set(entry, "resolved_target_type", kind)
                    else:
                        _entry_reason(entry, f"Unresolved {kind.replace('_', ' ')} reference: {name}")
                    add(kind, group.name, name)
        else:
            for name in group.members:
                add("service_group" if name in indexes["service_group"] else "service_object", group.name, name)
        for member in group.service_objects:
            for port in (member.destination, member.source):
                add("service_object", group.name, port.object_name if port else None)

    for group, kind in [(config.protocol_groups, "protocol_group"), (config.icmp_type_groups, "icmp_group")]:
        for item in group:
            if item.member_entries:
                nested_kind = "protocol_group" if kind == "protocol_group" else "icmp_group"
                for entry in item.member_entries:
                    if _entry_get(entry, "type") in {"protocol_group", "icmp_group"}:
                        name = _entry_get(entry, "value")
                        target = indexes[nested_kind].get(name)
                        _entry_set(entry, "resolved", target is not None)
                        if target is not None:
                            _entry_set(entry, "resolved_target_type", nested_kind)
                        else:
                            _entry_reason(entry, f"Unresolved {nested_kind.replace('_', ' ')} reference: {name}")
                        add(nested_kind, item.name, name)
            else:
                for name in item.members:
                    add(kind, item.name, name)

    for rule in config.access_rules:
        add("time_range", rule.acl_name, rule.time_range)
        if rule.time_range:
            schedule = indexes["time_range"].get(rule.time_range)
            if schedule is not None and schedule.migration_status == "PARSE_ERROR":
                issues.append(ReferenceIssue(
                    "time_range", rule.acl_name, rule.time_range, True,
                    f"Referenced time-range {rule.time_range} contains parse errors",
                ))
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
        for transform_set in item.transform_sets:
            add("ipsec_transform_set", item.name, transform_set)
        for proposal in item.ikev2_proposals:
            add("ikev2_proposal", item.name, proposal)
        if item.dynamic_map:
            add("crypto_map", item.name, item.dynamic_map)
    for item in config.tunnel_groups:
        policy = item.default_group_policy or item.ipsec_attributes.get("default_group_policy")
        if not policy:
            for command in item.ipsec_attributes.get("raw_subcommands", []):
                match = re.match(r"(?:default-)?group-policy\s+(\S+)", command, re.I)
                if match:
                    policy = match.group(1)
                    break
        add("group_policy", item.name, policy)
        for pool in item.address_pools:
            add("vpn_address_pool", item.name, pool)
    for item in config.group_policies:
        for pool in item.address_pools:
            add("vpn_address_pool", item.name, pool)
        add("acl", item.name, item.split_tunnel_acl)
    for item in config.aaa_server_hosts:
        add("aaa_server_group", item.name, item.group_name)
        add("interface", item.name, item.interface)
    for collection in (config.aaa_authentication_rules, config.aaa_authorization_rules, config.aaa_accounting_rules):
        for item in collection:
            add("aaa_server_group", item.name, item.server_group)
            add("interface", item.name, item.interface)
    if not (config.aaa_server_groups or config.aaa_server_hosts or config.aaa_authentication_rules or config.aaa_authorization_rules or config.aaa_accounting_rules):
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
        invalid_schedule = (
            issue.reference_type == "time_range"
            and issue.resolved
            and "contains parse errors" in issue.reason
        )
        if issue.resolved and not invalid_schedule:
            continue
        for collection in (config.network_groups, config.service_groups, config.protocol_groups,
                           config.icmp_type_groups, config.access_rules, config.acl_bindings,
                           config.route_maps, config.interfaces, config.crypto_maps,
                           config.tunnel_groups, config.group_policies, config.aaa_records,
                           config.aaa_server_groups, config.aaa_server_hosts, config.local_users,
                           config.aaa_authentication_rules, config.aaa_authorization_rules,
                           config.aaa_accounting_rules):
            for item in collection:
                if getattr(item, "name", None) != issue.source_object and getattr(item, "acl_name", None) != issue.source_object:
                    continue
                if hasattr(item, "migration_status"):
                    if item.migration_status != "PARSE_ERROR":
                        item.migration_status = "PARTIALLY_NORMALIZED"
                if hasattr(item, "requires_manual_review"):
                    item.requires_manual_review = True
                reason = issue.reason if issue.reason.startswith("Cycle detected") else f"{issue.reason}: {issue.reference_name}"
                if hasattr(item, "review_reasons"):
                    if reason not in item.review_reasons:
                        item.review_reasons.append(reason)
                if hasattr(item, "source_attributes"):
                    item.source_attributes.setdefault("reference_issues", []).append(issue.as_dict())
                    if issue.reference_type == "network_group":
                        validations = item.source_attributes.setdefault("reference_validation", [])
                        if issue.reason.startswith("Cycle detected") and "Cyclic nested network-group reference" not in validations:
                            validations.append("Cyclic nested network-group reference")
                        if reason not in validations:
                            validations.append(reason)
                if issue.reference_type in {"network_object", "network_group", "service_object", "service_group", "protocol_group", "icmp_group"} and hasattr(item, "member_entries"):
                    for entry in item.member_entries:
                        if _entry_get(entry, "value") == issue.reference_name:
                            _entry_reason(entry, reason)
                break
