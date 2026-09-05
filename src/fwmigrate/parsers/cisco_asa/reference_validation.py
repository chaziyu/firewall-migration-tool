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
    reference_context: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _index(items: Iterable[Any]) -> Dict[str, Any]:
    return {item.name: item for item in items if getattr(item, "name", None)}


def _source_context(item: Any) -> Optional[str]:
    return getattr(item, "source_context", None) or getattr(item, "source_attributes", {}).get("source_context")


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


def build_reference_indexes(config: Any, source_context: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    def scoped(items: Iterable[Any]) -> Iterable[Any]:
        return (item for item in items if _source_context(item) == source_context)

    interfaces = _index(scoped(config.interfaces))
    interfaces.update({item.nameif: item for item in scoped(config.interfaces) if getattr(item, "nameif", None)})
    return {
        "network_object": _index(scoped(config.network_objects)),
        "network_group": _index(scoped(config.network_groups)),
        "service_object": _index(scoped(config.service_objects)),
        "service_group": _index(scoped(config.service_groups)),
        "protocol_group": _index(scoped(config.protocol_groups)),
        "icmp_group": _index(scoped(config.icmp_type_groups)),
        "acl": {name: name for name in {item.acl_name for item in scoped(config.access_rules)}},
        "time_range": _index(scoped(config.time_ranges)),
        "route_map": _index(scoped(config.route_maps)),
        "interface": interfaces,
        "nameif": {item.nameif: item for item in scoped(config.interfaces) if item.nameif},
        "ike_policy": _index(scoped(config.ike_policies)),
        "ikev2_proposal": _index(scoped(config.ikev2_proposals)),
        "ipsec_transform_set": _index(scoped(config.ipsec_transform_sets)),
        "vpn_address_pool": _index(scoped(config.vpn_address_pools)),
        "trustpoint": {name: name for name in config.trustpoints},
        "crypto_map": _index(scoped(config.crypto_maps)),
        "tunnel_group": _index(scoped(config.tunnel_groups)),
        "group_policy": _index(scoped(config.group_policies)),
        "class_map": _index(scoped(config.class_maps)),
        "policy_map": _index(scoped(config.policy_maps)),
        "tcp_map": _index(scoped(config.tcp_maps)),
        "dns_server_group": _index(scoped(config.dns_server_groups)),
        "aaa_server_group": _index(scoped(config.aaa_server_groups)) or {
            item.name: item for item in scoped(config.aaa_records)
            if item.source_attributes.get("raw_command", "").lower().startswith("aaa-server ")
        },
        "route_tracking": {str(track_id): track_id for track_id in config.route_tracking_ids},
    }


def _issue(kind: str, source: str, name: str, indexes: Dict[str, Dict[str, Any]], source_context: Optional[str] = None, reference_context: Optional[str] = None) -> ReferenceIssue:
    resolved = name in indexes[kind]
    return ReferenceIssue(
        kind, source, name, resolved,
        "resolved" if resolved else f"Unresolved {kind.replace('_', ' ')} reference",
        source_context,
        reference_context,
    )


def _cycle_issues(kind: str, groups: Iterable[Any], indexes: Dict[str, Dict[str, Any]], source_context: Optional[str] = None) -> List[ReferenceIssue]:
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
            elif kind == "icmp_group":
                allowed = {"icmp_group"}
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
            issues.extend(ReferenceIssue(kind, participant, name, False, reason, source_context) for participant in cycle[:-1])
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
    collections = (
        config.interfaces, config.network_objects, config.network_groups,
        config.service_objects, config.service_groups, config.protocol_groups,
        config.icmp_type_groups, config.access_rules, config.acl_bindings,
        config.time_ranges, config.route_maps, config.crypto_maps,
        config.ike_policies, config.ikev2_proposals, config.ipsec_transform_sets,
        config.vpn_address_pools, config.tunnel_groups, config.group_policies,
        config.class_maps, config.policy_maps, config.tcp_maps,
        config.dns_server_groups, config.aaa_server_groups,
        config.aaa_server_hosts, config.aaa_records, config.local_users,
        config.aaa_authentication_rules, config.aaa_authorization_rules,
        config.aaa_accounting_rules, config.dhcp_servers, config.dhcp_relays,
        config.ntp_servers, config.management_access_rules, config.snmp_settings,
        config.logging_settings,
    )
    source_contexts = {None}
    for collection in collections:
        source_contexts.update(_source_context(item) for item in collection)
    scoped_indexes = {context: build_reference_indexes(config, context) for context in source_contexts}
    indexes = dict(scoped_indexes[None])
    active_source_context: Optional[str] = None

    def select_context(source_context: Optional[str]) -> None:
        nonlocal active_source_context
        indexes.clear()
        indexes.update(scoped_indexes.get(source_context, scoped_indexes[None]))
        active_source_context = source_context

    issues: List[ReferenceIssue] = []

    def add(kind: str, source: str, name: Optional[str], context: Optional[str] = None) -> None:
        if name and name not in {"any", "any4", "any6"}:
            issues.append(_issue(kind, source, name, indexes, active_source_context, context))

    for group in config.network_groups:
        select_context(_source_context(group))
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

    for source_context in source_contexts:
        select_context(source_context)
        _resolve_network_group_families(indexes)

    for group in config.service_groups:
        select_context(_source_context(group))
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
                if port and port.operator in {"object", "object-group"}:
                    kind = "service_group" if port.operator == "object-group" else "service_object"
                    add(kind, group.name, port.object_name or (port.values[0] if port.values else None), "service-port")

    for item in config.service_objects:
        select_context(_source_context(item))
        for member in item.ports:
            for port in (member.destination, member.source):
                if port and port.operator in {"object", "object-group"}:
                    kind = "service_group" if port.operator == "object-group" else "service_object"
                    add(kind, item.name, port.object_name or (port.values[0] if port.values else None), "service-port")

    for group, kind in [(config.protocol_groups, "protocol_group"), (config.icmp_type_groups, "icmp_group")]:
        for item in group:
            select_context(_source_context(item))
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
        select_context(_source_context(rule))
        add("time_range", rule.acl_name, rule.time_range)
        if rule.time_range:
            schedule = indexes["time_range"].get(rule.time_range)
            if schedule is not None and schedule.migration_status == "PARSE_ERROR":
                issues.append(ReferenceIssue(
                    "time_range", rule.acl_name, rule.time_range, True,
                    f"Referenced time-range {rule.time_range} contains parse errors",
                    active_source_context,
                ))
        add("protocol_group", rule.acl_name, rule.protocol_object)
        add("icmp_group", rule.acl_name, rule.icmp_object_group)
        for endpoint in (rule.source_endpoint, rule.destination_endpoint):
            if endpoint and endpoint.type in {"object", "object-group"}:
                add("network_group" if endpoint.type == "object-group" else "network_object", rule.acl_name, endpoint.value)

    for binding in config.acl_bindings:
        select_context(_source_context(binding))
        add("acl", "access-group", binding.acl_name)
        add("interface", "access-group", binding.interface)

    for route_map in config.route_maps:
        select_context(_source_context(route_map))
        for rule in route_map.rules:
            add("acl", route_map.name, rule.match_acl)
    for interface in config.interfaces:
        select_context(_source_context(interface))
        for route_map in interface.policy_route_maps:
            add("route_map", interface.name, route_map)
    for item in config.crypto_maps:
        select_context(_source_context(item))
        add("acl", item.name, item.acl_name)
        add("interface", item.name, item.interface_attachment, "crypto-map")
        for transform_set in item.transform_sets:
            add("ipsec_transform_set", item.name, transform_set)
        for proposal in item.ikev2_proposals:
            add("ikev2_proposal", item.name, proposal)
        if item.dynamic_map:
            add("crypto_map", item.name, item.dynamic_map)
    for item in config.tunnel_groups:
        select_context(_source_context(item))
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
        add("trustpoint", item.name, item.trustpoint)
    for item in config.group_policies:
        select_context(_source_context(item))
        for pool in item.address_pools:
            add("vpn_address_pool", item.name, pool)
        add("acl", item.name, item.split_tunnel_acl)
    for item in config.class_maps:
        select_context(_source_context(item))
        for match in item.matches:
            if match.match_type != "access_list" or not match.acl_name:
                continue
            target = indexes["acl"].get(match.acl_name)
            match.resolved = target is not None
            if target is not None:
                match.resolved_target_type = "acl"
            else:
                _entry_reason(match, f"Unresolved ACL reference: {match.acl_name}")
            add("acl", item.name, match.acl_name, "class-map")
    for item in config.policy_maps:
        select_context(_source_context(item))
        for section in item.classes:
            if section.class_name != "class-default":
                add("class_map", item.name, section.class_name, section.class_name)
            if section.tcp_map:
                add("tcp_map", item.name, section.tcp_map, section.class_name)
    for item in config.service_policies:
        select_context(_source_context(item))
        add("policy_map", item.name, item.policy_name, "service-policy")
        if item.scope == "interface":
            add("interface", item.name, item.interface, "service-policy")
    for item in config.dhcp_servers:
        select_context(_source_context(item))
        add("interface", item.name, item.interface, "dhcpd")
    for item in config.dhcp_relays:
        select_context(_source_context(item))
        for entry in item.server_entries:
            target = indexes["interface"].get(entry.interface) if entry.interface else None
            entry.resolved_interface = target.name if target is not None else None
            if entry.interface and target is None:
                entry.review_reasons.append(f"Unresolved interface reference: {entry.interface}")
            add("interface", item.name, entry.interface, "dhcprelay-server")
        for interface in item.enabled_interfaces:
            add("interface", item.name, interface, "dhcprelay-enable")
    for interface in config.dns_settings.lookup_interfaces:
        add("interface", config.dns_settings.name, interface, "dns-domain-lookup")
    system = config.system_settings
    add("interface", system.name, system.management_access_interface, "management-access")
    for item in config.ntp_servers:
        select_context(_source_context(item))
        add("interface", item.name, item.interface, "ntp")
    for item in config.management_access_rules:
        select_context(_source_context(item))
        add("interface", item.name, item.interface, item.protocol)
    for item in config.snmp_settings:
        select_context(_source_context(item))
        add("interface", item.name, item.interface, "snmp")
    for item in config.logging_settings:
        select_context(_source_context(item))
        add("interface", item.name, item.interface, "logging")
    failover = config.failover_config
    add("interface", failover.name, failover.lan_interface, "failover-lan")
    add("interface", failover.name, failover.stateful_link_interface, "failover-stateful")
    add("interface", failover.name, failover.state_link_interface, "failover-state")
    for name in failover.interface_monitoring:
        add("interface", failover.name, name, "failover-monitor")
    for item in failover.interface_ips:
        add("interface", item.name, item.interface, "failover-ip")
    for item in failover.mac_addresses:
        add("interface", item.name, item.interface, "failover-mac")
    for item in config.aaa_server_hosts:
        select_context(_source_context(item))
        add("aaa_server_group", item.name, item.group_name)
        add("interface", item.name, item.interface)
    for collection in (config.aaa_authentication_rules, config.aaa_authorization_rules, config.aaa_accounting_rules):
        for item in collection:
            select_context(_source_context(item))
            add("aaa_server_group", item.name, item.server_group)
    if not (config.aaa_server_groups or config.aaa_server_hosts or config.aaa_authentication_rules or config.aaa_authorization_rules or config.aaa_accounting_rules):
        for item in config.aaa_records:
            raw = item.source_attributes.get("raw_command", "")
            if raw.lower().startswith("aaa-server "):
                item.source_attributes["aaa_server_group"] = item.name
            else:
                match = re.match(r"aaa\s+(?:authentication|authorization|accounting)\s+\S+\s+(\S+)", raw, re.I)
                add("aaa_server_group", item.name, match.group(1) if match else None)

    for route in config.static_routes:
        select_context(_source_context(route))
        if route.track_id is not None:
            add("route_tracking", route.raw_line or "static route", str(route.track_id), "static-route")

    for source_context in source_contexts:
        select_context(source_context)
        issues.extend(_cycle_issues("network_group", [item for item in config.network_groups if _source_context(item) == source_context], indexes, source_context))
        issues.extend(_cycle_issues("service_group", [item for item in config.service_groups if _source_context(item) == source_context], indexes, source_context))
        issues.extend(_cycle_issues("protocol_group", [item for item in config.protocol_groups if _source_context(item) == source_context], indexes, source_context))
        issues.extend(_cycle_issues("icmp_group", [item for item in config.icmp_type_groups if _source_context(item) == source_context], indexes, source_context))
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
        reason = issue.reason if issue.reason.startswith("Cycle detected") else f"{issue.reason}: {issue.reference_name}"
        if issue.reference_type == "route_tracking":
            for route in config.static_routes:
                if route.track_id == int(issue.reference_name) and _source_context(route) == issue.source_context:
                    route.migration_status = "PARTIALLY_NORMALIZED" if route.migration_status != "PARSE_ERROR" else route.migration_status
                    route.requires_manual_review = True
                    if reason not in route.review_reasons:
                        route.review_reasons.append(reason)
                    route.source_attributes.setdefault("reference_issues", []).append(issue.as_dict())
            continue
        if issue.reference_type == "class_map" and any(item.name == issue.source_object and _source_context(item) == issue.source_context for item in config.policy_maps):
            policy = next(item for item in config.policy_maps if item.name == issue.source_object and _source_context(item) == issue.source_context)
            policy.migration_status = "PARTIALLY_NORMALIZED" if policy.migration_status != "PARSE_ERROR" else policy.migration_status
            policy.requires_manual_review = True
            if reason not in policy.review_reasons:
                policy.review_reasons.append(reason)
            for section in policy.classes:
                if section.class_name == issue.reference_context:
                    section.migration_status = "PARTIALLY_NORMALIZED" if section.migration_status != "PARSE_ERROR" else section.migration_status
                    section.requires_manual_review = True
                    if reason not in section.review_reasons:
                        section.review_reasons.append(reason)
            continue
        if issue.reference_type == "tcp_map" and any(item.name == issue.source_object and _source_context(item) == issue.source_context for item in config.policy_maps):
            policy = next(item for item in config.policy_maps if item.name == issue.source_object and _source_context(item) == issue.source_context)
            policy.migration_status = "PARTIALLY_NORMALIZED" if policy.migration_status != "PARSE_ERROR" else policy.migration_status
            policy.requires_manual_review = True
            if reason not in policy.review_reasons:
                policy.review_reasons.append(reason)
            for section in policy.classes:
                if section.class_name == issue.reference_context:
                    section.migration_status = "PARTIALLY_NORMALIZED" if section.migration_status != "PARSE_ERROR" else section.migration_status
                    section.requires_manual_review = True
                    if reason not in section.review_reasons:
                        section.review_reasons.append(reason)
            continue
        if issue.reference_type == "acl" and issue.reference_context == "class-map":
            item = next((item for item in config.class_maps if item.name == issue.source_object and _source_context(item) == issue.source_context), None)
            if item is not None:
                item.migration_status = "PARTIALLY_NORMALIZED" if item.migration_status != "PARSE_ERROR" else item.migration_status
                item.requires_manual_review = True
                if reason not in item.review_reasons:
                    item.review_reasons.append(reason)
                for match in item.matches:
                    if match.acl_name == issue.reference_name:
                        _entry_reason(match, reason)
                continue
        if issue.reference_type in {"policy_map", "interface"} and issue.reference_context == "service-policy":
            matched = [
                item for item in config.service_policies
                if item.name == issue.source_object
                and _source_context(item) == issue.source_context
                and (issue.reference_type != "interface" or item.interface == issue.reference_name)
            ]
            for item in matched:
                item.migration_status = "PARTIALLY_NORMALIZED" if item.migration_status != "PARSE_ERROR" else item.migration_status
                item.requires_manual_review = True
                if reason not in item.review_reasons:
                    item.review_reasons.append(reason)
            if matched:
                continue
        for collection in (config.network_groups, config.service_objects, config.service_groups, config.protocol_groups,
                           config.icmp_type_groups, config.access_rules, config.acl_bindings,
                           config.route_maps, config.interfaces, config.crypto_maps,
                           config.static_routes,
                           config.tunnel_groups, config.group_policies, config.aaa_records,
                           config.aaa_server_groups, config.aaa_server_hosts, config.local_users,
                           config.aaa_authentication_rules, config.aaa_authorization_rules,
                           config.aaa_accounting_rules, config.dhcp_servers, config.dhcp_relays,
                           [config.dns_settings, config.system_settings, config.failover_config],
                           config.ntp_servers, config.management_access_rules,
                           config.snmp_settings, config.logging_settings, config.enable_credentials,
                           config.failover_config.interface_ips, config.failover_config.mac_addresses):
            for item in collection:
                if _source_context(item) != issue.source_context:
                    continue
                if getattr(item, "name", None) != issue.source_object and getattr(item, "acl_name", None) != issue.source_object:
                    continue
                if hasattr(item, "migration_status"):
                    if item.migration_status != "PARSE_ERROR":
                        item.migration_status = "PARTIALLY_NORMALIZED"
                if hasattr(item, "requires_manual_review"):
                    item.requires_manual_review = True
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
