from __future__ import annotations

from dataclasses import dataclass, asdict
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Set

from .relationships.references import ASAReferenceIndex, ASAReferenceKind, ASAReferenceStatus, build_asa_reference_index, source_context_of


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
    return source_context_of(item)


def _entry_get(entry: Any, key: str, default: Any = None) -> Any:
    return entry.get(key, default) if isinstance(entry, dict) else getattr(entry, key, default)


def _issue(kind: str, source: str, name: str, source_context: Optional[str], reference_context: Optional[str], references: ASAReferenceIndex) -> ReferenceIssue:
    result = references.resolve(source_context, ASAReferenceKind(kind), name)
    if result.status is ASAReferenceStatus.AMBIGUOUS:
        return ReferenceIssue(kind, source, name, False, f"Ambiguous {kind.replace('_', ' ')} reference", source_context, reference_context)
    resolved = result.status is ASAReferenceStatus.RESOLVED
    return ReferenceIssue(
        kind, source, name, resolved,
        "resolved" if resolved else f"Unresolved {kind.replace('_', ' ')} reference",
        source_context,
        reference_context,
    )


def _cycle_issues(kind: str, groups: Iterable[Any], source_context: Optional[str] = None) -> List[ReferenceIssue]:
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


def validate_references(config: Any) -> List[ReferenceIssue]:
    reference_index = build_asa_reference_index(config)
    source_contexts = sorted(set(reference_index.contexts) | {None}, key=lambda value: (value is not None, value or ""))
    active_source_context: Optional[str] = None

    def select_context(source_context: Optional[str]) -> None:
        nonlocal active_source_context
        active_source_context = source_context

    issues: List[ReferenceIssue] = []

    def add(kind: str, source: str, name: Optional[str], context: Optional[str] = None) -> None:
        if name and name not in {"any", "any4", "any6"}:
            issues.append(_issue(kind, source, name, active_source_context, context, reference_index))

    from .relationships.interface_topology import build_asa_interface_topology
    topology = build_asa_interface_topology(config, reference_index)
    issues.extend(ReferenceIssue(issue.reference_kind.value, issue.source_object, issue.reference_name,
                                 issue.status is ASAReferenceStatus.RESOLVED, issue.reason,
                                 issue.source_context, issue.reference_context) for issue in topology.issues)
    issues.extend(ReferenceIssue(duplicate.reference_kind.value, duplicate.source_name, duplicate.source_name,
                                 False, f"Duplicate {duplicate.reference_kind.value} definition",
                                 duplicate.source_context) for duplicate in reference_index.duplicates)

    for group in config.network_groups:
        select_context(_source_context(group))
        for entry in group.member_entries:
            kind = {"network_object": "network_object", "network_group": "network_group"}.get(_entry_get(entry, "type"))
            if kind:
                name = _entry_get(entry, "value")
                add(kind, group.name, name)
        if not group.member_entries:
            for name in group.members:
                group_ref = reference_index.resolve(_source_context(group), ASAReferenceKind.NETWORK_GROUP, name)
                add("network_group" if group_ref.status is not ASAReferenceStatus.UNRESOLVED else "network_object", group.name, name)

    for source_context in source_contexts:
        select_context(source_context)
        families = reference_index.group_address_families(source_context)
        for group in config.network_groups:
            if _source_context(group) != source_context:
                continue
            if families.get(group.name) is None and group.member_entries:
                issues.append(ReferenceIssue(
                    "network_group", group.name, group.name, False,
                    "Network-group address family is unresolved",
                    source_context, "address-family",
                ))

    for group in config.service_groups:
        select_context(_source_context(group))
        if group.member_entries:
            for entry in group.member_entries:
                kind = {"service_object": "service_object", "service_group": "service_group"}.get(_entry_get(entry, "type"))
                if kind:
                    name = _entry_get(entry, "value")
                    add(kind, group.name, name)
        else:
            for name in group.members:
                group_ref = reference_index.resolve(_source_context(group), ASAReferenceKind.SERVICE_GROUP, name)
                add("service_group" if group_ref.status is not ASAReferenceStatus.UNRESOLVED else "service_object", group.name, name)
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
                        add(nested_kind, item.name, name)
            else:
                for name in item.members:
                    add(kind, item.name, name)

    for rule in config.access_rules:
        select_context(_source_context(rule))
        add("time_range", rule.acl_name, rule.time_range)
        if rule.time_range:
            schedule_result = reference_index.resolve(active_source_context, ASAReferenceKind.TIME_RANGE, rule.time_range)
            schedule = schedule_result.target
            if schedule is not None and schedule.extraction_status == "PARSE_ERROR":
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
            for acl_name in rule.match_acls or ([rule.match_acl] if rule.match_acl else []):
                add("acl", route_map.name, acl_name)
            for output_interface in rule.output_interfaces or ([rule.set_interface] if rule.set_interface else []):
                add("interface", route_map.name, output_interface, "route-map set interface")
            for next_hop in rule.next_hops or rule.source_attributes.get("next_hops", [rule.set_next_hop]):
                if not next_hop:
                    continue
                try:
                    ipaddress.ip_address(next_hop)
                except ValueError:
                    issues.append(ReferenceIssue(
                        "next_hop", route_map.name, next_hop, False,
                        "Invalid route-map next-hop address", active_source_context,
                        "route-map set ip next-hop",
                    ))
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
        add("group_policy", item.name, item.default_group_policy)
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
    for item in config.icmp_management_rules:
        select_context(_source_context(item))
        add("interface", item.name, item.interface, "icmp")
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
            add("acl", item.name, getattr(item, "acl_reference", None), "aaa")
    if not (config.aaa_server_groups or config.aaa_server_hosts or config.aaa_authentication_rules or config.aaa_authorization_rules or config.aaa_accounting_rules):
        for item in config.aaa_records:
            raw = item.source_attributes.get("raw_command", "")
            if raw.lower().startswith("aaa-server "):
                pass
            else:
                match = re.match(r"aaa\s+(?:authentication|authorization|accounting)\s+\S+\s+(\S+)", raw, re.I)
                add("aaa_server_group", item.name, match.group(1) if match else None)

    for route in config.static_routes:
        select_context(_source_context(route))
        add("interface", route.raw_line or "static route", route.interface, "static-route")
        if route.track_id is not None:
            add("route_tracking", route.raw_line or "static route", str(route.track_id), "static-route")

    for nat in config.nat_rules:
        select_context(_source_context(nat))
        for value in (nat.real_source, nat.mapped_source, nat.real_destination, nat.mapped_destination, nat.pat_pool):
            if not value or value.lower() in {"interface", "any", "original", "translated"}:
                continue
            try:
                ipaddress.ip_network(value, strict=False)
                continue
            except ValueError:
                pass
            object_ref = reference_index.resolve(active_source_context, ASAReferenceKind.NETWORK_OBJECT, value)
            group_ref = reference_index.resolve(active_source_context, ASAReferenceKind.NETWORK_GROUP, value)
            if object_ref.status is ASAReferenceStatus.RESOLVED or group_ref.status is ASAReferenceStatus.RESOLVED:
                continue
            if object_ref.status is ASAReferenceStatus.AMBIGUOUS or group_ref.status is ASAReferenceStatus.AMBIGUOUS:
                issues.append(ReferenceIssue("network_object", nat.name, value, False, "Ambiguous NAT address operand", active_source_context, "nat"))
            else:
                issues.append(ReferenceIssue("network_object", nat.name, value, False, "Unresolved NAT address operand", active_source_context, "nat"))
    for track in config.tracks:
        select_context(_source_context(track))
        if track.sla_id is not None:
            add("sla_monitor", track.name, str(track.sla_id), "track")

    for source_context in source_contexts:
        select_context(source_context)
        issues.extend(_cycle_issues("network_group", [item for item in config.network_groups if _source_context(item) == source_context], source_context))
        issues.extend(_cycle_issues("service_group", [item for item in config.service_groups if _source_context(item) == source_context], source_context))
        issues.extend(_cycle_issues("protocol_group", [item for item in config.protocol_groups if _source_context(item) == source_context], source_context))
        issues.extend(_cycle_issues("icmp_group", [item for item in config.icmp_type_groups if _source_context(item) == source_context], source_context))
    return issues


