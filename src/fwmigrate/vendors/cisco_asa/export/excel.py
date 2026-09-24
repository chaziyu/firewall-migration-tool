from __future__ import annotations

from pathlib import Path
from typing import Any

from .excel_schema import SHEET_HEADERS, SHEET_ORDER
from ..presentation_schema import DERIVED_SECTIONS, SOURCE_SECTIONS
from ..presentation import excel_value


def _name(value: Any) -> Any:
    return getattr(value, "name", value)


def _row(sheet: str, item: Any) -> tuple[Any, ...]:
    if sheet == "Interfaces":
        return item.name, item.nameif, item.source_context, item.ip, item.mask, item.security_level
    if sheet == "Network Objects":
        return item.name, item.type, item.value, item.source_context
    if sheet == "Network Groups":
        return item.name, ", ".join(item.members), item.source_context
    if sheet == "ACL Rules":
        return (item.acl_name, item.source_order, item.action,
                item.protocol, getattr(item.source_endpoint, "value", None),
                getattr(item.destination_endpoint, "value", None), item.service,
                item.source_context, item.raw_line)
    if sheet == "NAT Rules":
        rule = item.source_rule
        return (rule.name, item.source_order, item.effective_order, item.ordering_status, item.section,
                item.translation_semantics, rule.source_interface, rule.destination_interface,
                rule.real_source, rule.mapped_source, item.source_context, rule.raw_line)
    if sheet == "Source NAT Pools":
        return (item.source_rule.name, item.pool_type, item.mapped_source, _name(item.mapped_interface),
                item.address_family, item.translation_semantics, _name(item.source_interface),
                _name(item.destination_interface), item.source_context, item.issues)
    if sheet == "Published Services - VIPs":
        return (item.source_rule.name, item.mapped_address, item.real_address, item.mapped_service,
                item.real_service, item.protocol, _name(item.source_nat_interface), _name(item.destination_nat_interface),
                item.source_nat_order, item.source_context, item.issues)
    if sheet == "Routes":
        route = item.source_route
        return (item.interface, item.configured_destination, item.configured_mask, item.normalized_destination,
                item.gateway, item.configured_administrative_distance, item.effective_administrative_distance,
                item.track_id, item.source_context, route.raw_line)
    if sheet in {"VPN", "IPsec VPN"}:
        source = item.source_identity
        return (item.topology_type, source.name, item.crypto_map, item.crypto_map_sequence,
                getattr(item.crypto_acl, "acl_name", item.crypto_acl), item.peers,
                tuple(getattr(value, "name", value) for value in item.tunnel_groups),
                getattr(item.interface, "name", None), tuple(getattr(value, "name", value) for value in item.transform_sets),
                tuple(getattr(value, "name", value) for value in item.ikev2_proposals), item.tunnel_interface,
                item.ipsec_profile, getattr(item.group_policy, "name", None),
                tuple(getattr(value, "name", value) for value in item.address_pools), item.source_context, item.issues)
    if sheet == "Remote Access VPN":
        authentication = _name(item.authentication_server_group)
        if authentication is None and item.local_authentication_available:
            authentication = "Local"
        return (item.tunnel_group.name, _name(item.group_policy), authentication,
                tuple(_name(value) for value in item.address_pools),
                tuple(_name(value) for value in item.dhcp_servers), item.address_assignment_methods,
                item.vpn_protocols, _name(item.split_tunnel_acl), _name(item.vpn_filter_acl),
                _name(item.vpn_access_hours), item.dns_servers, item.wins_servers, item.default_domain,
                tuple(_name(value) for value in item.enabled_interfaces),
                tuple(_name(value) for value in item.trustpoints), item.source_context, item.issues)
    raise KeyError(sheet)


def export_asa_excel(result: Any, output: Any) -> Any:
    from openpyxl import Workbook

    workbook = Workbook()
    workbook.remove(workbook.active)
    config = result.config
    for name in SHEET_ORDER:
        sheet = workbook.create_sheet(name)
        if name == "Summary":
            sheet.append(("Field", "Value"))
            for key, value in {
                "Vendor": "Cisco ASA", "Hostname": config.hostname,
                "Interfaces": len(config.interfaces), "ACL Rules": len(config.access_rules),
                "NAT Rules": len(config.nat_rules), "Validation Issues": len(result.validation.issues),
                "Unsupported Commands": len(result.unsupported_items),
            }.items():
                sheet.append((key, excel_value(value)))
            continue
        if name == "Source Inventory":
            sheet.append(SHEET_HEADERS[name])
            for item in result.inventory_items:
                sheet.append((item.domain, item.source_path, item.source_id, item.status.value,
                              item.requires_manual_review, "; ".join(item.notes)))
            continue
        if name == "Review Required":
            sheet.append(SHEET_HEADERS[name])
            for item in result.inventory_items:
                if item.requires_manual_review:
                    sheet.append((item.domain, item.source_path, item.source_id, item.status.value,
                                  "; ".join(item.notes), item.source_path or item.source_id))
            for issue in result.validation.issues:
                sheet.append(("Validation", issue.source_context, issue.source_object, issue.severity,
                              issue.message, issue.source_object))
            for issue in result.derived.relationship_issues + result.derived.transform_issues:
                sheet.append(("Derived", getattr(issue, "source_context", None),
                              getattr(issue, "source_object", None), "REVIEW_REQUIRED",
                              getattr(issue, "message", str(issue)), getattr(issue, "source_object", None)))
            continue
        if name == "Validation":
            sheet.append(SHEET_HEADERS[name])
            for issue in result.validation.issues:
                sheet.append((issue.severity, issue.category, issue.message, issue.source_context, issue.source_object))
            continue
        if name == "Unsupported":
            sheet.append(SHEET_HEADERS[name])
            for item in result.unsupported_items:
                raw = getattr(item, "raw_capture", None)
                source_name = getattr(item, "source_name", "") or ""
                line = getattr(item, "line_number", None)
                if line is None and source_name.startswith("line ") and source_name[5:].isdigit():
                    line = int(source_name[5:])
                sheet.append((line, getattr(item, "source_context", None),
                              getattr(item, "source_path", None), item.reason, raw))
            continue
        if name == "Extraction Coverage":
            sheet.append(SHEET_HEADERS[name])
            from collections import Counter
            counts = Counter((item.source_path, item.status.value, item.requires_manual_review)
                             for item in result.inventory_items)
            areas = {
                "Address Objects": ("object network", "object-group network"),
                "Address Groups": ("object-group network",), "Source NAT": ("nat object", "nat manual"),
                "Firewall Policy": ("access-list", "access-group"), "MPF / Security Stack": ("class-map", "policy-map", "service-policy"),
                "Schedules": ("time-range",), "Services": ("object service", "object-group service"),
                "Destination NAT": ("nat object", "nat manual"), "VIP-group equivalent source": ("nat manual",),
                "IPS / AIP": ("ips", "policy-map"), "Static Routes": ("route", "ipv6 route"),
                "Command Authorization": ("privilege", "aaa authorization command"), "Administrators": ("username",),
                "DHCP": ("dhcpd", "dhcprelay"), "Policy Routing / SLA": ("policy-route", "sla-monitor", "track"),
                "Zones": ("interface",), "User Groups": ("object-group user",), "Local Users": ("username",),
                "IPsec VPN": ("crypto ikev1 policy", "crypto ikev2 policy", "crypto ipsec", "crypto map", "tunnel-group"),
                "Remote Access VPN": ("webvpn", "group-policy", "vpn-addr-assign", "tunnel-group"),
            }
            for label, families in areas.items():
                matching = [(path, status, review, count) for (path, status, review), count in counts.items()
                            if any(path.startswith(family) for family in families)]
                sheet.append((label, ", ".join(families), sum(c for _, _, _, c in matching),
                              sum(c for _, s, _, c in matching if s == "EXTRACTED"),
                              sum(c for _, s, _, c in matching if s == "PARTIAL"),
                              sum(c for _, s, _, c in matching if s == "UNSUPPORTED"),
                              sum(c for _, s, _, c in matching if s == "PARSE_ERROR"),
                              sum(c for _, _, r, c in matching if r)))
            continue
        if name == "NAT Rules":
            sheet.append(SHEET_HEADERS[name])
            for item in result.derived.nat.rules:
                rule = item.source_rule
                values = (rule.name, item.source_order, item.effective_order, item.ordering_status,
                item.section, rule.source_context, rule.syntax_family, rule.source_order_within_section,
                          rule.source_sequence, item.translation_semantics, rule.source_interface,
                          rule.destination_interface, rule.real_source, rule.mapped_source, rule.source_mode,
                          rule.mapped_source_mode, rule.real_destination, rule.mapped_destination,
                          rule.destination_mode, rule.original_service, rule.translated_service,
                          rule.service_protocol, rule.service_operand_1, rule.service_operand_2,
                          rule.owning_object, rule.access_list, rule.pat_pool,
                          rule.pat_pool_options, rule.identity_nat, rule.nat_exemption, rule.dns,
                          rule.no_proxy_arp, rule.route_lookup, rule.unidirectional, rule.inactive,
                          rule.options, item.issues, rule.raw_line)
                sheet.append(tuple(excel_value(value) for value in values))
            continue
        if name == "Routes":
            sheet.append(SHEET_HEADERS[name])
            for item in result.derived.routes.routes:
                sheet.append(tuple(excel_value(value) for value in _row(name, item)))
            continue
        if name == "Interfaces":
            sheet.append(SHEET_HEADERS[name])
            topology = {(item.source_context, item.name.casefold()): item
                        for item in result.derived.interface_topology.interfaces}
            fields = SOURCE_SECTIONS[name][1].split()
            for item in config.interfaces:
                view = topology.get((item.source_context, item.name.casefold()))
                values = (*(getattr(item, field, None) for field in fields), getattr(view, "kind", None),
                          _name(getattr(view, "parent", None)), _name(getattr(view, "aggregate", None)),
                          tuple(_name(value) for value in getattr(view, "physical_interfaces", ())),
                          getattr(view, "issues", ()))
                sheet.append(tuple(excel_value(value) for value in values))
            continue
        if name == "Zones":
            sheet.append(SHEET_HEADERS[name])
            resolved = {}
            for entry in result.derived.interface_topology.interfaces:
                for zone in entry.zones:
                    resolved.setdefault((entry.source_context, _name(zone)), set()).add(entry.name)
            issues = {(getattr(issue, "source_context", None), getattr(issue, "source_object", None))
                      for issue in result.derived.relationship_issues}
            for zone in config.traffic_zones:
                explicit = list(zone.members)
                explicit.extend(interface.name for interface in config.interfaces
                                if interface.source_context == zone.source_context
                                and zone.name in interface.traffic_zone_members)
                explicit = tuple(dict.fromkeys(explicit))
                members = resolved.get((zone.source_context, zone.name), set())
                unresolved = tuple(member for member in explicit if member not in members)
                has_issue = (zone.source_context, zone.name) in issues
                sheet.append((zone.name, zone.source_context, excel_value(explicit),
                              excel_value(tuple(sorted(members))), excel_value(unresolved),
                              excel_value(zone.raw_extra), zone.requires_manual_review or has_issue))
            continue
        if name == "IPS Actions":
            sheet.append(SHEET_HEADERS[name])
            activations = {}
            for relationship in result.derived.mpf_relationships.service_policies:
                policy_map = getattr(relationship.policy_map, "name", None)
                if policy_map:
                    activations.setdefault(policy_map, []).append(
                        getattr(relationship.service_policy, "name", None))
            for policy_map, class_map, action in result.derived.mpf_relationships.external_ips_actions:
                sheet.append((policy_map.name, class_map.class_name, action.mode, action.failure_mode,
                              action.sensor, policy_map.source_context,
                              excel_value(tuple(activations.get(policy_map.name, ()))), None))
            continue
        if name == "Failover":
            sheet.append(("Record Type", "Context", "Source Values"))
            sheet.append(("Failover Configuration", None, excel_value(result.config.failover_config)))
            for item in config.failover_settings:
                sheet.append(("Failover Setting", item.source_context,
                              excel_value({"setting": item.setting})))
            continue
        if name in SOURCE_SECTIONS:
            sheet.append(SHEET_HEADERS[name])
            spec = SOURCE_SECTIONS[name]
            values = getattr(config, spec[0], ()) or ()
            if getattr(type(values), "model_fields", None):
                values = (values,)
            if len(spec) == 3:
                values = (child for parent in values for child in (getattr(parent, spec[1], ()) or ()))
                fields = spec[2].split()
            else:
                fields = spec[1].split()
            if name == "Policy Routing":
                values = (item for item in values if any(getattr(item, key, None)
                          for key in ("policy_route_maps", "policy_route_cost", "policy_route_path_monitors")))
            for item in values:
                sheet.append(tuple(excel_value(getattr(item, field, None)) for field in fields))
            continue
        if name in DERIVED_SECTIONS:
            sheet.append(SHEET_HEADERS[name])
            path = DERIVED_SECTIONS[name].split(".")
            values = result.derived
            for part in path:
                values = getattr(values, part)
            for item in values:
                sheet.append(tuple(excel_value(value) for value in _derived_row(name, item)))
            continue
    if hasattr(output, "write"):
        workbook.save(output)
        return output
    path = Path(output)
    workbook.save(path)
    return path


def _derived_row(sheet: str, item: Any) -> tuple[Any, ...]:
    if sheet == "ACL Bindings":
        return item.acl_name, item.source_context, item.scope, item.interface, item.direction, item.resolved_acl, item.issues
    return _row(sheet, item)


__all__ = ["export_asa_excel"]

