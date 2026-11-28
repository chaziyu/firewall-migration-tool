"""FortiGate Excel row builders grouped away from workbook orchestration.

Rows are derived only from extracted/derived/validation state supplied by the
existing Excel context. No source-model mutation or target inference occurs here.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any, Iterable, Iterator, Mapping, Sequence

from fwmigrate.source_reporting import ExcelExportProfile

from ..extraction.coverage import extraction_status, find_typed_source_object, supports_path
from ..security.extraction import sanitize_source_attributes
from ..transform.policies import effective_policy_action
from ..report_values import address_value, credential_presence, policy_nat_entries, policy_nat_review
from .excel_schema import SHEET_ORDER
from .excel_common import (
    _VISIBLE_MODEL_FIELDS_BY_SHEET,
    _SOURCE_PATHS_BY_SHEET,
    _add_analysis_status,
    _additional_settings,
    _additional_source_settings,
    _enabled_text,
    _excel_value,
    _interface_source_values,
    _model_rows,
    _nat_type,
    _overlay_raw,
    _overlay_safe_raw,
    _safe_command_value,
    _sheet_for_domain,
    _source_category,
)

if TYPE_CHECKING:
    from .excel import _ExcelContext


def rows_for_sheet(
    sheet_name: str,
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterable[Mapping[str, Any]]:
    builders = {
        "Review Required": _review_rows,
        "Review Summary": _review_summary_rows,
        "Interfaces": _interface_rows,
        "Interface Secondary IPs": _interface_secondary_rows,
        "Zones": _zone_rows,
        "Addresses": _address_rows,
        "Wildcard FQDN": _wildcard_fqdn_rows,
        "Address Groups": _address_group_rows,
        "Services": _service_rows,
        "Service Groups": _service_group_rows,
        "Service Categories": _service_category_rows,
        "Derived Service Expansions": _derived_service_rows,
        "One-Time Schedules": _one_time_schedule_rows,
        "Recurring Schedules": _recurring_schedule_rows,
        "Schedule Groups": _schedule_group_rows,
        "Policies": _policy_rows,
        "Security Policies": _security_policy_rows,
        "IP Pools": _ip_pool_rows,
        "Virtual IPs": _vip_rows,
        "VIP Real Servers": _vip_real_server_rows,
        "VIP Groups": _vip_group_rows,
        "NAT Rules": _nat_rows,
        "Routes": _route_rows,
        "VPN Tunnels": _vpn_phase1_rows,
        "Policy IPsec Phase 1": _policy_vpn_phase1_rows,
        "VPN Phase 2": _vpn_phase2_rows,
        "Policy IPsec Phase 2": _policy_vpn_phase2_rows,
        "DHCP Servers": _dhcp_server_rows,
        "DHCP IP Ranges": _dhcp_ip_range_rows,
        "DHCP Exclude Ranges": _dhcp_exclude_range_rows,
        "DHCP Reservations": _dhcp_reservation_rows,
        "SD-WAN": _sdwan_rows,
        "SD-WAN Zones": _sdwan_zone_rows,
        "SD-WAN Members": _sdwan_member_rows,
        "SD-WAN Health Checks": _sdwan_health_rows,
        "SD-WAN Rules": _sdwan_rule_rows,
        "SSL VPN Settings": _ssl_settings_rows,
        "SSL VPN Realms": _ssl_realm_rows,
        "SSL VPN Clients": _ssl_client_rows,
        "SSL VPN Portals": _ssl_portal_rows,
        "SSL VPN Authentication Rules": _ssl_auth_rule_rows,
        "NTP Settings": _ntp_setting_rows,
        "NTP Servers": _ntp_server_rows,
        "Local Users": _local_user_rows,
        "User Groups": _user_group_rows,
        "User Group Matches": _user_group_match_rows,
        "Administrators": _administrator_rows,
        "Admin Profiles": _admin_profile_rows,
        "Admin Profile Permissions": _admin_permission_rows,
        "IPS Sensors": _ips_sensor_rows,
        "IPS Sensor Entries": _ips_entry_rows,
        "IPS Exempt IPs": _ips_exempt_rows,
        "Security Profiles": _security_profile_rows,
        "Antivirus Profiles": _av_profile_rows,
        "Web Filter Profiles": _webfilter_profile_rows,
        "DNS Filter Profiles": _dnsfilter_profile_rows,
        "Application Lists": _application_list_rows,
        "File Filter Profiles": _file_filter_profile_rows,
        "Email Filter Profiles": _emailfilter_profile_rows,
        "VoIP Profiles": _voip_profile_rows,
        "WAF Profiles": _waf_profile_rows,
        "SSL-SSH Profiles": _ssl_ssh_profile_rows,
        "Proxy Policies": _proxy_policy_rows,
        "Auth Policies": _auth_policy_rows,
        "Traffic Shapers": _traffic_shaper_rows,
        "LDB Monitors": _ldb_monitor_rows,
        "High Availability": _ha_rows,
        "SNMP Communities": _snmp_community_rows,
        "SNMP Users": _snmp_user_rows,
        "FortiGuard": _fortiguard_rows,
        "BGP Configuration": _bgp_rows,
        "OSPF Configuration": _ospf_rows,
        "Prefix Lists": _prefix_list_rows,
        "Route Maps": _route_map_rows,
        "Password Policies": _password_policy_rows,
        "Guest Users": _guest_user_rows,
        "Managed FortiAPs": _managed_fortiap_rows,
        "WiFi SSIDs": _wifi_ssid_rows,
        "FortiAP Profiles": _fortiap_profile_rows,
        "WIDS Profiles": _wids_profile_rows,
        "Managed Switches": _managed_switch_rows,
        "Switch Port Policies": _switch_port_policy_rows,
        "NAC Policies": _nac_policy_rows,
        "Syslog Settings": _syslog_setting_rows,
        "External Resources": _external_resource_rows,
        "Unresolved References": _unresolved_reference_rows,
        "Unsupported": _unsupported_rows,
        "Extraction Coverage": _coverage_rows,
    }

    assert builders.keys() <= set(SHEET_ORDER)
    builder = builders.get(sheet_name)

    if builder is not None:
        return builder(context, headers)

    return _generic_source_rows(sheet_name, context, headers)



def _review_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for issue in context.validation.issues:
        row = {
            "Severity": issue.severity.value,
            "Category": issue.domain,
            "Object": issue.object_name,
            "VDOM": issue.vdom,
            "Field": issue.field,
            "Issue / Review Reason": issue.message,
            "Source Sheet": _sheet_for_domain(issue.domain),
        }
        yield row


def _review_summary_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    del headers
    groups: dict[tuple[Any, ...], list[Any]] = {}
    for detail_row, issue in enumerate(context.validation.issues, start=4):
        key = (issue.severity.value, issue.domain, issue.vdom, issue.field, issue.message)
        groups.setdefault(key, []).append((detail_row, issue.object_name))
    for key in sorted(groups, key=lambda value: tuple("" if part is None else str(part) for part in value)):
        details = groups[key]
        objects = list(dict.fromkeys(name for _, name in details))
        object_sample = ", ".join(map(str, [name for name in objects if name not in (None, "")][:5]))
        yield {
            "Issue Group": " | ".join(str(part) for part in key if part not in (None, "")),
            "Severity": key[0], "Category": key[1], "VDOM": key[2], "Field": key[3],
            "Issue / Review Reason": key[4], "Occurrences": len(details),
            "Affected Objects": len(objects), "Object Sample": object_sample,
            "First Detail": f"Review Required!A{details[0][0]}",
        }


def _interface_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    topology = {(item.vdom, item.name): item for item in context.derived.topology.interfaces}
    interfaces = {(item.vdom, item.name): item for item in context.config.interfaces}
    aggregate_members: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    children: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    owned: set[tuple[str, str]] = set()
    for interface in context.config.interfaces:
        key = (interface.vdom, interface.name)
        if interface.interface and (interface.vdom, interface.interface) in interfaces:
            children[(interface.vdom, interface.interface)].append(key)
        for member in interface.members:
            member_key = (interface.vdom, member)
            aggregate_members[key].append(member_key)
            owned.add(member_key)

    vpns_by_interface: dict[tuple[str, str], list[Any]] = defaultdict(list)
    vpns = {(item.vdom, item.name): item for item in context.config.ipsec_phase1}
    for vpn in context.derived.topology.vpns:
        if vpn.attached_interface:
            vpns_by_interface[(vpn.vdom, vpn.attached_interface)].append(vpn)

    def rank(key: tuple[str, str]) -> tuple[int, str]:
        return _interface_rank(topology.get(key), interfaces[key])

    roots = sorted(
        (key for key in interfaces if key not in owned and not interfaces[key].interface),
        key=rank,
    )
    zones_by_interface: dict[tuple[str, str], list[str]] = defaultdict(list)
    for zone in context.config.zones:
        for member in zone.members:
            zones_by_interface[(zone.vdom, member)].append(zone.name)
    visited: set[tuple[str, str]] = set()
    emitted_vpns: set[tuple[str, str]] = set()

    def emit_vpn(vpn_top: Any, prefix: str = "") -> Iterator[dict[str, Any]]:
        vpn_key = (vpn_top.vdom, vpn_top.name)
        if vpn_key in emitted_vpns:
            return
        emitted_vpns.add(vpn_key)
        vpn = vpns.get(vpn_key)
        if vpn is None:
            return
        row = {
            "Name": f"{prefix}{_topology_symbol('vpn')} {vpn.name}",
            "Type": vpn.type,
            "Parent Interface": vpn_top.attached_interface,
            "Aggregate": vpn_top.aggregate,
            "Physical Interfaces": list(vpn_top.physical_interfaces),
            "Topology Path": list(vpn_top.path),
            "VDOM": vpn.vdom,
            "Topology Issues": list(vpn_top.issues),
            "Source Explicit Fields": sorted(vpn.explicit_fields),
            "Additional Settings": sanitize_source_attributes(vpn.raw_extra),
        }
        _add_analysis_status(
            row,
            context,
            vdom=vpn.vdom,
            names=(vpn.name,),
            domains=("ipsec_phase1", "vpn_topology"),
            extra_reasons=vpn_top.issues,
        )
        _overlay_safe_raw(row, row["Additional Settings"], headers)
        yield row

    def emit_interface(
        key: tuple[str, str], prefix: str = "", child_indent: str = ""
    ) -> Iterator[dict[str, Any]]:
        if key in visited:
            return
        visited.add(key)
        interface = interfaces[key]
        key = (interface.vdom, interface.name)
        top = topology.get(key)
        row = {
            "Name": f"{prefix}{_topology_symbol(top.kind if top else None)} {interface.name}",
            "Alias": interface.alias,
            "Zone": zones_by_interface.get(key, []),
            "IP / Prefix": interface.ip,
            "Type": interface.type,
            "Role": interface.role,
            "Addressing Mode": interface.mode,
            "Management Access": interface.allowaccess,
            "VLAN ID": interface.vlanid,
            "Parent Interface": interface.interface,
            "Aggregate": top.aggregate if top else None,
            "Physical Interfaces": list(top.physical_interfaces) if top else [],
            "Topology Path": list(top.path) if top else [interface.name],
            "Members": interface.members,
            "Status": _enabled_text(interface.status),
            "Description": interface.description,
            "VDOM": interface.vdom,
            "Topology Issues": list(top.issues) if top else [],
            "Source Explicit Fields": sorted(interface.explicit_fields),
            "Additional Settings": sanitize_source_attributes(interface.raw_extra),
        }

        _add_analysis_status(
            row,
            context,
            vdom=interface.vdom,
            names=(interface.name,),
            domains=("interface", "interface_topology"),
        )
        source_values = _interface_source_values(
            context,
            vdom=interface.vdom,
            name=interface.name,
        )

        row["Secondary IPv4 Addresses"] = [secondary.ip for secondary in interface.secondary_ips if secondary.ip]
        _overlay_safe_raw(row, source_values, headers)
        row["Additional Settings"] = _additional_source_settings(
            source_values,
            row,
            headers,
        )
        yield row

        child_keys = tuple(aggregate_members.get(key, ())) + tuple(children.get(key, ()))
        child_keys = tuple(sorted((item for item in dict.fromkeys(child_keys) if item in interfaces), key=rank))
        vpn_children = tuple(vpns_by_interface.get(key, ()))
        children_count = len(child_keys) + len(vpn_children)
        child_number = 0
        for child_key in child_keys:
            child_number += 1
            last = child_number == children_count
            yield from emit_interface(
                child_key,
                child_indent + ("└─ " if last else "├─ "),
                child_indent + ("   " if last else "│  "),
            )
        for vpn_top in vpn_children:
            child_number += 1
            last = child_number == children_count
            yield from emit_vpn(vpn_top, child_indent + ("└─ " if last else "├─ "))

    for key in roots:
        yield from emit_interface(key)
    for key in sorted(interfaces, key=rank):
        yield from emit_interface(key)
    for vpn_top in context.derived.topology.vpns:
        if (vpn_top.vdom, vpn_top.name) not in emitted_vpns:
            yield from emit_vpn(vpn_top)


def _interface_rank(topology: Any, interface: Any) -> tuple[int, str]:
    return (
        {"aggregate": 0, "physical": 1, "vlan": 2, "logical": 3, "tunnel": 4}.get(
            topology.kind if topology else None,
            5,
        ),
        interface.name,
    )


def _topology_symbol(kind: str | None) -> str:
    return {"aggregate": "◆", "physical": "●", "vlan": "▣", "logical": "◇", "tunnel": "◇", "vpn": "◈"}.get(kind, "◇")


def _interface_secondary_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for interface in context.config.interfaces:
        for item in interface.secondary_ips:
            row = {
                "Interface": interface.name,
                "ID": item.id,
                "IP / Prefix": item.ip,
                "Management Access": item.allowaccess,
                "HA Priority": item.ha_priority,
                "VDOM": interface.vdom,
                "Additional Settings": _additional_settings(item, sheet_name="Interface Secondary IPs"),
            }
            _add_analysis_status(
                row,
                context,
                vdom=interface.vdom,
                names=(interface.name, item.id),
            )
            _overlay_safe_raw(row, row["Additional Settings"], headers)
            yield row


def _zone_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for item in context.config.zones:
        row = {
            "Name": item.name,
            "Members": item.members,
            "Description": item.description,
            "Intrazone": item.intrazone,
            "VDOM": item.vdom,
            "Additional Settings": _additional_settings(item, sheet_name="Zones"),
        }
        _add_analysis_status(row, context, vdom=item.vdom, names=(item.name,), domains=('zone',))
        _overlay_safe_raw(row, row["Additional Settings"], headers)
        yield row


def _address_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for item in context.config.addresses:
        value = address_value(item)
        row = {
            "Name": item.name,
            "Type": item.type,
            "Value": value,
            "Source Explicit Fields": sorted(item.explicit_fields),
            "Address Family": item.address_family,
            "Associated Interface": item.associated_interface,
            "Allow Routing": item.allow_routing,
            "Tags": [
                tag
                for entry in item.tagging
                for tag in entry.tags
            ],
            "Description": item.comment,
            "VDOM": item.vdom,
            "Additional Settings": sanitize_source_attributes(item.raw_extra),
        }
        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.name,),
            domains=("address6",) if item.address_family == "ipv6" else ("address",),
            extra_reasons=(value,) if value and value.startswith(("Unknown:", "Unsupported address type:", "Ambiguous:")) else (),
        )
        _overlay_safe_raw(row, row["Additional Settings"], headers)
        yield row


def _wildcard_fqdn_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for item in context.config.wildcard_fqdns:
        row = {
            "Name": item.name,
            "Wildcard FQDN": item.wildcard_fqdn,
            "Description": item.comment,
            "VDOM": item.vdom,
            "Additional Settings": sanitize_source_attributes(item.raw_extra),
        }
        _add_analysis_status(row, context, vdom=item.vdom, names=(item.name,), domains=('wildcard_fqdn',))
        yield row


def _address_group_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for item in context.config.address_groups:
        row = {
            "Name": item.name,
            "Members": item.members,
            "Address Family": item.address_family,
            "Exclusion Enabled": item.exclude,
            "Exclude Members": item.exclude_members,
            "Description": item.comment,
            "Allow Routing": item.allow_routing,
            "Group Type": item.type,
            "Tags": [tag for entry in item.tagging for tag in entry.tags],
            "VDOM": item.vdom,
            "Additional Settings": sanitize_source_attributes(item.raw_extra),
        }
        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.name,),
            domains=("address_group6",)
            if item.address_family == "ipv6"
            else ("address_group",),
        )
        _overlay_safe_raw(row, row["Additional Settings"], headers)
        yield row


def _service_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    yield from _model_rows(context, context.config.services, headers, {
        "Name": "name", "Protocol": "protocol", "TCP Port Range": "tcp_portrange",
        "UDP Port Range": "udp_portrange", "SCTP Port Range": "sctp_portrange",
        "Protocol Number": "protocol_number", "ICMP Type": "icmptype", "ICMP Code": "icmpcode",
        "Category": "category", "Proxy": "proxy", "Session TTL": "session_ttl",
        "Description": "comment", "VDOM": "vdom",
    }, domains=("service",))


def _service_group_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    yield from _model_rows(context, context.config.service_groups, headers, {
        "Name": "name", "Members": "members", "Proxy": "proxy",
        "Description": "comment", "VDOM": "vdom",
    }, domains=("service_group",))


def _service_category_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    yield from _model_rows(context, context.config.service_categories, headers, {
        "Name": "name", "Description": "comment", "VDOM": "vdom",
    }, domains=("service_category",))


def _one_time_schedule_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    yield from _model_rows(context, context.config.one_time_schedules, headers, {
        "Name": "name", "Start": "start", "End": "end", "Start UTC": "start_utc",
        "End UTC": "end_utc", "Expiration Days": "expiration_days", "Color": "color",
        "Fabric Object": "fabric_object", "VDOM": "vdom",
    }, domains=("schedule", "schedule_onetime"))


def _recurring_schedule_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    yield from _model_rows(context, context.config.recurring_schedules, headers, {
        "Name": "name", "Days": "days", "Start": "start", "End": "end",
        "Color": "color", "Fabric Object": "fabric_object", "VDOM": "vdom",
    }, domains=("schedule", "schedule_recurring"))


def _schedule_group_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    yield from _model_rows(context, context.config.schedule_groups, headers, {
        "Name": "name", "Members": "members", "Color": "color",
        "Fabric Object": "fabric_object", "VDOM": "vdom",
    }, domains=("schedule_group",))


def _derived_service_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    source = {(item.vdom, item.name): item for item in context.config.services}
    for item in context.derived.services.services:
        source_item = source.get((item.vdom, item.source_name or item.name))
        row = {
            "Name": item.name,
            "Source Service": item.source_name,
            "Object Type": "Service",
            "Origin": "Derived",
            "Protocol": item.protocol,
            "Destination Port": item.port,
            "Source Port": item.source_port,
            "Protocol Number": item.protocol_number,
            "ICMP Type": item.icmp_type,
            "ICMP Code": item.icmp_code,
            "Generated": item.generated,
            "Description": item.comment,
            "VDOM": item.vdom,
        }
        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.source_name, item.name),
            domains=('service',),
        )
        if source_item is not None:
            _overlay_raw(row, source_item.raw_extra, headers)
        yield row

    source = {(item.vdom, item.name): item for item in context.config.service_groups}
    for item in context.derived.services.groups:
        source_item = source.get((item.vdom, item.name))
        row = {
            "Name": item.name,
            "Object Type": "Service Group",
            "Origin": "Derived",
            "Members": list(item.members) if item.members is not None else None,
            "Generated": item.generated,
            "Description": item.comment,
            "VDOM": item.vdom,
        }
        _add_analysis_status(row, context, vdom=item.vdom, names=(item.name,), domains=('service_group', 'service'))
        if source_item is not None:
            _overlay_raw(row, source_item.raw_extra, headers)
        yield row


def _policy_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    order_by_identity = _policy_orders(context)
    counts, nat = policy_nat_entries(context.config, context.derived)
    for item in context.config.policies:
        key = (item.vdom, item.policy_id)
        entries = nat.get(key, ())
        reasons = policy_nat_review(key, counts, entries)
        nat_items = entries if item.policy_id is not None and counts[key] == 1 else ()
        row = {
            "Rule #": item.policy_id,
            "Policy Order": order_by_identity.get((item.vdom, item.policy_id)),
            "Action Origin": "EXPLICIT" if "action" in item.explicit_fields else "FORTIOS_DEFAULT",
            "Policy Name": item.name,
            "Source Name": item.name,
            "Source Interface": item.srcintf,
            "Source Addresses": item.srcaddr,
            "Source IPv6 Addresses": item.srcaddr6,
            "Source IPv6 Address Negate": item.srcaddr6_negate,
            "Destination Interface": item.dstintf,
            "Destination Addresses": item.dstaddr,
            "Destination IPv6 Addresses": item.dstaddr6,
            "Destination IPv6 Address Negate": item.dstaddr6_negate,
            "Services": item.service,
            "Action": effective_policy_action(item.action),
            "Schedule": item.schedule,
            "NAT Enabled": _enabled_text(item.nat),
            "UTM Status": item.utm_status,
            "Source Address Negate": item.srcaddr_negate,
            "Destination Address Negate": item.dstaddr_negate,
            "User Groups": item.groups,
            "Users": item.users,
            "Service Negate": item.service_negate,
            "VPN Tunnel": item.vpntunnel,
            "Security Profile Group": item.profile_group,
            "Protocol Options": item.profile_protocol_options,
            "Per-IP Shaper": item.per_ip_shaper,
            "Antivirus": item.av_profile,
            "IPS Sensor": item.ips_sensor,
            "Web Filter": item.webfilter_profile,
            "Application List": item.application_list,
            "DNS Filter": item.dnsfilter_profile,
            "SSL/SSH Profile": item.ssl_ssh_profile,
            "Log Setting": item.logtraffic,
            "Comments": item.comments,
            "Status": _enabled_text(item.status),
            "SNAT Type": "; ".join(_nat_type(entry.translation_type) for entry in nat_items) or None,
            "SNAT Address": (list(nat_items[0].translated_addresses) if len(nat_items) == 1 else
                [f"{_nat_type(entry.translation_type)}: {', '.join(entry.translated_addresses) or 'Not specified'}" for entry in nat_items]),
            "IP Pool Name": (list(nat_items[0].pool_names) if len(nat_items) == 1 else
                [f"{_nat_type(entry.translation_type)}: {', '.join(entry.pool_names) or 'Not specified'}" for entry in nat_items]),
            "VDOM": item.vdom,
            "Source Explicit Fields": sorted(item.explicit_fields),
            "Additional Settings": _additional_settings(
                item,
                represented_fields=_VISIBLE_MODEL_FIELDS_BY_SHEET["Policies"],
            ),
        }
        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.name, item.policy_id),
            domains=('policy', 'nat'),
            extra_reasons=reasons,
        )
        _overlay_safe_raw(row, row["Additional Settings"], headers)
        yield row


def _security_policy_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    return _model_rows(
        context, context.config.security_policies, headers,
        {"Policy ID": "policy_id", "Action": "action", "Application Categories": "app_category", "VDOM": "vdom"},
        domains=("security_policy",),
    )


def _ip_pool_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        [*context.config.ip_pools, *context.config.ip_pools6],
        headers,
        {
            "Name": "name",
            "Address Family": "address_family",
            "Type": "type",
            "Start IP": "startip",
            "End IP": "endip",
            "Source Start IP": "source_startip",
            "Source End IP": "source_endip",
            "Start Port": "startport",
            "End Port": "endport",
            "VDOM": "vdom",
            "Associated Interface": "associated_interface",
            "ARP Reply": "arp_reply",
            "ARP Interface": "arp_intf",
            "Permit Any Host": "permit_any_host",
            "Excluded IPs": "exclude_ip",
            "NAT64": "nat64",
            "Add NAT64 Route": "add_nat64_route",
            "NAT46": "nat46",
            "Add NAT46 Route": "add_nat46_route",
            "Description": "comments",
            "Comments": "comments",
            "Source Explicit Fields": "explicit_fields",
        },
        domains=('ip_pool', 'ip_pool6'),
    )
def _vip_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        [*context.config.vips, *context.config.vips6],
        headers,
        {
            "Name": "name",
            "Address Family": "address_family",
            "Type": "type",
            "Status": "status",
            "External IP": "extip",
            "External Address Objects": "extaddr",
            "External Interface": "extintf",
            "Mapped IPs": "mappedip",
            "Real Servers": lambda item: [
                ":".join(
                    str(value)
                    for value in (server.ip or server.address, server.port)
                    if value is not None
                )
                for server in getattr(item, "realservers", [])
            ],
            "Real Server Count": lambda item: len(getattr(item, "realservers", [])),
            "Port Forward": "portforward",
            "Protocol": "protocol",
            "External Port": "extport",
            "Mapped Port": "mappedport",
            "ARP Reply": "arp_reply",
            "NAT Source VIP": "nat_source_vip",
            "NAT64": "nat64",
            "NAT66": "nat66",
            "NDP Reply": "ndp_reply",
            "Services": "service",
            "Load Balance Method": "ldb_method",
            "Server Type": "server_type",
            "Monitors": "monitor",
            "Description": "comment",
            "VDOM": "vdom",
        },
        domains=('vip', 'vip6'),
    )
def _vip_real_server_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterator[dict[str, Any]]:

    for vip in context.config.vips:
        for item in vip.realservers:
            row = {
                "VIP Name": vip.name,
                "Server ID": item.id,
                "IP": item.ip,
                "Address": item.address,
                "Port": item.port,
                "Status": item.status,
                "Weight": item.weight,
                "Monitors": item.monitor,
                "VDOM": vip.vdom,
                "Additional Settings": _additional_settings(item, sheet_name="VIP Real Servers"),
            }
            _add_analysis_status(
                row,
                context,
                vdom=vip.vdom,
                names=(vip.name, item.id),
                domains=('vip',),
            )
            _overlay_safe_raw(row, row["Additional Settings"], headers)
            yield row


def _vip_group_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        [*context.config.vip_groups, *context.config.vip_groups6],
        headers,
        {
            "Name": "name",
            "Address Family": "address_family",
            "Interface": "interface",
            "Members": "members",
            "Comments": "comments",
            "VDOM": "vdom",
        },
        domains=('vip_group', 'vip_group6'),
    )
def _nat_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterator[dict[str, Any]]:
    order_by_identity = _policy_orders(context)
    policies = {
        (policy.vdom, policy.policy_id): policy
        for policy in context.config.policies
        if policy.policy_id is not None and isinstance(order_by_identity.get((policy.vdom, policy.policy_id)), int)
    }

    for item in context.derived.nat:
        policy = policies.get(
            (item.vdom, item.policy_id)
        )

        row = {
            "Rule #": item.policy_id,
            "Policy Order": order_by_identity.get((item.vdom, item.policy_id)),
            "Policy Name": item.policy_name,
            "Source Interface": (
                policy.srcintf
                if policy is not None
                else []
            ),
            "Destination Interface": (
                policy.dstintf
                if policy is not None
                else list(item.egress_interfaces)
            ),
            "Source Addresses": (
                policy.srcaddr
                if policy is not None
                else []
            ),
            "Source IPv6 Addresses": (
                policy.srcaddr6
                if policy is not None
                else []
            ),
            "Destination Addresses": (
                policy.dstaddr
                if policy is not None
                else []
            ),
            "Destination IPv6 Addresses": (
                policy.dstaddr6
                if policy is not None
                else []
            ),
            "Services": (
                policy.service
                if policy is not None
                else []
            ),
            "NAT Enabled": _enabled_text(policy.nat) if policy is not None else None,
            "SNAT Type": _nat_type(item.translation_type),
            "SNAT Address": list(item.translated_addresses),
            "IP Pool Name": list(item.pool_names),
            "Egress Interfaces": list(
                item.egress_interfaces
            ),
            "VDOM": item.vdom,
        }

        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(
                item.policy_name,
                item.policy_id,
            ),
            extra_reasons=(
                (*item.issues, "Ambiguous policy identity; source policy fields were not joined.")
                if policy is None
                else item.issues
            ),
            domains=('nat',),
        )
        yield row


def _policy_orders(context: _ExcelContext) -> dict[tuple[str, int], int | str]:
    cached = getattr(context, "_policy_orders_cache", None)
    if cached is not None:
        return cached
    counts: dict[tuple[str, int], int] = defaultdict(int)
    orders: dict[tuple[str, int], int] = {}
    vdom_positions: dict[str, int] = defaultdict(int)
    for policy in context.config.policies:
        identity = (policy.vdom, policy.policy_id)
        counts[identity] += 1
        vdom_positions[policy.vdom] += 1
        orders[identity] = vdom_positions[policy.vdom]
    result = {
        identity: order if identity[1] is not None and counts[identity] == 1 else "Ambiguous identity"
        for identity, order in orders.items()
    }
    context._policy_orders_cache = result
    return result


def _route_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterator[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.static_routes,
        headers,
        {
            "Route ID": "seq_num",
            "Destination": "dst",
            "Destination Address Object": "dstaddr",
            "Interface": "device",
            "Gateway": "gateway",
            "Distance": "distance",
            "Priority": "priority",
            "Status": "status",
            "SD-WAN Zone": "sdwan_zone",
            "Preferred Source": "preferred_source",
            "Source Prefix": "src",
            "Dynamic Gateway": "dynamic_gateway",
            "Blackhole": "blackhole",
            "Description": "comment",
            "Address Family": "address_family",
            "VDOM": "vdom",
        },
        domains=('static_route', 'static_route6'),
    )
def _vpn_phase1_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterator[dict[str, Any]]:
    topology = {
        (item.vdom, item.name): item
        for item in context.derived.topology.vpns
    }

    for item in context.config.ipsec_phase1:
        top = topology.get(
            (item.vdom, item.name)
        )

        row = {
            "Name": item.name,
            "Local Interface": item.interface,
            "Remote Gateway IPv4": item.remote_gw,
            "Remote Gateway DDNS": item.remotegw_ddns,
            "Type": item.type,
            "IKE Version": item.ike_version,
            "IKE Mode": item.mode,
            "Authentication Method": item.authmethod,
            "Remote Authentication Method": item.authmethod_remote,
            "PSK Configured": credential_presence(item.psk_configured),
            "PPK Secret Configured": credential_presence(item.ppk_secret_configured),
            "Auth Password Configured": credential_presence(item.auth_password_configured),
            "Group Authentication Secret Configured": credential_presence(item.group_authentication_secret_configured),
            "Phase 1 Proposal": item.proposal,
            "Phase 1 DH Groups": item.dhgrp,
            "Key Lifetime (Seconds)": item.keylife,
            "NAT Traversal": item.nattraversal,
            "DPD Mode": item.dpd,
            "DPD Retry Count": item.dpd_retrycount,
            "DPD Retry Interval": item.dpd_retryinterval,
            "Local Gateway": item.local_gw,
            "Local ID": item.localid,
            "Local ID Type": item.localid_type,
            "Peer ID": item.peerid,
            "Certificate": item.certificate,
            "Description": item.comments,
            "VDOM": item.vdom,
            "Aggregate": (
                top.aggregate
                if top
                else None
            ),
            "Attached Physical Interfaces": (
                list(top.physical_interfaces)
                if top
                else []
            ),
            "Topology Path": (
                list(top.path)
                if top
                else []
            ),
            "Topology Issues": (
                list(top.issues)
                if top
                else []
            ),
            "Source Explicit Fields": sorted(
                item.explicit_fields
            ),
            "Additional Settings": _additional_settings(item, sheet_name="VPN Tunnels"),
        }

        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.name,),
            domains=("ipsec_phase1", "vpn_topology"),
            extra_reasons=(
                top.issues
                if top
                else ()
            ),
        )

        _overlay_safe_raw(row, row["Additional Settings"], headers)

        yield row


def _policy_vpn_phase1_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.ipsec_policy_phase1,
        headers,
        {
            "Name": "name",
            "Remote Gateway IPv4": "remote_gw",
            "Remote Gateway DDNS": "remotegw_ddns",
            "IKE Version": "ike_version",
            "IKE Mode": "mode",
            "Authentication Method": "authmethod",
            "Remote Authentication Method": "authmethod_remote",
            "PSK Configured": lambda item: credential_presence(item.psk_configured),
            "PPK Secret Configured": lambda item: credential_presence(item.ppk_secret_configured),
            "Auth Password Configured": lambda item: credential_presence(item.auth_password_configured),
            "Group Authentication Secret Configured": lambda item: credential_presence(item.group_authentication_secret_configured),
            "Phase 1 Proposal": "proposal",
            "Phase 1 DH Groups": "dhgrp",
            "Key Lifetime (Seconds)": "keylife",
            "NAT Traversal": "nattraversal",
            "DPD Mode": "dpd",
            "DPD Retry Count": "dpd_retrycount",
            "DPD Retry Interval": "dpd_retryinterval",
            "Local Gateway": "local_gw",
            "Local ID": "localid",
            "Peer ID": "peerid",
            "Certificate": "certificate",
            "Description": "comments",
            "VDOM": "vdom",
        },
        domains=("ipsec_policy_phase1",),
    )


def _vpn_phase2_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterator[dict[str, Any]]:
    normalized = {
        (item.vpn_type, item.vdom, item.name): item
        for item in context.derived.vpn.phase2
    }

    for item in context.config.ipsec_phase2:
        norm = normalized.get(
            ("route-based", item.vdom, item.name)
        )

        row = {
            "Name": item.name,
            "Phase 1": item.phase1name,
            "Proposal": item.proposal,
            "PFS": item.pfs,
            "DH Groups": item.dhgrp,
            "Key Lifetime Seconds": item.keylifeseconds,
            "Key Lifetime KB": item.keylifekbs,
            "Source Range": (
                norm.source_range
                if norm
                else None
            ),
            "Destination Range": (
                norm.destination_range
                if norm
                else None
            ),
            "Source Range IPv6": norm.source_range6 if norm else None,
            "Destination Range IPv6": norm.destination_range6 if norm else None,
            "Protocol": item.protocol,
            "Source Port": item.src_port,
            "Destination Port": item.dst_port,
            "Auto Negotiate": item.auto_negotiate,
            "VDOM": item.vdom,
            "Comments": item.comments,
            "Source Explicit Fields": sorted(
                item.explicit_fields
            ),
            "Additional Settings": _additional_settings(item, sheet_name="VPN Phase 2"),
        }

        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.name,),
            domains=("vpn_phase2",),
        )

        _overlay_safe_raw(row, row["Additional Settings"], headers)

        yield row


def _policy_vpn_phase2_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    normalized = {(item.vpn_type, item.vdom, item.name): item for item in context.derived.vpn.phase2}
    for item in context.config.ipsec_policy_phase2:
        norm = normalized.get(("policy-based", item.vdom, item.name))
        row = {
            "Name": item.name, "Phase 1": item.phase1name, "Proposal": item.proposal,
            "PFS": item.pfs, "DH Groups": item.dhgrp, "Key Lifetime Seconds": item.keylifeseconds,
            "Key Lifetime KB": item.keylifekbs, "Source Range": norm.source_range if norm else None,
            "Destination Range": norm.destination_range if norm else None,
            "Source Range IPv6": norm.source_range6 if norm else None,
            "Destination Range IPv6": norm.destination_range6 if norm else None,
            "Protocol": item.protocol, "Source Port": item.src_port, "Destination Port": item.dst_port,
            "Auto Negotiate": item.auto_negotiate, "Comments": item.comments, "VDOM": item.vdom,
            "Source Explicit Fields": sorted(item.explicit_fields),
            "Additional Settings": _additional_settings(item, sheet_name="Policy IPsec Phase 2"),
        }
        _add_analysis_status(row, context, vdom=item.vdom, names=(item.name,), domains=("ipsec_policy_phase2",))
        _overlay_safe_raw(row, row["Additional Settings"], headers)
        yield row
    return


def _dhcp_server_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.dhcp_servers,
        headers,
        {
            "Server ID": "id",
            "Interface": "interface",
            "Status": "status",
            "Server Type": "server_type",
            "IP Mode": "ip_mode",
            "Default Gateway": "default_gateway",
            "Netmask": "netmask",
            "Lease Time": "lease_time",
            "DNS Service": "dns_service",
            "DNS Server 1": "dns_server1",
            "DNS Server 2": "dns_server2",
            "DNS Server 3": "dns_server3",
            "DNS Server 4": "dns_server4",
            "Timezone Option": "timezone_option",
            "Timezone": "timezone",
            "Relay Agent": "relay_agent",
            "VDOM": "vdom",
        },
        domains=('dhcp_server',),
    )
def _dhcp_ip_range_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    return _dhcp_child_rows(context, headers, "ip_ranges")


def _dhcp_exclude_range_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    return _dhcp_child_rows(context, headers, "exclude_ranges")


def _dhcp_reservation_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for server in context.config.dhcp_servers:
        for item in server.reserved_addresses:
            row = {
                "Server ID": server.id,
                "Interface": server.interface,
                "Reservation ID": item.id,
                "IP Address": item.ip,
                "MAC Address": item.mac,
                "Description": item.description,
                "Action": item.action,
                "Type": item.type,
                "VDOM": server.vdom,
                "Extraction Status": "EXTRACTED",
                "Source Explicit Fields": sorted(item.explicit_fields),
                "Additional Settings": _additional_settings(item, sheet_name="DHCP Reservations"),
            }
            _overlay_safe_raw(row, row["Additional Settings"], headers)
            _add_analysis_status(row, context, vdom=server.vdom, names=(server.id, item.id), domains=('dhcp_server',))
            yield row


def _dhcp_child_rows(
    context: _ExcelContext,
    headers: Sequence[str],
    attribute: str,
) -> Iterator[dict[str, Any]]:
    for server in context.config.dhcp_servers:
        for item in getattr(server, attribute):
            row = {
                "Server ID": server.id,
                "Interface": server.interface,
                "Range ID": item.id,
                "Source ID": item.id,
                "Start IP": item.start_ip,
                "End IP": item.end_ip,
                "Lease Time": item.lease_time,
                "VDOM": server.vdom,
                "Extraction Status": "EXTRACTED",
                "Manual Review": "No",
                "Source Explicit Fields": sorted(item.explicit_fields),
                "Additional Settings": _additional_settings(
                    item,
                    sheet_name="DHCP IP Ranges" if attribute == "ip_ranges" else "DHCP Exclude Ranges",
                ),
            }
            _overlay_safe_raw(row, row["Additional Settings"], headers)
            _add_analysis_status(row, context, vdom=server.vdom, names=(server.id, item.id), domains=('dhcp_server',))
            yield row


def _sdwan_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for item in context.config.sdwans:
        row = {
            "Status": item.status if "status" in item.explicit_fields and item.status is not None else "Not explicitly configured",
            "Load Balance Mode": item.load_balance_mode,
            "Extraction Status": "EXTRACTED",
            "Manual Review": "No",
            "Additional Settings": _additional_settings(item, sheet_name="SD-WAN"),
            "VDOM": item.vdom,
        }
        _overlay_safe_raw(row, row["Additional Settings"], headers)
        _add_analysis_status(row, context, vdom=item.vdom, names=(item.vdom,))
        yield row


def _sdwan_zone_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for sdwan in context.config.sdwans:
        for item in sdwan.zones:
            row = {
                "Zone Name": item.name,
                "Additional Settings": _additional_settings(item, sheet_name="SD-WAN Zones"),
                "VDOM": sdwan.vdom,
            }
            _overlay_safe_raw(row, row["Additional Settings"], headers)
            _add_analysis_status(row, context, vdom=sdwan.vdom, names=(item.name,))
            yield row


def _sdwan_member_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    topology = {(item.vdom, item.name): item for item in context.derived.topology.interfaces}
    for sdwan in context.config.sdwans:
        for item in sdwan.members:
            top = topology.get((sdwan.vdom, item.interface or ""))
            row = {
                "ID": item.seq_num,
                "Interface": item.interface,
                "Zone": item.zone,
                "Gateway": item.gateway,
                "Source": item.source,
                "Cost": item.cost,
                "Weight": item.weight,
                "Priority": item.priority,
                "Status": item.status,
                "Additional Settings": _additional_settings(item, sheet_name="SD-WAN Members"),
                "VDOM": sdwan.vdom,
                "Physical Interfaces": list(top.physical_interfaces) if top else [],
                "Aggregate": top.aggregate if top else None,
                "Source Explicit Fields": sorted(item.explicit_fields),
            }
            _overlay_safe_raw(row, row["Additional Settings"], headers)
            _add_analysis_status(row, context, vdom=sdwan.vdom, names=(item.interface, item.seq_num), domains=('sdwan_member',))
            yield row


def _sdwan_health_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for sdwan in context.config.sdwans:
        for item in sdwan.health_checks:
            first_sla = item.sla[0] if item.sla else None
            row = {
                "Name": item.name,
                "Server": item.server,
                "System DNS": item.system_dns,
                "Members": item.members,
                "Protocol": item.protocol,
                "Interval": item.interval,
                "Fail Time": item.failtime,
                "Recovery Time": item.recoverytime,
                "Latency (ms)": item.latency_threshold if item.latency_threshold is not None else (first_sla.latency_threshold if first_sla else None),
                "Jitter (ms)": item.jitter_threshold if item.jitter_threshold is not None else (first_sla.jitter_threshold if first_sla else None),
                "Packet Loss (%)": item.packetloss_threshold if item.packetloss_threshold is not None else (first_sla.packetloss_threshold if first_sla else None),
                "Additional Settings": _additional_settings(item, sheet_name="SD-WAN Health Checks"),
                "VDOM": sdwan.vdom,
            }
            _overlay_safe_raw(row, row["Additional Settings"], headers)
            _add_analysis_status(row, context, vdom=sdwan.vdom, names=(item.name,))
            yield row


def _sdwan_rule_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for sdwan in context.config.sdwans:
        for item in sdwan.services:
            row = {
                "ID": item.id,
                "Name": item.name,
                "Status": item.status,
                "Mode": item.mode,
                "Link Cost Factor": item.link_cost_factor,
                "Source": item.src,
                "Destination": item.dst,
                "Protocol": item.protocol,
                "Start Port": item.start_port,
                "End Port": item.end_port,
                "Priority Members": item.priority_members,
                "Health Checks": item.health_check,
                "Priority Zones": item.priority_zone,
                "Additional Settings": _additional_settings(item, sheet_name="SD-WAN Rules"),
                "VDOM": sdwan.vdom,
            }
            _overlay_safe_raw(row, row["Additional Settings"], headers)
            _add_analysis_status(row, context, vdom=sdwan.vdom, names=(item.id, item.name))
            yield row


def _ssl_settings_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.ssl_vpn_settings,
        headers,
        {
            "Status": "status",
            "Minimum Protocol": "ssl_min_proto_ver",
            "Maximum Protocol": "ssl_max_proto_ver",
            "Authentication Timeout": "auth_timeout",
            "Idle Timeout": "idle_timeout",
            "Port": "port",
            "DNS Server 1": "dns_server1",
            "DNS Server 2": "dns_server2",
            "Server Certificate": "servercert",
            "Source Interfaces": "source_interface",
            "Source Addresses": "source_address",
            "Tunnel IP Pools": "tunnel_ip_pools",
            "Default Portal": "default_portal",
            "VDOM": "vdom",
        },
        domains=('ssl_settings',),
    )


def _ssl_realm_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    rows = list(_model_rows(context, context.config.ssl_vpn_realms, headers, {
        "URL Path": "url_path",
        "Login Page Configured": lambda item: bool(item.login_page),
        "Login Page Length": lambda item: len(item.login_page or ""),
        "Maximum Concurrent Users": "max_concurrent_user",
        "NAS IP": "nas_ip", "RADIUS Port": "radius_port", "RADIUS Server": "radius_server",
        "Virtual Host": "virtual_host", "Virtual Host Only": "virtual_host_only",
        "Virtual Host Server Certificate": "virtual_host_server_cert", "VDOM": "vdom",
    }, domains=("ssl_vpn_realm",)))
    for row in rows:
        settings = row.get("Additional Settings")
        if isinstance(settings, dict):
            settings.pop("login_page", None)
    return rows


def _ssl_client_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    return _model_rows(context, context.config.ssl_vpn_clients, headers, {
        "Name": "name", "Certificate": "certificate", "Class ID": "class_id", "Comment": "comment",
        "Distance": "distance", "Interface": "interface", "IPv4 Subnets": "ipv4_subnets",
        "IPv6 Subnets": "ipv6_subnets", "Peer": "peer", "Port": "port", "Priority": "priority",
        "PSK Configured": lambda item: credential_presence(item.psk_configured),
        "Realm": "realm", "Server": "server", "Source IP": "source_ip", "Status": "status",
        "User": "user", "VDOM": "vdom",
    }, domains=("ssl_vpn_client",))


def _ssl_portal_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.ssl_vpn_portals,
        headers,
        {
            "Name": "name",
            "Tunnel Mode": "tunnel_mode",
            "IPv6 Tunnel Mode": "ipv6_tunnel_mode",
            "IP Pools": "ip_pools",
            "IPv6 Pools": "ipv6_pools",
            "Split Tunneling": "split_tunneling",
            "Limit User Logins": "limit_user_logins",
            "FortiClient Download": "forticlient_download",
            "Split Tunneling Routing Addresses": "split_tunneling_routing_address",
            "VDOM": "vdom",
        },
        domains=('ssl_vpn_portal',),
    )
def _ssl_auth_rule_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for settings in context.config.ssl_vpn_settings:
        for item in settings.authentication_rules:
            row = {
                "ID": item.id,
                "Auth": item.auth,
                "Cipher": item.cipher,
                "Client Certificate": item.client_cert,
                "Realm": item.realm,
                "Source Interfaces": item.source_interface,
                "Source Addresses": item.source_address,
                "Source Address Negate": item.source_address_negate,
                "Users": item.users,
                "User Peer": item.user_peer,
                "Groups": item.groups,
                "Portal": item.portal,
                "VDOM": settings.vdom,
                "Extraction Status": "EXTRACTED",
                "Manual Review": "No",
                "Additional Settings": _additional_settings(item, sheet_name="SSL VPN Authentication Rules"),
            }
            _overlay_safe_raw(row, row["Additional Settings"], headers)
            _add_analysis_status(row, context, vdom=settings.vdom, names=(item.id, item.portal))
            yield row


def _local_user_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.local_users,
        headers,
        {
            "Name": "name",
            "ID": "id",
            "Status": "status",
            "Type": "type",
            "Password Configured": "password_configured",
            "Password Time": "passwd_time",
            "Two Factor": "two_factor",
            "Two Factor Authentication": "two_factor_authentication",
            "Two Factor Notification": "two_factor_notification",
            "FortiToken": "fortitoken",
            "Email": "email_to",
            "LDAP Server": "ldap_server",
            "RADIUS Server": "radius_server",
            "TACACS+ Server": "tacacs_server",
            "Auth Concurrent Override": "auth_concurrent_override",
            "Auth Concurrent Value": "auth_concurrent_value",
            "Authentication Timeout": "authtimeout",
            "Password Policy": "passwd_policy",
            "Workstation": "workstation",
            "Username Sensitivity": "username_sensitivity",
            "PPK Identity": "ppk_identity",
            "PPK Secret Configured": "ppk_secret_configured",
            "VDOM": "vdom",
        },
        domains=('local_user',),
    )
def _user_group_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.user_groups,
        headers,
        {
            "Name": "name",
            "ID": "id",
            "Type": "group_type",
            "Group Type": "group_type",
            "Members": "members",
            "Match Count": lambda item: len(item.matches),
            "Auth Concurrent Override": "auth_concurrent_override",
            "Auth Concurrent Value": "auth_concurrent_value",
            "Authentication Timeout": "authtimeout",
            "VDOM": "vdom",
        },
        domains=('user_group',),
    )
def _user_group_match_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for group in context.config.user_groups:
        for item in group.matches:
            row = {
                "User Group": group.name,
                "Match ID": item.id,
                "Server Name": item.server_name,
                "Group Name": item.group_name,
                "VDOM": group.vdom,
                "Additional Settings": _additional_settings(item, sheet_name="User Group Matches"),
            }
            _overlay_safe_raw(row, row["Additional Settings"], headers)
            _add_analysis_status(row, context, vdom=group.vdom, names=(group.name, item.id))
            yield row


def _administrator_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.administrators,
        headers,
        {
            "Name": "name",
            "Access Profile": "accprofile",
            "VDOMs": "vdoms",
            "IPv4 Trusted Hosts": "trusthosts",
            "Two Factor": "two_factor",
            "Two Factor Authentication": "two_factor_authentication",
            "Two Factor Notification": "two_factor_notification",
            "Remote Auth": "remote_auth",
            "Remote Group": "remote_group",
            "Credential Configured": lambda item: (
                bool(item.password_configured or item.ssh_key_configured)
            ),
            "FortiToken": "fortitoken",
            "Guest User Groups": "guest_usergroups",
            "Schedule": "schedule",
            "Peer Auth": "peer_auth",
            "Peer Group": "peer_group",
            "SSH Certificate": "ssh_certificate",
            "Additional Settings": "raw_extra",
        },
        domains=('administrator',), issue_vdom='root',
    )
def _admin_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.admin_profiles,
        headers,
        {
            "Name": "name",
            "Additional Settings": "raw_extra",
        },
        domains=('admin_profile',), issue_vdom='root',
    )
def _admin_permission_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for profile in context.config.admin_profiles:
        for kind, permission in (
            ("Firewall", profile.firewall_permission),
            ("Log", profile.log_permission),
            ("Network", profile.network_permission),
            ("System", profile.system_permission),
            ("UTM", profile.utm_permission),
        ):
            if permission is None:
                continue
            values = permission.model_dump(mode="python", exclude={"raw_extra", "explicit_fields"})
            for setting, value in values.items():
                if value in (None, "", [], {}):
                    continue
                row = {
                    "Profile": profile.name,
                    "Permission Group": kind,
                    "Setting": setting,
                    "Value": value,
                    "Extraction Status": "EXTRACTED",
                    "Additional Settings": _additional_settings(
                        permission,
                        represented_fields=values.keys(),
                    ),
                }
                _add_analysis_status(
                    row,
                    context,
                    vdom="root",
                    names=(profile.name, setting),
                    domains=('admin_profile',),
                )
                yield row


def _ips_sensor_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.ips_sensors,
        headers,
        {
            "Name": "name",
            "Description": "comment",
            "Block Malicious URL": "block_malicious_url",
            "Scan Botnet Connections": "scan_botnet_connections",
            "Extended Log": "extended_log",
            "Replacement Message Group": "replacemsg_group",
            "Entry Count": lambda item: len(item.entries),
            "VDOM": "vdom",
        },
        domains=('ips_sensor',),
    )
def _ips_entry_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterator[dict[str, Any]]:

    for sensor in context.config.ips_sensors:
        for item in sensor.entries:
            row = {
                "Sensor": sensor.name,
                "Entry ID": item.id,
                "Signature IDs": item.rule,
                "CVEs": item.cve,
                "Applications": item.application,
                "OS": item.os,
                "Protocols": item.protocol,
                "Severities": item.severity,
                "Location": item.location,
                "Default Action Filter": item.default_action,
                "Default Status Filter": item.default_status,
                "Action": item.action,
                "Status": item.status,
                "Log": item.log,
                "Log Packet": item.log_packet,
                "Log Attack Context": item.log_attack_context,
                "Rate Count": item.rate_count,
                "Rate Duration": item.rate_duration,
                "Rate Mode": item.rate_mode,
                "Rate Track": item.rate_track,
                "Quarantine": item.quarantine,
                "Quarantine Expiry": item.quarantine_expiry,
                "Quarantine Log": item.quarantine_log,
                "Vulnerability Types": item.vuln_type,
                "Last Modified Filter": item.last_modified,
                "VDOM": sensor.vdom,
                "Additional Settings": _additional_settings(item, sheet_name="IPS Sensor Entries"),
            }

            _overlay_safe_raw(row, row["Additional Settings"], headers)
            _add_analysis_status(row, context, vdom=sensor.vdom, names=(sensor.name, item.id), domains=('ips_sensor',))

            yield row


def _ips_exempt_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for sensor in context.config.ips_sensors:
        for entry in sensor.entries:
            for item in entry.exempt_ips:
                row = {
                        "Sensor": sensor.name,
                        "Entry ID": entry.id,
                        "Exempt IP ID": item.id,
                        "Source IP": item.src_ip,
                        "Destination IP": item.dst_ip,
                        "VDOM": sensor.vdom,
                        "Additional Settings": _additional_settings(item, sheet_name="IPS Exempt IPs"),
                    }
                _add_analysis_status(row, context, vdom=sensor.vdom, names=(sensor.name, entry.id, item.id), domains=('ips_sensor',))
                yield row


def _security_profile_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.profile_groups,
        headers,
        {
            "Name": "name",
            "Antivirus": "av_profile",
            "IPS Sensor": "ips_sensor",
            "Application List": "application_list",
            "Web Filter": "webfilter_profile",
            "DNS Filter": "dnsfilter_profile",
            "File Filter": "file_filter_profile",
            "SSL/SSH Profile": "ssl_ssh_profile",
            "VDOM": "vdom",
        },
        domains=('profile_group',),
    )


def _av_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.antivirus_profiles, headers,
        {"Name": "name", "Feature Set": "feature_set", "Inspection Mode": "inspection_mode", "Scan Mode": "scan_mode", "AV Virus Log": "av_virus_log", "AV Block Log": "av_block_log", "Extended Log": "extended_log", "Comments": "comment", "VDOM": "vdom"},
        domains=("antivirus_profile",),
    )


def _webfilter_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.webfilter_profiles, headers,
        {"Name": "name", "Feature Set": "feature_set", "Inspection Mode": "inspection_mode", "URL Filter Table": "urlfilter_table", "Log All URL": "log_all_url", "Extended Log": "extended_log", "Safe Search": "safe_search", "Comments": "comment", "VDOM": "vdom"},
        domains=("webfilter_profile",),
    )


def _dnsfilter_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.dnsfilter_profiles, headers,
        {"Name": "name", "Block Action": "block_action", "Redirect Portal": "redirect_portal", "Block Botnet": "block_botnet", "Safe Search": "safe_search", "Log All Domain": "log_all_domain", "Domain Filter Table": "domain_filter_table", "Comments": "comment", "VDOM": "vdom"},
        domains=("dnsfilter_profile",),
    )


def _application_list_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.application_lists, headers,
        {"Name": "name", "Other Application Action": "other_application_action", "Other Application Log": "other_application_log", "Unknown Application Action": "unknown_application_action", "Deep App Inspection": "deep_app_inspection", "Extended Log": "extended_log", "Entry Count": lambda item: len(item.entries), "Comments": "comment", "VDOM": "vdom"},
        domains=("application_list",),
    )


def _file_filter_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.file_filter_profiles, headers,
        {"Name": "name", "Feature Set": "feature_set", "Log": "log", "Extended Log": "extended_log", "Scan Archive Contents": "scan_archive_contents", "Rule Count": lambda item: len(item.rules), "Comments": "comment", "VDOM": "vdom"},
        domains=("file_filter_profile",),
    )


def _emailfilter_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.emailfilter_profiles, headers,
        {"Name": "name", "Feature Set": "feature_set", "Spam Filtering": "spam_filtering", "Spam Log": "spam_log", "External": "external", "Comments": "comment", "VDOM": "vdom"},
        domains=("emailfilter_profile",),
    )


def _voip_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.voip_profiles, headers,
        {"Name": "name", "Feature Set": "feature_set", "SIP Status": "sip_status", "SIP RTP": "sip_rtp", "SIP Strict Register": "sip_strict_register", "SIP Invite Rate": "sip_invite_rate", "SIP Register Rate": "sip_register_rate", "Comments": "comment", "VDOM": "vdom"},
        domains=("voip_profile",),
    )


def _waf_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.waf_profiles, headers,
        {"Name": "name", "Extended Log": "extended_log", "External": "external", "Replacement Message Group": "replacemsg_group", "Comments": "comment", "VDOM": "vdom"},
        domains=("waf_profile",),
    )


def _ssl_ssh_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.ssl_ssh_profiles, headers,
        {"Name": "name", "CA Name": "caname", "Server Cert Mode": "server_cert_mode", "Server Cert": "server_cert", "Use SSL Server": "use_ssl_server", "Supported ALPN": "supported_alpn", "Comments": "comment", "VDOM": "vdom"},
        domains=("ssl_ssh_profile",),
    )


def _proxy_policy_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.proxy_policies, headers,
        {"Policy ID": "policy_id", "Name": "name", "Proxy Type": "proxy", "Status": "status", "Source Interface": "srcintf", "Destination Interface": "dstintf", "Source Addresses": "srcaddr", "Destination Addresses": "dstaddr", "Services": "service", "Action": "action", "Schedule": "schedule", "Profile Group": "profile_group", "Web Filter": "webfilter_profile", "AV Profile": "av_profile", "SSL/SSH Profile": "ssl_ssh_profile", "Comments": "comments", "VDOM": "vdom"},
        domains=("proxy_policy",),
    )


def _auth_policy_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.auth_policies, headers,
        {"Policy ID": "policy_id", "Name": "name", "Status": "status", "Source Interface": "srcintf", "Source Addresses": "srcaddr", "Destination Addresses": "dstaddr", "Services": "service", "Users": "users", "User Groups": "groups", "Active Auth Method": "active_auth_method", "SSO Auth Method": "sso_auth_method", "Comments": "comments", "VDOM": "vdom"},
        domains=("auth_policy",),
    )


def _traffic_shaper_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.traffic_shapers, headers,
        {"Name": "name", "Guaranteed Bandwidth": "guaranteed_bandwidth", "Maximum Bandwidth": "maximum_bandwidth", "Bandwidth Unit": "bandwidth_unit", "Priority": "priority", "Per-Policy": "per_policy", "DiffServ": "diffserv", "DSCP Marking Method": "dscp_marking_method", "VDOM": "vdom"},
        domains=("traffic_shaper",),
    )


def _ldb_monitor_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.ldb_monitors, headers,
        {"Name": "name", "Type": "type", "Interval": "interval", "Timeout": "timeout", "Retry": "retry", "Port": "port", "Source IP": "src_ip", "HTTP Get": "http_get", "HTTP Match": "http_match", "VDOM": "vdom"},
        domains=("ldb_monitor",),
    )


def _ha_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.ha_config, headers,
        {"Mode": "mode", "Group ID": "group_id", "Group Name": "group_name", "Priority": "priority", "Heartbeat Interfaces": "hbdev", "Session Pickup": "session_pickup", "Override": "override", "Schedule": "schedule", "Monitors": "monitor", "Password Configured": "password_configured", "VDOM": "vdom"},
        domains=("ha",),
    )


def _snmp_community_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.snmp_communities, headers,
        {"ID": "id", "Name": "name", "Status": "status", "Query V1 Status": "query_v1_status", "Query V2c Status": "query_v2c_status", "Trap V1 Status": "trap_v1_status", "Trap V2c Status": "trap_v2c_status", "Host Count": lambda item: len(item.hosts), "VDOM": "vdom"},
        domains=("snmp_community",),
    )


def _snmp_user_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.snmp_users, headers,
        {"Name": "name", "Status": "status", "Security Level": "security_level", "Auth Proto": "auth_proto", "Priv Proto": "priv_proto", "Queries": "queries", "Trap Status": "trap_status", "Notify Hosts": "notify_hosts", "VDOM": "vdom"},
        domains=("snmp_user",),
    )


def _fortiguard_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.fortiguard, headers,
        {"FortiGuard Anycast": "fortiguard_anycast", "Protocol": "protocol", "Port": "port", "Webfilter Cache": "webfilter_cache", "Antispam Cache": "antispam_cache", "Update Server Location": "update_server_location", "DDNS Enable": "ddns_enable", "VDOM": "vdom"},
        domains=("fortiguard",),
    )


def _bgp_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.router_bgp, headers,
        {"BGP AS": "bgp_as", "Router ID": "router_id", "Keepalive Timer": "keepalive_timer", "Holdtime Timer": "holdtime_timer", "eBGP Multipath": "ebgp_multipath", "iBGP Multipath": "ibgp_multipath", "Graceful Restart": "graceful_restart", "Neighbor Count": lambda item: len(item.neighbors), "Network Count": lambda item: len(item.networks) + len(item.networks6), "VDOM": "vdom"},
        domains=("router_bgp",),
    )


def _ospf_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.router_ospf, headers,
        {"Router ID": "router_id", "Default Information Originate": "default_information_originate", "ABR Type": "abr_type", "RFC1583 Compatible": "rfc1583_compatible", "Distance": "distance", "BFD": "bfd", "Area Count": lambda item: len(item.areas), "Interface Count": lambda item: len(item.ospf_interfaces), "Network Count": lambda item: len(item.networks), "VDOM": "vdom"},
        domains=("router_ospf",),
    )


def _prefix_list_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.prefix_lists, headers,
        {"Name": "name", "Address Family": "address_family", "Rule Count": lambda item: len(item.rules), "Comments": "comments", "VDOM": "vdom"},
        domains=("prefix_list",),
    )


def _route_map_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.route_maps, headers,
        {"Name": "name", "Rule Count": lambda item: len(item.rules), "Comments": "comments", "VDOM": "vdom"},
        domains=("route_map",),
    )


def _password_policy_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.password_policies, headers,
        {"Name": "name", "Expire Status": "expire_status", "Expire Days": "expire_days", "Minimum Length": "minimum_length", "Min Lowercase": "min_lower_case_letter", "Min Uppercase": "min_upper_case_letter", "Min Non-Alphanumeric": "min_non_alphanumeric", "Min Number": "min_number", "Reuse Password": "reuse_password", "VDOM": "vdom"},
        domains=("password_policy",),
    )


def _guest_user_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.guest_users, headers,
        {"ID": "id", "User ID": "user_id", "Type": "type", "Sponsor": "sponsor", "Company": "company", "Email": "email", "Mobile Phone": "mobile_phone", "Expiration": "expiration", "Password Configured": "password_configured", "Comments": "comment", "VDOM": "vdom"},
        domains=("guest_user",),
    )


def _wifi_ssid_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.wireless_vaps, headers,
        {"Name": "name", "SSID": "ssid", "Status": "status", "Local Bridging": "local_bridging", "Security": "security", "Encrypt": "encrypt", "Auth": "auth", "Passphrase Configured": "passphrase_configured", "RADIUS Server": "radius_server", "User Groups": "usergroup", "Schedule": "schedule", "VLAN ID": "vlanid", "VDOM": "vdom"},
        domains=("wireless_vap",),
    )


def _managed_fortiap_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.wireless_wtps, headers,
        {"WTP ID": "wtp_id", "Name": "name", "WTP Profile": "wtp_profile", "Admin": "admin", "Location": "location", "WAN Port Mode": "wan_port_mode", "Override Allowaccess": "override_allowaccess", "Comments": "comment", "VDOM": "vdom"},
        domains=("wireless_wtp",),
    )


def _fortiap_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.wtp_profiles, headers,
        {"Name": "name", "Platform": "platform", "AP Country": "ap_country", "DTLS Policy": "dtls_policy", "LED State": "led_state", "Comments": "comment", "VDOM": "vdom"},
        domains=("wtp_profile",),
    )


def _wids_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.wids_profiles, headers,
        {"Name": "name", "Rogue AP Detection": "ap_scan", "Sensor Mode": "sensor_mode", "Passive Scan": "ap_scan_passive", "Comments": "comment", "VDOM": "vdom"},
        domains=("wids_profile",),
    )


def _managed_switch_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.managed_switches, headers,
        {"Switch ID": "switch_id", "Name": "name", "Switch Group": "switch_group", "Status": "status", "Platform": "platform", "Serial": "sn", "Firmware Version": "firmware_provision_version", "Version": "version", "Directly Connected": "directly_connected", "Switch Profile": "switch_profile", "Port Count": lambda item: len(item.ports), "Description": "description", "VDOM": "vdom"},
        domains=("managed_switch",),
    )


def _switch_port_policy_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.switch_port_policies, headers,
        {"Name": "name", "User Groups": "user_group", "Guest VLAN": "guest_vlan", "Guest Auth Delay": "guest_auth_delay", "MAC Auth Bypass": "mac_auth_bypass", "EAP Pass Through": "eap_passthru", "Override RADIUS": "radius_timeout_overwrite", "FortiLink": "fortilink", "QoS Policy": "qos_policy", "VLAN Policy": "vlan_policy", "Bounce Port Link": "bounce_port_link", "Description": "description", "VDOM": "vdom"},
        domains=("switch_port_policy",),
    )


def _nac_policy_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.nac_policies, headers,
        {"Name": "name", "Category": "category", "HW Vendor": "hw_vendor", "MAC": "mac", "OS": "os", "Assign VLAN": "assign_vlan", "Matched Devices": "matched_devices", "Switch Group": "switch_group", "User Group": "user_group", "Status": "status", "Description": "description", "VDOM": "vdom"},
        domains=("nac_policy",),
    )


def _syslog_setting_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context, context.config.syslog_settings, headers,
        {"Syslog Name": "syslog_name", "Status": "status", "Server": "server", "Mode": "mode", "Port": "port", "Facility": "facility", "Source IP": "source_ip", "Format": "format", "Interface": "interface", "VDOM": "vdom"},
        domains=("syslog_setting",),
    )
def _external_resource_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.external_resources,
        headers,
        {
            "Name": "name",
            "Resource": "resource",
            "Type": "type",
            "Refresh Rate": "refresh_rate",
            "Comments": "comments",
            "VDOM": "vdom",
        },
        domains=('external_resource',),
    )


def _unresolved_reference_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for item in context.derived.broken_references:
        yield {
                "Source VDOM": item.source_vdom,
                "Source Type": item.source_kind,
                "Source Object": item.source_name,
                "Field": item.source_field,
                "Reference": item.reference,
                "Expected Type": [kind.value for kind in item.expected_kinds],
                "Reason": "Reference could not be resolved in the same VDOM.",
            }
    return


def _unsupported_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    del headers
    return [
        {
            "Section": path,
            "VDOMs": ", ".join(sorted({record.vdom for record in context.source_by_path.get(path, ()) if record.vdom is not None})),
            "Source Records": count,
            "Primitive Registration": "REGISTERED" if path in context.registered_sections else "GENERIC",
            "Model Coverage": "SOURCE_ONLY",
            "Reason": (
                "Primitive source shapes are registered, but no dedicated FortiGate source model is defined."
                if path in context.registered_sections
                else "Explicit source is preserved generically, with no primitive registration or dedicated FortiGate model."
            ),
            "Raw Capture Location": (
                "Full Excel export / sanitized source evidence"
                if context.profile is ExcelExportProfile.FAST
                else "FortiGate Source Inventory"
            ),
            "Source Evidence": f"{path}: {count} source record(s)",
        }
        for path, count in sorted(context.source_only_counts.items())
    ]


def _iter_fortigate_source_inventory_rows(
    context: _ExcelContext,
) -> Iterator[tuple[Any, ...]]:
    for record in context.extracted.source_objects:
        typed = find_typed_source_object(context.typed_source_identity_index, record)
        raw_extra = getattr(typed.model, "raw_extra", {}) if typed else {}
        status = extraction_status(supports_path(record.source_path), typed, record)
        if context.profile is ExcelExportProfile.FAST and status == "TYPED":
            continue
        registration = "REGISTERED" if record.source_path in context.registered_sections else "GENERIC"
        base = (
            _source_category(record.source_path),
            record.vdom,
            "Object" if record.object_name is not None else "Config",
            record.source_path,
            record.object_name,
            "\n".join(record.parent_objects) or None,
        )

        provenance = (
            record.cli_scope, " / ".join(record.cli_path),
            record.start_line_number, record.end_line_number,
        )
        if not record.commands:
            yield (*base, None, None, None, registration, status, len(raw_extra) if typed else None, *provenance)
            continue

        raw_extra_count = len(raw_extra) if typed else None
        for command in record.commands:
            yield (
                *base,
                command.operation,
                command.key,
                _excel_value(_safe_command_value(command.key, command.values)),
                registration,
                status,
                raw_extra_count,
                *provenance,
            )


def _coverage_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    del headers

    rows: list[dict[str, Any]] = []

    paths = context.source_paths | frozenset(
        path for path, objects in context.typed_source_inventory.items() if objects
    )
    for path in sorted(paths):
        records = context.source_by_path.get(path, [])
        typed_objects = context.typed_source_inventory.get(path, ())
        typed_support = supports_path(path)
        source_only = 0 if typed_support else len(records)
        model_gaps = sum(
            extraction_status(typed_support, find_typed_source_object(context.typed_source_identity_index, record), record) == "MODEL_GAP"
            for record in records
        )
        raw_extra_objects = sum(bool(getattr(item.model, "raw_extra", {})) for item in typed_objects)
        raw_extra_entries = sum(len(getattr(item.model, "raw_extra", {})) for item in typed_objects)

        rows.append(
            {
                "Source Section": path,
                "Found": "Yes",
                "Source Records": len(records),
                "Primitive Registration": "REGISTERED" if path in context.registered_sections else "GENERIC",
                "Model Coverage": "TYPED" if typed_support else "SOURCE_ONLY",
                "Typed Objects": len(typed_objects),
                "Raw Extra Objects": raw_extra_objects,
                "Raw Extra Entries": raw_extra_entries,
                "Model Gaps": model_gaps,
                "Source-only Records": source_only,
                "Line Start": min(
                    (
                        record.start_line_number
                        for record in records
                        if record.start_line_number is not None
                    ),
                    default=None,
                ),
                "Line End": max(
                    (
                        record.end_line_number
                        for record in records
                        if record.end_line_number is not None
                    ),
                    default=None,
                ),
                "Notes": (
                    "Typed extraction is declared, but source records are missing matching model objects."
                    if model_gaps
                    else "Dedicated FortiGate model represents this source path; additional explicit state is preserved in raw_extra."
                    if typed_support and raw_extra_objects
                    else "Dedicated FortiGate source model represents this source path."
                    if typed_support
                    else "Explicit source is preserved in Source Inventory; no dedicated FortiGate model is defined."
                ),
            }
        )

    return rows


def _generic_source_rows(
    sheet_name: str,
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterator[dict[str, Any]]:
    del headers

    paths = _SOURCE_PATHS_BY_SHEET.get(
        sheet_name,
        (),
    )

    for path in paths:
        for record in context.source_by_path.get(
            path,
            (),
        ):
            values = sanitize_source_attributes(
                record.values
            )

            if not values:
                row = {
                    "VDOM": record.vdom,
                    "Source Path": record.source_path,
                    "Object": record.object_name,
                    "Parent / Subsection": list(
                        record.parent_objects
                    ),
                    "Setting": None,
                    "Value": None,
                }

                _add_analysis_status(
                    row,
                    context,
                    vdom=record.vdom,
                    names=(record.object_name,),
                )

                yield row
                continue

            for setting, value in values.items():
                row = {
                    "VDOM": record.vdom,
                    "Source Path": record.source_path,
                    "Object": record.object_name,
                    "Parent / Subsection": list(
                        record.parent_objects
                    ),
                    "Setting": setting,
                    "Value": value,
                }

                _add_analysis_status(
                    row,
                    context,
                    vdom=record.vdom,
                    names=(record.object_name,),
                )

                yield row


def _ntp_setting_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterable[Mapping[str, Any]]:
    del headers
    rows: list[dict[str, Any]] = []

    for record in context.source_by_path.get("system ntp", ()):
        values = sanitize_source_attributes(record.values)
        for setting, value in values.items():
            row = {
                "Setting": setting,
                "Value": value,
                "Source Path": record.source_path,
            }
            _add_analysis_status(
                row,
                context,
                vdom=record.vdom,
                names=(None,),
            )
            rows.append(row)

    return rows


def _ntp_server_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    del headers
    rows: list[dict[str, Any]] = []

    for record in context.source_by_path.get("system ntp ntpserver", ()):
        values = sanitize_source_attributes(record.values)
        for setting, value in values.items():
            row = {
                "Server ID": record.object_name,
                "Setting": setting,
                "Value": value,
                "Source Path": record.source_path,
            }
            _add_analysis_status(
                row,
                context,
                vdom=record.vdom,
                names=(record.object_name,),
            )
            rows.append(row)

    return rows


