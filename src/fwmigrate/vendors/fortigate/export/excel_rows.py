"""FortiGate Excel row builders grouped away from workbook orchestration.

Rows are derived only from extracted/derived/validation state supplied by the
existing Excel context. No source-model mutation or target inference occurs here.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Iterable, Iterator, Mapping, Sequence

from fwmigrate.source_reporting import ExcelExportProfile

from ..extraction.coverage import extraction_status, find_typed_source_object, supports_path
from ..security.extraction import sanitize_source_attributes
from ..transform.policies import effective_policy_action
from .excel_schema import SHEET_ORDER
from .excel_common import (
    _POLICY_ACTION_NOTE,
    _VISIBLE_MODEL_FIELDS_BY_SHEET,
    _SOURCE_PATHS_BY_SHEET,
    _add_analysis_status,
    _additional_settings,
    _additional_source_settings,
    _enabled_text,
    _excel_safe,
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
        "Interfaces": _interface_rows,
        "Interface Secondary IPs": _interface_secondary_rows,
        "Zones": _zone_rows,
        "Addresses": _address_rows,
        "Wildcard FQDN": _wildcard_fqdn_rows,
        "Address Groups": _address_group_rows,
        "Services": _service_rows,
        "Service Groups": _service_group_rows,
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
        value = item.subnet or item.ip6 or (
            f"{item.start_ip}-{item.end_ip}" if item.start_ip and item.end_ip else None
        ) or item.fqdn or item.wildcard or item.wildcard_fqdn
        row = {
            "Name": item.name,
            "Type": item.type,
            "Value": value,
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
    source = {(item.vdom, item.name): item for item in context.config.services}
    for item in context.derived.services.services:
        source_item = source.get((item.vdom, item.source_name or item.name))
        row = {
            "Name": item.name,
            "Source Service": item.source_name,
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


def _service_group_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    source = {(item.vdom, item.name): item for item in context.config.service_groups}
    for item in context.derived.services.groups:
        source_item = source.get((item.vdom, item.name))
        row = {
            "Name": item.name,
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
    nat = {
        (item.vdom, item.policy_id): item
        for item in context.derived.nat
    }
    for item in context.config.policies:
        nat_item = nat.get((item.vdom, item.policy_id))
        row = {
            "Rule #": item.policy_id,
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
            "SNAT Type": _nat_type(nat_item.translation_type) if nat_item else None,
            "SNAT Address": list(nat_item.translated_addresses) if nat_item else [],
            "IP Pool Name": list(nat_item.pool_names) if nat_item else [],
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
    policies = {
        (policy.vdom, policy.policy_id): policy
        for policy in context.config.policies
    }

    for item in context.derived.nat:
        policy = policies.get(
            (item.vdom, item.policy_id)
        )

        row = {
            "Rule #": item.policy_id,
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
            extra_reasons=item.issues,
            domains=('nat',),
        )
        yield row


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
            "PSK Configured": "Yes" if item.psk_configured else "No",
            "PPK Secret Configured": "Yes" if item.ppk_secret_configured else "No",
            "Auth Password Configured": "Yes" if item.auth_password_configured else "No",
            "Group Authentication Secret Configured": "Yes" if item.group_authentication_secret_configured else "No",
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
            "PSK Configured": lambda item: "Yes" if item.psk_configured else "No",
            "PPK Secret Configured": lambda item: "Yes" if item.ppk_secret_configured else "No",
            "Auth Password Configured": lambda item: "Yes" if item.auth_password_configured else "No",
            "Group Authentication Secret Configured": lambda item: "Yes" if item.group_authentication_secret_configured else "No",
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


def _policy_vpn_phase2_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    normalized = {(item.vpn_type, item.vdom, item.name): item for item in context.derived.vpn.phase2}
    rows = []
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
        rows.append(row)
    return rows


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
            "Status": item.status,
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
            row = {
                "Name": item.name,
                "Server": item.server,
                "Members": item.members,
                "Protocol": item.protocol,
                "Interval": item.interval,
                "Fail Time": item.failtime,
                "Recovery Time": item.recoverytime,
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
                "Source": item.src,
                "Destination": item.dst,
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
        "PSK Configured": lambda item: "Yes" if item.psk_configured else "No",
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


def _unresolved_reference_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for item in context.derived.broken_references:
        rows.append(
            {
                "Source VDOM": item.source_vdom,
                "Source Type": item.source_kind,
                "Source Object": item.source_name,
                "Field": item.source_field,
                "Reference": item.reference,
                "Expected Type": [kind.value for kind in item.expected_kinds],
                "Reason": "Reference could not be resolved in the same VDOM.",
            }
        )
    return rows


def _unsupported_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    del headers
    return [
        {
            "Section": path,
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
        }
        for path, count in sorted(context.source_only_counts.items())
    ]


def _iter_fortigate_source_inventory_rows(
    context: _ExcelContext,
) -> Iterator[tuple[Any, ...]]:
    for record in context.extracted.source_objects:
        typed = find_typed_source_object(context.typed_source_identity_index, record)
        raw_extra = getattr(typed.model, "raw_extra", {}) if typed else {}
        status = extraction_status(supports_path(record.source_path), typed)
        if context.profile is ExcelExportProfile.FAST and status == "TYPED":
            continue
        registration = "REGISTERED" if record.source_path in context.registered_sections else "GENERIC"
        base = (
            _excel_safe(_source_category(record.source_path)),
            _excel_safe(record.vdom),
            _excel_safe("Object" if record.object_name is not None else "Config"),
            _excel_safe(record.source_path),
            _excel_safe(record.object_name),
            _excel_safe("\n".join(record.parent_objects) or None),
        )

        if not record.commands:
            yield (*base, None, None, None, _excel_safe(registration), _excel_safe(status), len(raw_extra) if typed else None)
            continue

        for command in record.commands:
            yield (
                *base,
                _excel_safe(command.operation),
                _excel_safe(command.key),
                _excel_safe(_safe_command_value(command.key, command.values)),
                _excel_safe(registration),
                _excel_safe(status),
                len(raw_extra) if typed else None,
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
        matched = sum(
            find_typed_source_object(context.typed_source_identity_index, record) is not None
            for record in records
        )
        source_only = 0 if typed_support else len(records)
        model_gaps = len(records) - matched if typed_support else 0
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


