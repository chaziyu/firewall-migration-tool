from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

from pydantic import BaseModel

from .report_values import address_value, policy_nat_entries, policy_nat_review
from .derived import DerivedViews
from .model.source import FGConfig
from .validation.index import ValidationIssueIndex
from .validation.models import ValidationResult
from .security.extraction import sanitize_source_attributes
from .security.extraction import sanitize_source_value
from .extraction.result import ExtractionResult
from .extraction.coverage import (
    build_typed_source_inventory, build_typed_source_identity_index,
    find_typed_source_object, extraction_status, supports_path,
)


def _source_evidence(
    extracted: ExtractionResult,
    *,
    include_commands: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    typed = build_typed_source_inventory(extracted.config)
    index = build_typed_source_identity_index(typed)
    by_path: dict[str, Counter] = defaultdict(Counter)
    records = []
    for record in extracted.source_objects:
        status = extraction_status(supports_path(record.source_path), find_typed_source_object(index, record), record)
        by_path[record.source_path][status] += 1
        entry: dict[str, Any] = {
            "name": record.object_name, "vdom": record.vdom, "source_path": record.source_path,
            "cli_scope": record.cli_scope, "cli_path": list(record.cli_path),
            "parent_objects": list(record.parent_objects), "extraction_status": status,
            "values": sanitize_source_attributes(record.values, preserve_keys=True), "explicit_fields": list(record.explicit_fields),
            "unset_fields": list(record.unset_fields), "start_line_number": record.start_line_number,
            "end_line_number": record.end_line_number,
        }
        if include_commands:
            entry["commands"] = [
                {"operation": command.operation, "field": command.key,
                 "values": sanitize_source_value(command.key, list(command.values)),
                 "line_number": command.line_number}
                for command in record.commands
            ]
        else:
            entry["command_count"] = len(record.commands)
        records.append(entry)
    coverage = []
    for path in sorted(set(by_path) | {path for path, items in typed.items() if items}):
        statuses = by_path[path]
        coverage.append({
            "source_path": path, "source_records": sum(statuses.values()), "typed_objects": len(typed.get(path, ())),
            "status": "MODEL_GAP" if statuses["MODEL_GAP"] else next(iter(statuses)) if len(statuses) == 1 else "MIXED",
            "source_only_records": statuses["SOURCE_ONLY"], "empty_sections": statuses["EMPTY_SECTION"],
            "model_gaps": statuses["MODEL_GAP"], "typed_with_additional_settings": statuses["TYPED_WITH_RAW_EXTRA"],
        })
    counts = Counter(row["extraction_status"] for row in records)
    return ({"records": len(records), "source_only_count": counts["SOURCE_ONLY"],
             "unsupported_count": counts["SOURCE_ONLY"], "empty_section_count": counts["EMPTY_SECTION"],
             "model_gap_count": counts["MODEL_GAP"], "typed_with_additional_settings_count": counts["TYPED_WITH_RAW_EXTRA"]},
            {"extraction_coverage": coverage, "source_inventory": records})


def _source_details(value: Any) -> Any:
    """Retain explicit source detail and safe nested evidence without adding defaults."""
    if isinstance(value, BaseModel):
        row = {}
        for name in type(value).model_fields:
            item = getattr(value, name)
            if name == "raw_extra":
                row["additional_settings"] = _source_details(item)
            elif name == "explicit_fields":
                row[name] = sorted(item)
            elif isinstance(item, list) and not item and name not in value.model_fields_set:
                row[name] = None
            else:
                row[name] = _source_details(item)
        return sanitize_source_attributes(row)
    if isinstance(value, dict):
        return sanitize_source_attributes({key: _source_details(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return [_source_details(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    return value


def _messages(
    issue_index: ValidationIssueIndex,
    *,
    vdom: str,
    names: Iterable[object],
    domains: Iterable[str] = (),
) -> list[str]:
    return [
        issue.message
        for issue in issue_index.issues_for(vdom, names, domains)
    ]


def _review(*groups: Iterable[str]) -> str | None:
    messages = list(dict.fromkeys(message for group in groups for message in group))
    return "; ".join(messages) or None


def _source_rows(items: Iterable[Any], fields: tuple[str, ...]) -> list[dict[str, Any]]:
    """Project reviewed source fields plus sanitized evidence and explicitness."""
    rows = []
    for item in items:
        details = _source_details(item)
        row = {key: value for key, value in details.items()
               if key in fields or key in {"additional_settings", "explicit_fields"}}
        rows.append(row)
    return rows



def _object_counts(config: FGConfig) -> dict[str, int]:
    return {
        "interfaces": len(config.interfaces),
        "zones": len(config.zones),
        "addresses": len(config.addresses),
        "address_groups": len(config.address_groups),
        "services": len(config.services),
        "service_groups": len(config.service_groups),
        "schedules": len(config.one_time_schedules) + len(config.recurring_schedules),
        "schedule_groups": len(config.schedule_groups),
        "policies": len(config.policies),
        "central_snat": len(config.central_snat),
        "security_policies": len(config.security_policies),
        "protocol_options": len(config.protocol_options),
        "per_ip_shapers": len(config.per_ip_shapers),
        "session_helpers": len(config.session_helpers),
        "ssl_vpn_realms": len(config.ssl_vpn_realms),
        "ssl_vpn_clients": len(config.ssl_vpn_clients),
        "ssl_vpn_host_check_software": len(config.ssl_vpn_host_check_software),
        "ssl_vpn_bookmarks": sum(len(owner.bookmarks) for owner in config.ssl_vpn_user_bookmarks + config.ssl_vpn_user_group_bookmarks),
        "nac_policies": len(config.nac_policies),
        "profile_groups": len(config.profile_groups),
        "address6_templates": len(config.address6_templates),
        "ips_settings": len(config.ips_settings),
        "kmip_servers": len(config.kmip_servers),
        "kerberos_keytabs": len(config.kerberos_keytabs),
        "router_settings": len(config.router_settings),
        "sdn_proxies": len(config.sdn_proxies),
        "on_demand_sniffers": len(config.on_demand_sniffers),
        "affinity_interrupts": len(config.affinity_interrupts),
        "serial_ports": len(config.serial_ports),
        "firewall_regions": len(config.firewall_regions),
        "vendor_macs": len(config.vendor_macs),
        "ip_pools": len(config.ip_pools) + len(config.ip_pools6),
        "vips": len(config.vips) + len(config.vips6),
        "vip_groups": len(config.vip_groups) + len(config.vip_groups6),
        "wildcard_fqdns": len(config.wildcard_fqdns),
        "local_users": len(config.local_users),
        "administrators": len(config.administrators),
        "dhcp_servers": len(config.dhcp_servers),
        "ssl_vpn_portals": len(config.ssl_vpn_portals),
        "static_routes": len(config.static_routes),
        "ipsec_phase1": len(config.ipsec_phase1),
        "ipsec_policy_phase1": len(config.ipsec_policy_phase1),
        "ipsec_phase2": len(config.ipsec_phase2) + len(config.ipsec_policy_phase2),
        "ipsec_policy_phase2": len(config.ipsec_policy_phase2),
        "system_global": len(config.system_global),
        "system_dns": len(config.system_dns),
        "system_ntp": len(config.system_ntp),
        "ha_config": len(config.ha_config),
        "snmp_sysinfo": len(config.snmp_sysinfo),
        "snmp_communities": len(config.snmp_communities),
        "snmp_users": len(config.snmp_users),
        "fortiguard": len(config.fortiguard),
        "router_bgp": len(config.router_bgp),
        "router_ospf": len(config.router_ospf),
        "router_ospf6": len(config.router_ospf6),
        "router_rip": len(config.router_rip),
        "policy_routes": len(config.policy_routes),
        "prefix_lists": len(config.prefix_lists),
        "route_maps": len(config.route_maps),
        "aspath_lists": len(config.aspath_lists),
        "community_lists": len(config.community_lists),
        "router_multicast": len(config.router_multicast),
        "system_ipam": len(config.system_ipam),
        "fortiextenders": len(config.fortiextenders),
        "proxy_policies": len(config.proxy_policies),
        "auth_policies": len(config.auth_policies),
        "traffic_shapers": len(config.traffic_shapers),
        "ldb_monitors": len(config.ldb_monitors),
        "virtual_servers": sum(1 for item in config.vips if item.type == "server-load-balance" or item.realservers),
        "antivirus_profiles": len(config.antivirus_profiles),
        "webfilter_profiles": len(config.webfilter_profiles),
        "urlfilter_tables": len(config.urlfilter_tables),
        "webfilter_local_categories": len(config.webfilter_local_categories),
        "webfilter_local_ratings": len(config.webfilter_local_ratings),
        "webfilter_overrides": len(config.webfilter_overrides),
        "dnsfilter_profiles": len(config.dnsfilter_profiles),
        "application_lists": len(config.application_lists),
        "file_filter_profiles": len(config.file_filter_profiles),
        "emailfilter_profiles": len(config.emailfilter_profiles),
        "voip_profiles": len(config.voip_profiles),
        "waf_profiles": len(config.waf_profiles),
        "ssl_ssh_profiles": len(config.ssl_ssh_profiles),
        "ldap_servers": len(config.ldap_servers),
        "radius_servers": len(config.radius_servers),
        "tacacs_servers": len(config.tacacs_servers),
        "fsso_servers": len(config.fsso_servers),
        "fsso_pollings": len(config.fsso_pollings),
        "fortitokens": len(config.fortitokens),
        "user_settings": len(config.user_settings),
        "password_policies": len(config.password_policies),
        "wireless_vaps": len(config.wireless_vaps),
        "wireless_wtps": len(config.wireless_wtps),
        "wtp_profiles": len(config.wtp_profiles),
        "wids_profiles": len(config.wids_profiles),
        "managed_switches": len(config.managed_switches),
        "syslog_settings": len(config.syslog_settings),
        "log_memory_settings": len(config.log_memory_settings),
        "log_disk_settings": len(config.log_disk_settings),
        "log_settings": len(config.log_settings),
        "log_threat_weights": len(config.log_threat_weights),
        "guest_users": len(config.guest_users),
        "switch_port_policies": len(config.switch_port_policies),
        "switch_lldp_profiles": len(config.switch_lldp_profiles),
        "switch_qos_policies": len(config.switch_qos_policies),
        "switch_vlan_policies": len(config.switch_vlan_policies),
    }


def _interface_topology_rows(
    interfaces: list[dict[str, Any]],
    vpns: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_key = {(row["vdom"], row["name"]): row for row in interfaces}
    aggregate_members: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    children: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    vpn_children: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    owned: set[tuple[str, str]] = set()

    for row in interfaces:
        key = (row["vdom"], row["name"])
        if row["parent"] and (row["vdom"], row["parent"]) in by_key:
            children[(row["vdom"], row["parent"])].append(key)
        for member in row["members"] or ():
            member_key = (row["vdom"], member)
            aggregate_members[key].append(member_key)
            owned.add(member_key)

    for vpn in vpns:
        if vpn["interface"]:
            vpn_children[(vpn["vdom"], vpn["interface"])].append(vpn)

    rank = {"aggregate": 0, "physical": 1, "vlan": 2, "logical": 3, "tunnel": 4}
    sort_key = lambda key: (rank.get(by_key[key]["kind"], 5), by_key[key]["name"])
    roots = sorted(
        (
            key
            for key, row in by_key.items()
            if key not in owned and not row["parent"]
        ),
        key=sort_key,
    )
    symbols = {
        "aggregate": "◆",
        "physical": "●",
        "vlan": "▣",
        "logical": "◇",
        "tunnel": "◇",
        "vpn": "◈",
    }
    result: list[dict[str, Any]] = []
    visited: set[tuple[str, str]] = set()
    emitted_vpns: set[tuple[str, str]] = set()

    def emit_vpn(vpn: dict[str, Any], prefix: str = "") -> None:
        key = (vpn["vdom"], vpn["name"])
        if key in emitted_vpns:
            return
        emitted_vpns.add(key)
        result.append(
            {
                **vpn,
                "display_name": f"{prefix}{symbols['vpn']} {vpn['name']}",
                "kind": "vpn",
                "ip": vpn["remote_gateway"],
                "parent": vpn["interface"],
                "role": None,
                "status": None,
                "members": [],
            }
        )

    def emit_interface(
        key: tuple[str, str],
        prefix: str = "",
        child_indent: str = "",
    ) -> None:
        if key in visited:
            return
        visited.add(key)
        row = by_key[key]
        result.append(
            {
                **row,
                "display_name": f"{prefix}{symbols.get(row['kind'], '◇')} {row['name']}",
            }
        )
        child_keys = sorted(
            (
                child
                for child in dict.fromkeys(
                    (*aggregate_members[key], *children[key])
                )
                if child in by_key
            ),
            key=sort_key,
        )
        attached_vpns = vpn_children[key]
        child_count = len(child_keys) + len(attached_vpns)
        for index, child in enumerate(child_keys, start=1):
            last = index == child_count
            emit_interface(
                child,
                child_indent + ("└─ " if last else "├─ "),
                child_indent + ("   " if last else "│  "),
            )
        for offset, vpn in enumerate(attached_vpns, start=len(child_keys) + 1):
            emit_vpn(
                vpn,
                child_indent + ("└─ " if offset == child_count else "├─ "),
            )

    for key in roots:
        emit_interface(key)
    for key in sorted(by_key, key=sort_key):
        emit_interface(key)
    for vpn in vpns:
        emit_vpn(vpn)
    return result


def build_web_report(
    config: FGConfig,
    derived: DerivedViews,
    validation: ValidationResult,
    *,
    top_level_sections: int,
    extracted: ExtractionResult | None = None,
    include_source_commands: bool = True,
) -> dict[str, Any]:
    """Build a secret-safe presentation model for the browser report."""

    issue_index = ValidationIssueIndex(validation)
    topology = {(item.vdom, item.name): item for item in derived.topology.interfaces}
    vpn_topology = {(item.vdom, item.name): item for item in derived.topology.vpns}
    nat_counts, nat = policy_nat_entries(config, derived)
    vpn_phase2 = {(item.vpn_type, item.vdom, item.name): item for item in derived.vpn.phase2}
    vpn_issues: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for issue in derived.vpn.issues:
        vpn_issues[(issue.vpn_type, issue.vdom, issue.phase2)].append(issue.message)

    severity_counts: dict[str, int] = defaultdict(int)
    validation_rows = []
    for issue in validation.issues:
        severity = getattr(issue.severity, "value", str(issue.severity))
        severity_counts[severity] += 1
        validation_rows.append(
            {
                "severity": severity,
                "domain": issue.domain,
                "vdom": issue.vdom,
                "object_name": issue.object_name,
                "field": issue.field,
                "message": issue.message,
            }
        )

    interfaces = []
    _INTERFACE_EXTRA_FIELDS = (
        "mtu", "tcp_mss", "distance", "priority", "ha_priority", "min_links",
        "weight", "snmp_index", "link_up_delay", "link_down_delay",
        "dhcp_renew_time", "defaultgw", "lacp_mode", "lacp_speed",
        "aggregate_type", "management_ip", "dhcp_relay_ip",
    )
    for item in config.interfaces:
        top = topology.get((item.vdom, item.name))
        source = _source_rows((item,), (
            "alias", "description", "mode", "allowaccess", "vlanid", "vrf",
            "secondary_ips", "members", "cli_scope", "cli_vdom", "unset_fields",
        ))[0]
        extra_settings = source.get("additional_settings") or {}
        extra_projected = {
            field: extra_settings.get(field)
            for field in _INTERFACE_EXTRA_FIELDS
        }
        interfaces.append(
            {
                **source,
                **extra_projected,
                "name": item.name,
                "vdom": item.vdom,
                "ip": item.ip,
                "type": item.type,
                "kind": top.kind if top else None,
                "role": item.role,
                "parent": top.parent if top else item.interface,
                "status": item.status,
                "aggregate": top.aggregate if top else None,
                "physical_interfaces": list(top.physical_interfaces) if top else [],
                "topology_path": list(top.path) if top else [],
                "members": source["members"],
                "review": _review(
                    top.issues if top else (),
                    _messages(
                        issue_index,
                        vdom=item.vdom,
                        names=(item.name,),
                        domains=("interface", "interface_topology"),
                    ),
                ),
            }
        )

    addresses = [
        {
            "name": item.name,
            "vdom": item.vdom,
            "address_family": item.address_family,
            "type": item.type,
            "value": address_value(item),
            "associated_interface": item.associated_interface,
            "comment": item.comment,
            "review": _review(
                _messages(
                    issue_index,
                    vdom=item.vdom,
                    names=(item.name,),
                    domains=("address", "address6"),
                )
            ),
        }
        for item in config.addresses
    ]

    address_groups = [
        {
            "name": item.name,
            "vdom": item.vdom,
            "address_family": item.address_family,
            "members": list(item.members) if item.members is not None else None,
            "exclude_members": list(item.exclude_members) if item.exclude_members is not None else None,
            "comment": item.comment,
            "review": _review(
                _messages(
                    issue_index,
                    vdom=item.vdom,
                    names=(item.name,),
                    domains=("address_group", "address_group6"),
                )
            ),
        }
        for item in config.address_groups
    ]

    services = [
        {
            "name": item.name,
            "source_name": item.source_name,
            "vdom": item.vdom,
            "protocol": item.protocol,
            "port": item.port,
            "source_port": item.source_port,
            "protocol_number": item.protocol_number,
            "icmp_type": item.icmp_type,
            "icmp_code": item.icmp_code,
            "generated": item.generated,
            "comment": item.comment,
            "review": _review(
                _messages(
                    issue_index,
                    vdom=item.vdom,
                    names=(item.source_name, item.name),
                    domains=("service",),
                )
            ),
        }
        for item in derived.services.services
    ]

    service_groups = [
        {
            "name": item.name,
            "vdom": item.vdom,
            "members": list(item.members) if item.members is not None else None,
            "generated": item.generated,
            "comment": item.comment,
            "review": _review(
                _messages(
                    issue_index,
                    vdom=item.vdom,
                    names=(item.name,),
                    domains=("service_group", "service"),
                )
            ),
        }
        for item in derived.services.groups
    ]

    schedules = [
        {
            "name": item.name,
            "type": "one-time",
            "vdom": item.vdom,
            "start": item.start,
            "end": item.end,
            "start_utc": item.start_utc,
            "end_utc": item.end_utc,
            "expiration_days": item.expiration_days,
            "review": _review(_messages(issue_index, vdom=item.vdom, names=(item.name,), domains=("schedule", "schedule_onetime"))),
        }
        for item in config.one_time_schedules
    ] + [
        {
            "name": item.name,
            "type": "recurring",
            "vdom": item.vdom,
            "days": list(item.days),
            "start": item.start,
            "end": item.end,
            "review": _review(_messages(issue_index, vdom=item.vdom, names=(item.name,), domains=("schedule", "schedule_recurring"))),
        }
        for item in config.recurring_schedules
    ]

    schedule_groups = [
        {
            "name": item.name,
            "vdom": item.vdom,
            "members": list(item.members),
            "review": _review(_messages(issue_index, vdom=item.vdom, names=(item.name,), domains=("schedule_group",))),
        }
        for item in config.schedule_groups
    ]

    policies = []
    policy_details = _source_rows(config.policies, (
        "srcaddr_negate", "dstaddr_negate", "service_negate", "groups", "users", "logtraffic", "comments",
        "utm_status", "inspection_mode", "profile_type", "profile_group", "av_profile", "ips_sensor",
        "webfilter_profile", "dnsfilter_profile", "application_list", "ssl_ssh_profile", "vpntunnel",
        "nat64", "nat46", "natinbound", "natoutbound", "natip", "ippool", "poolname", "poolname6",
        "fixedport", "port_preserve", "internet_service", "internet_service_name", "internet_service_group",
        "internet_service_custom", "internet_service_src", "internet_service_src_name",
        "internet_service_src_group", "internet_service_src_custom",
    ))
    for item, detail in zip(config.policies, policy_details):
        key = (item.vdom, item.policy_id)
        nat_items = nat.get(key, ())
        policies.append(
            {
                **detail,
                "policy_id": item.policy_id,
                "name": item.name,
                "source_name": item.name,
                "vdom": item.vdom,
                "source_interfaces": list(item.srcintf) if item.srcintf is not None else None,
                "destination_interfaces": list(item.dstintf) if item.dstintf is not None else None,
                "source_addresses": list(item.srcaddr) if item.srcaddr is not None else None,
                "destination_addresses": list(item.dstaddr) if item.dstaddr is not None else None,
                "source_addresses_ipv6": list(item.srcaddr6) if item.srcaddr6 is not None else None,
                "destination_addresses_ipv6": list(item.dstaddr6) if item.dstaddr6 is not None else None,
                "source_address_negate_ipv6": item.srcaddr6_negate,
                "destination_address_negate_ipv6": item.dstaddr6_negate,
                "services": list(item.service) if item.service is not None else None,
                "schedule": item.schedule,
                "profile_protocol_options": item.profile_protocol_options,
                "per_ip_shaper": item.per_ip_shaper,
                "action": item.action,
                "nat": item.nat,
                "status": item.status,
                "review": _review(
                    policy_nat_review(key, nat_counts, nat_items),
                    _messages(
                        issue_index,
                        vdom=item.vdom,
                        names=(item.policy_id, item.name),
                        domains=("policy", "nat"),
                    ),
                ),
            }
        )

    security_policies = [
        {"policy_id": item.policy_id, "vdom": item.vdom, "action": item.action,
         "app_category": list(item.app_category),
         "review": _review(_messages(issue_index, vdom=item.vdom, names=(item.policy_id,), domains=("security_policy",)))}
        for item in config.security_policies
    ]
    protocol_options = [
        {"name": item.name, "vdom": item.vdom, "comment": item.comment,
         "review": _review(_messages(issue_index, vdom=item.vdom, names=(item.name,), domains=("protocol_options",)))}
        for item in config.protocol_options
    ]
    per_ip_shapers = [
        {"name": item.name, "vdom": item.vdom, "max_bandwidth": item.max_bandwidth,
         "bandwidth_unit": item.bandwidth_unit,
         "review": _review(_messages(issue_index, vdom=item.vdom, names=(item.name,), domains=("per_ip_shaper",)))}
        for item in config.per_ip_shapers
    ]

    nat_rows = [
        {
            "vdom": item.vdom,
            "policy_id": item.policy_id,
            "policy_name": item.policy_name,
            "translation_type": item.translation_type,
            "pool_names": list(item.pool_names),
            "translated_addresses": list(item.translated_addresses),
            "egress_interfaces": list(item.egress_interfaces),
            "review": _review(item.issues, policy_nat_review((item.vdom, item.policy_id), nat_counts, ()) if item.policy_id is None or nat_counts[(item.vdom, item.policy_id)] != 1 else ()),
        }
        for item in derived.nat
    ]

    routes = [
        {
            "route_id": item.seq_num,
            "vdom": item.vdom,
            "address_family": item.address_family,
            "destination": item.dst,
            "destination_address": item.dstaddr,
            "gateway": item.gateway,
            "device": item.device,
            "distance": item.distance,
            "priority": item.priority,
            "status": item.status,
            "review": _review(
                _messages(
                    issue_index,
                    vdom=item.vdom,
                    names=(item.seq_num,),
                    domains=("static_route", "static_route6"),
                )
            ),
        }
        for item in config.static_routes
    ]

    vpn_tunnels = []
    for item in config.ipsec_phase1:
        top = vpn_topology.get((item.vdom, item.name))
        vpn_tunnels.append(
            {
                "name": item.name,
                "vdom": item.vdom,
                "interface": item.interface,
                "remote_gateway": item.remote_gw or item.remotegw_ddns,
                "ike_version": item.ike_version,
                "type": item.type,
                "proposal": list(item.proposal),
                "aggregate": top.aggregate if top else None,
                "physical_interfaces": list(top.physical_interfaces) if top else [],
                "topology_path": list(top.path) if top else [],
                "review": _review(
                    top.issues if top else (),
                    _messages(
                        issue_index,
                        vdom=item.vdom,
                        names=(item.name,),
                        domains=("ipsec_phase1", "vpn_topology"),
                    ),
                ),
            }
        )

    vpn_phase2_rows = []
    for item in config.ipsec_phase2:
        normalized = vpn_phase2.get(("route-based", item.vdom, item.name))
        vpn_phase2_rows.append(
            {
                "name": item.name,
                "vdom": item.vdom,
                "phase1": item.phase1name,
                "proposal": list(item.proposal),
                "pfs": item.pfs,
                "dh_groups": list(item.dhgrp) if item.dhgrp is not None else None,
                "source_range": normalized.source_range if normalized else None,
                "destination_range": (
                    normalized.destination_range if normalized else None
                ),
                "source_range6": normalized.source_range6 if normalized else None,
                "destination_range6": normalized.destination_range6 if normalized else None,
                "review": _review(
                    vpn_issues[("route-based", item.vdom, item.name)],
                    _messages(
                        issue_index,
                        vdom=item.vdom,
                        names=(item.name,),
                        domains=("vpn_phase2",),
                    ),
                ),
            }
        )

    policy_vpn_phase2_rows = []
    for item in config.ipsec_policy_phase2:
        normalized = vpn_phase2.get(("policy-based", item.vdom, item.name))
        policy_vpn_phase2_rows.append({
            "name": item.name, "vdom": item.vdom, "phase1": item.phase1name,
            "proposal": list(item.proposal), "pfs": item.pfs, "dh_groups": list(item.dhgrp) if item.dhgrp is not None else None,
            "source_range": normalized.source_range if normalized else None,
            "destination_range": normalized.destination_range if normalized else None,
            "source_range6": normalized.source_range6 if normalized else None,
            "destination_range6": normalized.destination_range6 if normalized else None,
            "review": _review(
                vpn_issues[("policy-based", item.vdom, item.name)],
                _messages(issue_index, vdom=item.vdom, names=(item.name,), domains=("ipsec_policy_phase2",)),
            ),
        })

    policy_vpn_phase1_rows = [
        {
            "name": item.name,
            "vdom": item.vdom,
            "remote_gateway": item.remote_gw or item.remotegw_ddns,
            "ike_version": item.ike_version,
            "authentication_method": item.authmethod,
            "psk_configured": item.psk_configured,
            "review": _review(_messages(issue_index, vdom=item.vdom, names=(item.name,), domains=("ipsec_policy_phase1",))),
        }
        for item in config.ipsec_policy_phase1
    ]

    ssl_vpn_realms = [
        {"url_path": item.url_path, "vdom": item.vdom,
         "login_page_configured": bool(item.login_page),
         "login_page_length": len(item.login_page or ""),
         "radius_server": item.radius_server, "radius_port": item.radius_port,
         "virtual_host": item.virtual_host, "review": None}
        for item in config.ssl_vpn_realms
    ]
    ssl_vpn_bookmarks = [
        {"owner_type": owner_type, "owner_name": owner.owner_name, "name": bookmark.name,
         "apptype": bookmark.apptype, "url": bookmark.url, "host": bookmark.host,
         "logon_password_configured": bookmark.logon_password_configured,
         "sso_password_configured": bookmark.sso_password_configured, "vdom": owner.vdom}
        for owner_type, owners in (("user", config.ssl_vpn_user_bookmarks), ("group", config.ssl_vpn_user_group_bookmarks))
        for owner in owners for bookmark in owner.bookmarks
    ]
    nac_policies = [
        {"name": item.name, "vdom": item.vdom, "category": item.category,
         "description": item.description, "mac": item.mac, "host": item.host,
         "os": item.os, "family": item.family, "firewall_address": item.firewall_address,
         "user_group": item.user_group, "status": item.status,
         "review": _review(_messages(issue_index, vdom=item.vdom, names=(item.name,), domains=("nac_policy",)))}
        for item in config.nac_policies
    ]

    unresolved = [
        {
            "source_kind": item.source_kind,
            "vdom": item.source_vdom,
            "source_name": item.source_name,
            "source_field": item.source_field,
            "reference": item.reference,
            "expected_kinds": [kind.value for kind in item.expected_kinds],
        }
        for item in derived.broken_references
    ]

    source_sections = {
        "zones": _source_rows(config.zones, ("name", "vdom", "members", "description", "intrazone")),
        "user_groups": _source_rows(config.user_groups, ("name", "vdom", "id", "group_type", "members", "matches", "guests",
                                                         "authtimeout", "auth_concurrent_override", "auth_concurrent_value")),
        "admin_profiles": [{**{key: value for key, value in _source_details(item).items() if key != "scope"},
                            "profile_scope": item.scope, "vdom": item.cli_vdom} for item in config.admin_profiles],
        "ips_sensors": _source_rows(config.ips_sensors, ("name", "vdom", "comment", "block_malicious_url",
                                                       "scan_botnet_connections", "extended_log", "replacemsg_group", "entries")),
        "external_resources": _source_rows(config.external_resources, ("name", "vdom", "type", "resource", "comments", "refresh_rate")),
        "service_categories": _source_rows(config.service_categories, ("name", "vdom", "comment")),
        "sdwan": _source_rows(config.sdwans, ("vdom", "status", "load_balance_mode", "zones", "members", "health_checks", "services")),
        "ssl_vpn_settings": _source_rows(config.ssl_vpn_settings, ("vdom", "status", "source_interface", "source_address",
            "source_address6", "tunnel_ip_pools", "tunnel_ipv6_pools", "default_portal", "port", "servercert",
            "dns_server1", "dns_server2", "ssl_min_proto_ver", "ssl_max_proto_ver", "auth_timeout", "idle_timeout", "authentication_rules")),
        "vips": _source_rows(
            (*config.vips, *config.vips6),
            ("name", "vdom", "address_family", "type", "status", "extip", "extaddr", "extintf",
             "mappedip", "mapped_addr", "portforward", "protocol", "extport", "mappedport",
             "arp_reply", "nat_source_vip", "service", "ldb_method", "server_type", "monitor",
             "nat64", "nat66", "ndp_reply", "ipv4_mappedip", "ipv4_mappedport", "comment", "realservers"),
        ),
        "ip_pools": _source_rows(
            (*config.ip_pools, *config.ip_pools6),
            ("name", "vdom", "address_family", "type", "startip", "endip", "source_startip", "source_endip",
             "startport", "endport", "associated_interface", "arp_reply", "arp_intf", "permit_any_host",
             "nat64", "add_nat64_route", "nat46", "add_nat46_route", "exclude_ip", "comments"),
        ),
        "vip_groups": _source_rows(
            (*config.vip_groups, *config.vip_groups6),
            ("name", "vdom", "address_family", "interface", "members", "comments"),
        ),
        "wildcard_fqdns": _source_rows(config.wildcard_fqdns, ("name", "vdom", "wildcard_fqdn", "comment")),
        "local_users": _source_rows(
            config.local_users,
            ("name", "vdom", "id", "type", "status", "two_factor", "ldap_server", "radius_server",
             "tacacs_server", "authtimeout", "passwd_time", "passwd_policy", "email_to"),
        ),
        "administrators": [
            {**{key: value for key, value in _source_details(item).items() if key != "cli_vdom"},
             "vdom": item.cli_vdom}
            for item in config.administrators
        ],
        "dhcp_servers": _source_rows(
            config.dhcp_servers,
            ("id", "vdom", "interface", "status", "server_type", "ip_mode", "default_gateway",
             "netmask", "lease_time", "dns_service", "dns_server1", "dns_server2", "dns_server3",
             "dns_server4", "timezone_option", "timezone", "relay_agent", "ip_ranges", "exclude_ranges", "reserved_addresses"),
        ),
        "ssl_vpn_portals": _source_rows(
            config.ssl_vpn_portals,
            ("name", "vdom", "tunnel_mode", "ipv6_tunnel_mode", "ip_pools", "ipv6_pools", "web_mode",
             "split_tunneling", "split_tunneling_routing_address", "ipv6_split_tunneling",
             "ipv6_split_tunneling_routing_address", "limit_user_logins", "forticlient_download",
             "host_check", "host_check_policy"),
        ),
        "session_helpers": _source_rows(config.session_helpers, ("id", "name", "vdom", "protocol", "port")),
        "ssl_vpn_clients": _source_rows(
            config.ssl_vpn_clients,
            ("name", "vdom", "interface", "server", "port", "user", "peer", "realm", "certificate",
             "psk_configured", "source_ip", "ipv4_subnets", "ipv6_subnets", "distance", "priority",
             "class_id", "status", "comment"),
        ),
        "ssl_vpn_host_check_software": _source_rows(
            config.ssl_vpn_host_check_software,
            ("name", "vdom", "os_type", "type", "version", "guid", "check_items"),
        ),
        "profile_groups": _source_rows(
            config.profile_groups,
            ("name", "vdom", "application_list", "av_profile", "ips_sensor", "webfilter_profile",
             "dnsfilter_profile", "ssl_ssh_profile", "casb_profile", "cifs_profile",
             "diameter_filter_profile", "dlp_profile", "emailfilter_profile", "file_filter_profile",
             "icap_profile", "profile_protocol_options", "sctp_filter_profile", "ssh_filter_profile",
             "ips_voip_filter", "videofilter_profile", "virtual_patch_profile", "voip_profile", "waf_profile"),
        ),
        "address6_templates": _source_rows(
            config.address6_templates,
            ("name", "vdom", "ip6", "subnet_segment_count", "fabric_object", "segments"),
        ),
        "ips_settings": _source_rows(config.ips_settings, ("vdom", "ips_packet_quota", "packet_log_history")),
        "kmip_servers": _source_rows(
            config.kmip_servers,
            ("name", "vdom", "interface", "interface_select_method", "source_ip", "source_port",
             "username", "password_configured", "ssl_min_proto_version", "server_identity_check", "server_list"),
        ),
        "kerberos_keytabs": _source_rows(
            config.kerberos_keytabs,
            ("name", "vdom", "principal", "ldap_server", "pac_data", "keytab_configured"),
        ),
        "router_settings": _source_rows(config.router_settings, ("vdom", "hostname", "show_filter")),
        "sdn_proxies": _source_rows(
            config.sdn_proxies,
            ("name", "vdom", "type", "server", "server_port", "username", "password_configured"),
        ),
        "on_demand_sniffers": _source_rows(
            config.on_demand_sniffers,
            ("name", "vdom", "interface", "hosts", "ports", "protocols", "max_packet_count",
             "non_ip_packet", "advanced_filter"),
        ),
        "affinity_interrupts": _source_rows(
            config.affinity_interrupts,
            ("id", "interrupt", "affinity_cpumask", "default_affinity_cpumask"),
        ),
        "serial_ports": _source_rows(config.serial_ports, ("name",)),
        "firewall_regions": _source_rows(config.firewall_regions, ("id", "name", "city")),
        "vendor_macs": _source_rows(config.vendor_macs, ("id", "name", "mac_number", "obsolete")),
        "system_global": [_source_details(item) for item in config.system_global],
        "system_dns": [_source_details(item) for item in config.system_dns],
        "system_ntp": [_source_details(item) for item in config.system_ntp],
        "ha_config": [_source_details(item) for item in config.ha_config],
        "snmp_sysinfo": [_source_details(item) for item in config.snmp_sysinfo],
        "snmp_communities": [_source_details(item) for item in config.snmp_communities],
        "snmp_users": [_source_details(item) for item in config.snmp_users],
        "fortiguard": [_source_details(item) for item in config.fortiguard],
        "router_bgp": [_source_details(item) for item in config.router_bgp],
        "router_ospf": [_source_details(item) for item in config.router_ospf],
        "router_ospf6": [_source_details(item) for item in config.router_ospf6],
        "router_rip": [_source_details(item) for item in config.router_rip],
        "policy_routes": [_source_details(item) for item in config.policy_routes],
        "prefix_lists": [_source_details(item) for item in config.prefix_lists],
        "route_maps": [_source_details(item) for item in config.route_maps],
        "aspath_lists": [_source_details(item) for item in config.aspath_lists],
        "community_lists": [_source_details(item) for item in config.community_lists],
        "router_multicast": [_source_details(item) for item in config.router_multicast],
        "system_ipam": [_source_details(item) for item in config.system_ipam],
        "fortiextenders": [_source_details(item) for item in config.fortiextenders],
        "proxy_policies": [_source_details(item) for item in config.proxy_policies],
        "auth_policies": [_source_details(item) for item in config.auth_policies],
        "traffic_shapers": [_source_details(item) for item in config.traffic_shapers],
        "ldb_monitors": [_source_details(item) for item in config.ldb_monitors],
        "virtual_servers": _source_rows(
            (item for item in config.vips if item.type == "server-load-balance" or item.realservers),
            ("name", "vdom", "type", "status", "extip", "extintf", "extport", "server_type", "ldb_method", "monitor", "realservers", "comment"),
        ),
        "antivirus_profiles": [_source_details(item) for item in config.antivirus_profiles],
        "webfilter_profiles": [_source_details(item) for item in config.webfilter_profiles],
        "urlfilter_tables": [_source_details(item) for item in config.urlfilter_tables],
        "webfilter_local_categories": [_source_details(item) for item in config.webfilter_local_categories],
        "webfilter_local_ratings": [_source_details(item) for item in config.webfilter_local_ratings],
        "webfilter_overrides": [_source_details(item) for item in config.webfilter_overrides],
        "dnsfilter_profiles": [_source_details(item) for item in config.dnsfilter_profiles],
        "application_lists": [_source_details(item) for item in config.application_lists],
        "file_filter_profiles": [_source_details(item) for item in config.file_filter_profiles],
        "emailfilter_profiles": [_source_details(item) for item in config.emailfilter_profiles],
        "voip_profiles": [_source_details(item) for item in config.voip_profiles],
        "waf_profiles": [_source_details(item) for item in config.waf_profiles],
        "ssl_ssh_profiles": [_source_details(item) for item in config.ssl_ssh_profiles],
        "ldap_servers": [_source_details(item) for item in config.ldap_servers],
        "radius_servers": [_source_details(item) for item in config.radius_servers],
        "tacacs_servers": [_source_details(item) for item in config.tacacs_servers],
        "fsso_servers": [_source_details(item) for item in config.fsso_servers],
        "fsso_pollings": [_source_details(item) for item in config.fsso_pollings],
        "fortitokens": [_source_details(item) for item in config.fortitokens],
        "user_settings": [_source_details(item) for item in config.user_settings],
        "password_policies": [_source_details(item) for item in config.password_policies],
        "wireless_vaps": [_source_details(item) for item in config.wireless_vaps],
        "wireless_wtps": [_source_details(item) for item in config.wireless_wtps],
        "wtp_profiles": [_source_details(item) for item in config.wtp_profiles],
        "wids_profiles": [_source_details(item) for item in config.wids_profiles],
        "managed_switches": [_source_details(item) for item in config.managed_switches],
        "syslog_settings": [_source_details(item) for item in config.syslog_settings],
        "log_memory_settings": [_source_details(item) for item in config.log_memory_settings],
        "log_disk_settings": [_source_details(item) for item in config.log_disk_settings],
        "log_settings": [_source_details(item) for item in config.log_settings],
        "log_threat_weights": [_source_details(item) for item in config.log_threat_weights],
        "guest_users": [_source_details(item) for item in config.guest_users],
        "switch_port_policies": [_source_details(item) for item in config.switch_port_policies],
        "switch_lldp_profiles": [_source_details(item) for item in config.switch_lldp_profiles],
        "switch_qos_policies": [_source_details(item) for item in config.switch_qos_policies],
        "switch_vlan_policies": [_source_details(item) for item in config.switch_vlan_policies],
    }

    vdoms = sorted(
        {
            row["vdom"]
            for rows in (
                interfaces,
                addresses,
                address_groups,
                services,
                service_groups,
                schedules,
                schedule_groups,
                policies,
                security_policies,
                protocol_options,
                per_ip_shapers,
                routes,
                vpn_tunnels,
                vpn_phase2_rows,
                policy_vpn_phase1_rows,
                policy_vpn_phase2_rows,
                validation_rows,
                unresolved,
                *source_sections.values(),
            )
            for row in rows
            if row.get("vdom")
        }
    )

    evidence_summary, evidence_sections = (
        _source_evidence(extracted, include_commands=include_source_commands)
        if extracted is not None
        else ({}, {})
    )
    meta = extracted.source_metadata if extracted is not None else None
    source_meta_dict = (
        {
            "fortios_version": meta.fortios_version,
            "hardware_model": meta.hardware_model,
            "firmware_build": meta.firmware_build,
            "serial_number": meta.serial_number,
        }
        if meta is not None
        else {}
    )
    return {
        "vendor": "fortigate",
        "summary": {
            **evidence_summary,
            "source_metadata": source_meta_dict,
            "top_level_sections": top_level_sections,
            "objects": _object_counts(config),
            "validation": {
                "issue_count": len(validation_rows),
                "severity_counts": dict(severity_counts),
            },
            "vdoms": vdoms,
            "scopes": vdoms,
        },
        "sections": {
            **evidence_sections,
            **source_sections,
            "interfaces": interfaces,
            "interface_topology": _interface_topology_rows(
                interfaces,
                vpn_tunnels,
            ),
            "addresses": addresses,
            "address_groups": address_groups,
            "services": services,
            "service_groups": service_groups,
            "schedules": schedules,
            "schedule_groups": schedule_groups,
            "policies": policies,
            "central_snat": [item.model_dump(mode="json", exclude={"raw_extra"}) for item in config.central_snat],
            "security_policies": security_policies,
            "protocol_options": protocol_options,
            "per_ip_shapers": per_ip_shapers,
            "nat": nat_rows,
            "routes": routes,
            "vpn_tunnels": vpn_tunnels,
            "vpn_phase2": vpn_phase2_rows,
            "policy_vpn_phase1": policy_vpn_phase1_rows,
            "policy_vpn_phase2": policy_vpn_phase2_rows,
            "ssl_vpn_realms": ssl_vpn_realms,
            "ssl_vpn_bookmarks": ssl_vpn_bookmarks,
            "nac_policies": nac_policies,
            "validation": validation_rows,
            "unresolved_references": unresolved,
        },
    }
