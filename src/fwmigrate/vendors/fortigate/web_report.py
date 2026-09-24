from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from .derived import DerivedViews
from .model.source import FGConfig
from .validation.index import ValidationIssueIndex
from .validation.models import ValidationResult


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


def _address_value(item: Any) -> str | None:
    if item.start_ip and item.end_ip:
        return f"{item.start_ip}-{item.end_ip}"
    return item.subnet or item.ip6 or item.fqdn or item.wildcard or item.wildcard_fqdn


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
        "security_policies": len(config.security_policies),
        "protocol_options": len(config.protocol_options),
        "per_ip_shapers": len(config.per_ip_shapers),
        "session_helpers": len(config.session_helpers),
        "ssl_vpn_realms": len(config.ssl_vpn_realms),
        "ssl_vpn_clients": len(config.ssl_vpn_clients),
        "ssl_vpn_bookmarks": sum(len(owner.bookmarks) for owner in config.ssl_vpn_user_bookmarks + config.ssl_vpn_user_group_bookmarks),
        "nac_policies": len(config.nac_policies),
        "ip_pools": len(config.ip_pools) + len(config.ip_pools6),
        "vips": len(config.vips) + len(config.vips6),
        "vip_groups": len(config.vip_groups) + len(config.vip_groups6),
        "static_routes": len(config.static_routes),
        "ipsec_phase1": len(config.ipsec_phase1),
        "ipsec_policy_phase1": len(config.ipsec_policy_phase1),
        "ipsec_phase2": len(config.ipsec_phase2) + len(config.ipsec_policy_phase2),
        "ipsec_policy_phase2": len(config.ipsec_policy_phase2),
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
        for member in row["members"]:
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
) -> dict[str, Any]:
    """Build a secret-safe presentation model for the browser report."""

    issue_index = ValidationIssueIndex(validation)
    topology = {(item.vdom, item.name): item for item in derived.topology.interfaces}
    vpn_topology = {(item.vdom, item.name): item for item in derived.topology.vpns}
    nat = {(item.vdom, item.policy_id): item for item in derived.nat}
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
    for item in config.interfaces:
        top = topology.get((item.vdom, item.name))
        interfaces.append(
            {
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
                "members": list(item.members),
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
            "value": _address_value(item),
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
            "members": list(item.members),
            "exclude_members": list(item.exclude_members),
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
            "members": list(item.members),
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
            "review": _review(_messages(issue_index, vdom=item.vdom, names=(item.name,), domains=("schedule",))),
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
            "review": _review(_messages(issue_index, vdom=item.vdom, names=(item.name,), domains=("schedule",))),
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
    for item in config.policies:
        key = (item.vdom, item.policy_id)
        nat_item = nat.get(key)
        policies.append(
            {
                "policy_id": item.policy_id,
                "name": item.name,
                "source_name": item.name,
                "vdom": item.vdom,
                "source_interfaces": list(item.srcintf),
                "destination_interfaces": list(item.dstintf),
                "source_addresses": list(item.srcaddr),
                "destination_addresses": list(item.dstaddr),
                "source_addresses_ipv6": list(item.srcaddr6),
                "destination_addresses_ipv6": list(item.dstaddr6),
                "source_address_negate_ipv6": item.srcaddr6_negate,
                "destination_address_negate_ipv6": item.dstaddr6_negate,
                "services": list(item.service),
                "schedule": item.schedule,
                "profile_protocol_options": item.profile_protocol_options,
                "per_ip_shaper": item.per_ip_shaper,
                "action": item.action,
                "nat": item.nat,
                "status": item.status,
                "review": _review(
                    nat_item.issues if nat_item else (),
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
            "review": _review(item.issues),
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
                "dh_groups": list(item.dhgrp),
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
            "proposal": list(item.proposal), "pfs": item.pfs, "dh_groups": list(item.dhgrp),
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
            )
            for row in rows
            if row.get("vdom")
        }
    )

    return {
        "vendor": "fortigate",
        "summary": {
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
