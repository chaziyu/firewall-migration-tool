"""FortiGate global IP / object 'Where-Used' search across extracted source state."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ...source_reporting.ip_match import (
    ParsedQuery,
    parse_where_used_query,
    query_matches_ip_bounds,
    query_matches_ip_text,
    query_matches_name,
)
from .model.source import FGConfig


def _vdom_of(item: Any) -> str:
    return getattr(item, "vdom", None) or "root"


def _add_match(bucket: dict[str, dict[str, str]], vdom: str, name: str | None, reason: str) -> None:
    if not name:
        return
    bucket[vdom].setdefault(name, reason)


def _match_ref_list(
    query: ParsedQuery,
    refs: list[str] | tuple[str, ...] | None,
    matched_names: dict[str, str],
) -> list[str]:
    reasons: list[str] = []
    for ref in refs or ():
        if ref in matched_names:
            reasons.append(f"object '{ref}' ({matched_names[ref]})")
        else:
            direct = query_matches_ip_text(query, ref) or query_matches_name(query, ref)
            if direct:
                reasons.append(f"'{ref}' ({direct})")
    return reasons


def search_fortigate_where_used(config: FGConfig, query_text: str) -> dict[str, Any]:
    """Resolve IP/CIDR/range/object references across FortiGate configuration layers."""
    query = parse_where_used_query(query_text)
    matched_by_vdom: dict[str, dict[str, str]] = defaultdict(dict)

    # 1. Direct matches on addresses, VIPs, and IP pools
    addr_rows: list[dict[str, Any]] = []
    for addr in config.addresses:
        vdom = _vdom_of(addr)
        reasons: list[str] = []
        name_reason = query_matches_name(query, addr.name)
        if name_reason:
            reasons.append(name_reason)
        if addr.subnet:
            sub_reason = query_matches_ip_text(query, addr.subnet)
            if sub_reason:
                reasons.append(f"subnet {addr.subnet}: {sub_reason}")
        if addr.start_ip or addr.end_ip:
            range_reason = query_matches_ip_bounds(query, addr.start_ip, addr.end_ip)
            if range_reason:
                reasons.append(f"range {addr.start_ip}-{addr.end_ip}: {range_reason}")
        if addr.fqdn:
            fqdn_reason = query_matches_name(query, addr.fqdn)
            if fqdn_reason:
                reasons.append(f"fqdn {addr.fqdn}: {fqdn_reason}")
        if addr.wildcard:
            wc_reason = query_matches_ip_text(query, addr.wildcard)
            if wc_reason:
                reasons.append(f"wildcard {addr.wildcard}: {wc_reason}")
        if reasons:
            reason_text = "; ".join(dict.fromkeys(reasons))
            _add_match(matched_by_vdom, vdom, addr.name, reason_text)
            value = addr.subnet or (f"{addr.start_ip}-{addr.end_ip}" if addr.start_ip and addr.end_ip else None) or addr.fqdn or addr.wildcard or addr.ip6
            addr_rows.append({
                "kind": "Address",
                "name": addr.name,
                "vdom": vdom,
                "value": value,
                "members": None,
                "match_reason": reason_text,
            })

    vip_direct_matches: dict[tuple[str, str], str] = {}
    for vip in config.vips:
        vdom = _vdom_of(vip)
        reasons = []
        if r := query_matches_name(query, vip.name):
            reasons.append(r)
        if vip.extip and (r := query_matches_ip_text(query, vip.extip)):
            reasons.append(f"extip {vip.extip}: {r}")
        for mapped in vip.mappedip:
            if r := query_matches_ip_text(query, mapped):
                reasons.append(f"mappedip {mapped}: {r}")
        if vip.mapped_addr and (r := query_matches_name(query, vip.mapped_addr)):
            reasons.append(f"mapped-addr {vip.mapped_addr}: {r}")
        for ext_ref in vip.extaddr:
            if r := query_matches_name(query, ext_ref):
                reasons.append(f"extaddr {ext_ref}: {r}")
        for rs in vip.realservers:
            if rs.ip and (r := query_matches_ip_text(query, rs.ip)):
                reasons.append(f"realserver {rs.ip}: {r}")
            if rs.address and (r := query_matches_name(query, rs.address)):
                reasons.append(f"realserver {rs.address}: {r}")
        if reasons:
            reason_text = "; ".join(dict.fromkeys(reasons))
            vip_direct_matches[(vdom, vip.name)] = reason_text
            _add_match(matched_by_vdom, vdom, vip.name, reason_text)

    pool_direct_matches: dict[tuple[str, str], str] = {}
    for pool in config.ip_pools:
        vdom = _vdom_of(pool)
        reasons = []
        if r := query_matches_name(query, pool.name):
            reasons.append(r)
        if (pool.startip or pool.endip) and (r := query_matches_ip_bounds(query, pool.startip, pool.endip)):
            reasons.append(f"pool {pool.startip}-{pool.endip}: {r}")
        if (pool.source_startip or pool.source_endip) and (
            r := query_matches_ip_bounds(query, pool.source_startip, pool.source_endip)
        ):
            reasons.append(f"source {pool.source_startip}-{pool.source_endip}: {r}")
        if reasons:
            reason_text = "; ".join(dict.fromkeys(reasons))
            pool_direct_matches[(vdom, pool.name)] = reason_text
            _add_match(matched_by_vdom, vdom, pool.name, reason_text)

    # 2. Recursive upward expansion through address groups and VIP groups (cycle-safe)
    group_reasons: dict[tuple[str, str], list[str]] = defaultdict(list)
    for grp in config.address_groups:
        vdom = _vdom_of(grp)
        if r := query_matches_name(query, grp.name):
            group_reasons[(vdom, grp.name)].append(r)
            _add_match(matched_by_vdom, vdom, grp.name, r)

    changed = True
    while changed:
        changed = False
        for grp in config.address_groups:
            vdom = _vdom_of(grp)
            vdom_matches = matched_by_vdom[vdom]
            for member in grp.members or ():
                if member in vdom_matches:
                    msg = f"contains member '{member}' ({vdom_matches[member]})"
                    if msg not in group_reasons[(vdom, grp.name)]:
                        group_reasons[(vdom, grp.name)].append(msg)
                    if grp.name not in vdom_matches:
                        vdom_matches[grp.name] = msg
                        changed = True

    vip_group_reasons: dict[tuple[str, str], list[str]] = defaultdict(list)
    for vgrp in config.vip_groups:
        vdom = _vdom_of(vgrp)
        if r := query_matches_name(query, vgrp.name):
            vip_group_reasons[(vdom, vgrp.name)].append(r)
            _add_match(matched_by_vdom, vdom, vgrp.name, r)

    changed = True
    while changed:
        changed = False
        for vgrp in config.vip_groups:
            vdom = _vdom_of(vgrp)
            vdom_matches = matched_by_vdom[vdom]
            for member in vgrp.members:
                if member in vdom_matches:
                    msg = f"contains VIP '{member}' ({vdom_matches[member]})"
                    if msg not in vip_group_reasons[(vdom, vgrp.name)]:
                        vip_group_reasons[(vdom, vgrp.name)].append(msg)
                    if vgrp.name not in vdom_matches:
                        vdom_matches[vgrp.name] = msg
                        changed = True

    # Also match VIPs referencing matched address objects via extaddr / mapped_addr
    for vip in config.vips:
        vdom = _vdom_of(vip)
        vdom_matches = matched_by_vdom[vdom]
        extra_reasons: list[str] = []
        for ext_ref in vip.extaddr:
            if ext_ref in vdom_matches:
                extra_reasons.append(f"extaddr '{ext_ref}' ({vdom_matches[ext_ref]})")
        if vip.mapped_addr and vip.mapped_addr in vdom_matches:
            extra_reasons.append(f"mapped-addr '{vip.mapped_addr}' ({vdom_matches[vip.mapped_addr]})")
        if extra_reasons:
            combined = "; ".join(dict.fromkeys(([vip_direct_matches.get((vdom, vip.name), "")] if (vdom, vip.name) in vip_direct_matches else []) + extra_reasons))
            vip_direct_matches[(vdom, vip.name)] = combined
            _add_match(matched_by_vdom, vdom, vip.name, combined)

    for grp in config.address_groups:
        vdom = _vdom_of(grp)
        if (vdom, grp.name) in group_reasons:
            addr_rows.append({
                "kind": "Address Group",
                "name": grp.name,
                "vdom": vdom,
                "value": f"{len(grp.members or ())} members",
                "members": list(grp.members or ()),
                "match_reason": "; ".join(dict.fromkeys(group_reasons[(vdom, grp.name)])),
            })

    # 3. NAT / VIP / IP Pools
    nat_rows: list[dict[str, Any]] = []
    for vip in config.vips:
        vdom = _vdom_of(vip)
        if (vdom, vip.name) in vip_direct_matches:
            nat_rows.append({
                "kind": "VIP",
                "name": vip.name,
                "vdom": vdom,
                "external": vip.extip or ", ".join(vip.extaddr) or None,
                "mapped": ", ".join(vip.mappedip) or vip.mapped_addr or None,
                "match_reason": vip_direct_matches[(vdom, vip.name)],
            })
    for vgrp in config.vip_groups:
        vdom = _vdom_of(vgrp)
        if (vdom, vgrp.name) in vip_group_reasons:
            nat_rows.append({
                "kind": "VIP Group",
                "name": vgrp.name,
                "vdom": vdom,
                "external": None,
                "mapped": ", ".join(vgrp.members),
                "match_reason": "; ".join(dict.fromkeys(vip_group_reasons[(vdom, vgrp.name)])),
            })
    for pool in config.ip_pools:
        vdom = _vdom_of(pool)
        if (vdom, pool.name) in pool_direct_matches:
            nat_rows.append({
                "kind": "IP Pool",
                "name": pool.name,
                "vdom": vdom,
                "external": f"{pool.startip}-{pool.endip}" if pool.startip and pool.endip else pool.startip,
                "mapped": f"{pool.source_startip}-{pool.source_endip}" if pool.source_startip else None,
                "match_reason": pool_direct_matches[(vdom, pool.name)],
            })
    for csnat in config.central_snat:
        vdom = _vdom_of(csnat)
        vdom_matches = matched_by_vdom[vdom]
        reasons = []
        for field_label, refs in (("orig_addr", csnat.orig_addr), ("dst_addr", csnat.dst_addr), ("nat_ippool", csnat.nat_ippool)):
            for reason in _match_ref_list(query, refs, vdom_matches):
                reasons.append(f"{field_label}: {reason}")
        if reasons:
            nat_rows.append({
                "kind": "Central SNAT",
                "name": f"Central SNAT #{csnat.policy_id}" if csnat.policy_id is not None else "Central SNAT",
                "vdom": vdom,
                "external": ", ".join(csnat.orig_addr or ()) or None,
                "mapped": ", ".join(csnat.nat_ippool or ()) or None,
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    # 4. Firewall / Security & Proxy Policies
    policy_rows: list[dict[str, Any]] = []
    for pol in config.policies:
        vdom = _vdom_of(pol)
        vdom_matches = matched_by_vdom[vdom]
        reasons = []
        if pol.name and (r := query_matches_name(query, pol.name)):
            reasons.append(f"policy name: {r}")
        for field_label, refs in (
            ("srcaddr", pol.srcaddr),
            ("dstaddr", pol.dstaddr),
            ("poolname", pol.poolname),
        ):
            for reason in _match_ref_list(query, refs, vdom_matches):
                reasons.append(f"{field_label}: {reason}")
        if pol.natip and (r := query_matches_ip_text(query, pol.natip)):
            reasons.append(f"natip {pol.natip}: {r}")
        if reasons:
            policy_rows.append({
                "policy_id": pol.policy_id,
                "name": pol.name or f"Policy #{pol.policy_id}",
                "vdom": vdom,
                "srcintf": list(pol.srcintf or ()),
                "dstintf": list(pol.dstintf or ()),
                "srcaddr": list(pol.srcaddr or ()),
                "dstaddr": list(pol.dstaddr or ()),
                "action": pol.action,
                "status": pol.status,
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    for ppol in config.proxy_policies:
        vdom = _vdom_of(ppol)
        vdom_matches = matched_by_vdom[vdom]
        reasons = []
        if ppol.name and (r := query_matches_name(query, ppol.name)):
            reasons.append(f"proxy policy name: {r}")
        for field_label, refs in (("srcaddr", ppol.srcaddr), ("dstaddr", ppol.dstaddr)):
            for reason in _match_ref_list(query, refs, vdom_matches):
                reasons.append(f"{field_label}: {reason}")
        if reasons:
            policy_rows.append({
                "policy_id": ppol.policy_id,
                "name": ppol.name or f"Proxy Policy #{ppol.policy_id}",
                "vdom": vdom,
                "srcintf": list(ppol.srcintf),
                "dstintf": list(ppol.dstintf),
                "srcaddr": list(ppol.srcaddr),
                "dstaddr": list(ppol.dstaddr),
                "action": ppol.action,
                "status": ppol.status,
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    # 5. Static Routes
    route_rows: list[dict[str, Any]] = []
    for route in config.static_routes:
        vdom = _vdom_of(route)
        vdom_matches = matched_by_vdom[vdom]
        reasons = []
        if route.dst and (r := query_matches_ip_text(query, route.dst)):
            reasons.append(f"dst {route.dst}: {r}")
        if route.gateway and (r := query_matches_ip_text(query, route.gateway)):
            reasons.append(f"gateway {route.gateway}: {r}")
        if route.dstaddr:
            if route.dstaddr in vdom_matches:
                reasons.append(f"dstaddr '{route.dstaddr}' ({vdom_matches[route.dstaddr]})")
            elif r := query_matches_name(query, route.dstaddr):
                reasons.append(f"dstaddr '{route.dstaddr}': {r}")
        if route.device and (r := query_matches_name(query, route.device)):
            reasons.append(f"device '{route.device}': {r}")
        if reasons:
            route_rows.append({
                "route_id": route.seq_num,
                "vdom": vdom,
                "destination": route.dst or route.dstaddr,
                "gateway": route.gateway,
                "device": route.device,
                "status": route.status,
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    # 6. VPN & Interfaces
    vpn_iface_rows: list[dict[str, Any]] = []
    for iface in config.interfaces:
        vdom = _vdom_of(iface)
        reasons = []
        if r := query_matches_name(query, iface.name):
            reasons.append(f"interface name: {r}")
        if iface.ip and (r := query_matches_ip_text(query, iface.ip)):
            reasons.append(f"ip {iface.ip}: {r}")
        for sec in iface.secondary_ips:
            if sec.ip and (r := query_matches_ip_text(query, sec.ip)):
                reasons.append(f"secondary ip {sec.ip}: {r}")
        if reasons:
            vpn_iface_rows.append({
                "kind": "Interface",
                "name": iface.name,
                "vdom": vdom,
                "endpoint_or_ip": iface.ip,
                "detail": iface.role or iface.type,
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    for p1 in (*config.ipsec_phase1, *config.ipsec_policy_phase1):
        vdom = _vdom_of(p1)
        reasons = []
        if r := query_matches_name(query, p1.name):
            reasons.append(f"tunnel name: {r}")
        if p1.remote_gw and (r := query_matches_ip_text(query, p1.remote_gw)):
            reasons.append(f"remote-gw {p1.remote_gw}: {r}")
        if p1.local_gw and (r := query_matches_ip_text(query, p1.local_gw)):
            reasons.append(f"local-gw {p1.local_gw}: {r}")
        if p1.interface and (r := query_matches_name(query, p1.interface)):
            reasons.append(f"interface '{p1.interface}': {r}")
        if reasons:
            vpn_iface_rows.append({
                "kind": "IPsec Phase 1",
                "name": p1.name,
                "vdom": vdom,
                "endpoint_or_ip": p1.remote_gw or p1.remotegw_ddns,
                "detail": f"Interface: {p1.interface or 'Not reported'}",
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    for p2 in (*config.ipsec_phase2, *config.ipsec_policy_phase2):
        vdom = _vdom_of(p2)
        vdom_matches = matched_by_vdom[vdom]
        reasons = []
        if r := query_matches_name(query, p2.name):
            reasons.append(f"phase2 name: {r}")
        if p2.phase1name and (r := query_matches_name(query, p2.phase1name)):
            reasons.append(f"phase1 '{p2.phase1name}': {r}")
        if p2.src_subnet and (r := query_matches_ip_text(query, p2.src_subnet)):
            reasons.append(f"src-subnet {p2.src_subnet}: {r}")
        if p2.dst_subnet and (r := query_matches_ip_text(query, p2.dst_subnet)):
            reasons.append(f"dst-subnet {p2.dst_subnet}: {r}")
        if (p2.src_start_ip or p2.src_end_ip) and (r := query_matches_ip_bounds(query, p2.src_start_ip, p2.src_end_ip)):
            reasons.append(f"src-range {p2.src_start_ip}-{p2.src_end_ip}: {r}")
        if (p2.dst_start_ip or p2.dst_end_ip) and (r := query_matches_ip_bounds(query, p2.dst_start_ip, p2.dst_end_ip)):
            reasons.append(f"dst-range {p2.dst_start_ip}-{p2.dst_end_ip}: {r}")
        for field_label, ref in (("src-name", p2.src_name), ("dst-name", p2.dst_name)):
            if ref:
                if ref in vdom_matches:
                    reasons.append(f"{field_label} '{ref}' ({vdom_matches[ref]})")
                elif r := query_matches_name(query, ref):
                    reasons.append(f"{field_label} '{ref}': {r}")
        if reasons:
            vpn_iface_rows.append({
                "kind": "IPsec Phase 2",
                "name": p2.name,
                "vdom": vdom,
                "endpoint_or_ip": f"{p2.src_subnet or p2.src_name or '*'} -> {p2.dst_subnet or p2.dst_name or '*'}",
                "detail": f"Phase 1: {p2.phase1name or 'Not reported'}",
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    categories = [
        {
            "key": "addresses_and_groups",
            "label": "Addresses & Groups",
            "count": len(addr_rows),
            "columns": ["kind", "name", "vdom", "value", "members", "match_reason"],
            "rows": addr_rows,
        },
        {
            "key": "nat_vip_pools",
            "label": "NAT / VIP / IP Pools",
            "count": len(nat_rows),
            "columns": ["kind", "name", "vdom", "external", "mapped", "match_reason"],
            "rows": nat_rows,
        },
        {
            "key": "policies",
            "label": "Firewall / Security Policies",
            "count": len(policy_rows),
            "columns": ["policy_id", "name", "vdom", "srcintf", "dstintf", "srcaddr", "dstaddr", "action", "status", "match_reason"],
            "rows": policy_rows,
        },
        {
            "key": "static_routes",
            "label": "Static Routes",
            "count": len(route_rows),
            "columns": ["route_id", "vdom", "destination", "gateway", "device", "status", "match_reason"],
            "rows": route_rows,
        },
        {
            "key": "vpn_and_interfaces",
            "label": "VPN & Interfaces",
            "count": len(vpn_iface_rows),
            "columns": ["kind", "name", "vdom", "endpoint_or_ip", "detail", "match_reason"],
            "rows": vpn_iface_rows,
        },
    ]
    resolved_objects = sorted({name for vdom_map in matched_by_vdom.values() for name in vdom_map})
    total_matches = sum(cat["count"] for cat in categories)
    return {
        "vendor": "fortigate",
        "query": query.raw,
        "query_type": query.mode,
        "resolved_objects": resolved_objects,
        "total_matches": total_matches,
        "categories": categories,
    }
