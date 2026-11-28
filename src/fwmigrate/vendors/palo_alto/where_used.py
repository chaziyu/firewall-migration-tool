"""Palo Alto PAN-OS global IP / object 'Where-Used' search across extracted source state."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ...source_reporting.ip_match import (
    ParsedQuery,
    parse_where_used_query,
    query_matches_ip_text,
    query_matches_name,
)
from .model.source import PANOSConfig
from .source_model import PANScope, pan_scope_identity


def _scope_str(scope: PANScope | None) -> str:
    return pan_scope_identity(scope) if scope else "<unscoped>"


def _is_inheritable_scope(scope: PANScope | None) -> bool:
    if scope is None:
        return True
    return scope.kind in {"shared", "device-group"}


def _lookup_match(
    ref: str,
    scope: str,
    matched_by_scope: dict[str, dict[str, str]],
    matched_shared: dict[str, str],
) -> str | None:
    return matched_by_scope.get(scope, {}).get(ref) or matched_shared.get(ref)


def _match_refs(
    query: ParsedQuery,
    refs: list[str] | tuple[str, ...] | None,
    scope: str,
    matched_by_scope: dict[str, dict[str, str]],
    matched_shared: dict[str, str],
) -> list[str]:
    reasons: list[str] = []
    for ref in refs or ():
        resolved = _lookup_match(ref, scope, matched_by_scope, matched_shared)
        if resolved:
            reasons.append(f"object '{ref}' ({resolved})")
        else:
            direct = query_matches_ip_text(query, ref) or query_matches_name(query, ref)
            if direct:
                reasons.append(f"'{ref}' ({direct})")
    return reasons


def _dict_strings(mapping: dict[str, Any] | None) -> list[str]:
    if not isinstance(mapping, dict):
        return []
    out: list[str] = []
    for value in mapping.values():
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
        elif isinstance(value, dict):
            out.extend(_dict_strings(value))
    return out


def search_paloalto_where_used(config: PANOSConfig, query_text: str) -> dict[str, Any]:
    """Resolve IP/CIDR/range/object references across Palo Alto PAN-OS configuration layers."""
    query = parse_where_used_query(query_text)
    matched_by_scope: dict[str, dict[str, str]] = defaultdict(dict)
    matched_shared: dict[str, str] = {}

    def record_match(scope_obj: PANScope | None, name: str | None, reason: str) -> None:
        if not name:
            return
        sc = _scope_str(scope_obj)
        matched_by_scope[sc].setdefault(name, reason)
        if _is_inheritable_scope(scope_obj):
            matched_shared.setdefault(name, reason)

    # 1. Direct address matches
    addr_rows: list[dict[str, Any]] = []
    for addr in config.addresses:
        sc = _scope_str(addr.scope)
        reasons: list[str] = []
        if addr.name and (r := query_matches_name(query, addr.name)):
            reasons.append(r)
        for field_label, val in (
            ("ip-netmask", addr.ip_netmask),
            ("ip-range", addr.ip_range),
            ("ip-wildcard", addr.ip_wildcard),
        ):
            if val and (r := query_matches_ip_text(query, val)):
                reasons.append(f"{field_label} {val}: {r}")
        if addr.fqdn and (r := query_matches_name(query, addr.fqdn)):
            reasons.append(f"fqdn {addr.fqdn}: {r}")
        if reasons:
            reason_text = "; ".join(dict.fromkeys(reasons))
            record_match(addr.scope, addr.name, reason_text)
            addr_rows.append({
                "kind": "Address",
                "name": addr.name,
                "scope": sc,
                "value": addr.ip_netmask or addr.ip_range or addr.ip_wildcard or addr.fqdn,
                "members": None,
                "match_reason": reason_text,
            })

    # 2. Recursive upward address-group expansion (cycle-safe)
    group_reasons: dict[tuple[str, str], list[str]] = defaultdict(list)
    for grp in config.address_groups:
        sc = _scope_str(grp.scope)
        if grp.name and (r := query_matches_name(query, grp.name)):
            group_reasons[(sc, grp.name)].append(r)
            record_match(grp.scope, grp.name, r)

    changed = True
    while changed:
        changed = False
        for grp in config.address_groups:
            if not grp.name:
                continue
            sc = _scope_str(grp.scope)
            for member in grp.static_members or ():
                resolved = _lookup_match(member, sc, matched_by_scope, matched_shared)
                if resolved:
                    msg = f"contains member '{member}' ({resolved})"
                    if msg not in group_reasons[(sc, grp.name)]:
                        group_reasons[(sc, grp.name)].append(msg)
                    if grp.name not in matched_by_scope[sc]:
                        record_match(grp.scope, grp.name, msg)
                        changed = True

    for grp in config.address_groups:
        sc = _scope_str(grp.scope)
        if grp.name and (sc, grp.name) in group_reasons:
            addr_rows.append({
                "kind": "Address Group",
                "name": grp.name,
                "scope": sc,
                "value": f"{len(grp.static_members or ())} members",
                "members": list(grp.static_members or ()),
                "match_reason": "; ".join(dict.fromkeys(group_reasons[(sc, grp.name)])),
            })

    # 3. NAT Rules
    nat_rows: list[dict[str, Any]] = []
    for nat in config.nat_rules:
        sc = _scope_str(nat.scope)
        reasons = []
        if nat.name and (r := query_matches_name(query, nat.name)):
            reasons.append(f"nat rule name: {r}")
        for label, refs in (("source", nat.source), ("destination", nat.destination)):
            for reason in _match_refs(query, refs, sc, matched_by_scope, matched_shared):
                reasons.append(f"{label}: {reason}")
        translated_refs: list[str] = []
        st = nat.source_translation
        if st is not None:
            translated_refs.extend(getattr(st, "translated_addresses", None) or ())
            if getattr(st, "translated_address", None):
                translated_refs.append(st.translated_address)
            if getattr(st, "ip", None):
                translated_refs.append(st.ip)
        if nat.destination_translation and nat.destination_translation.translated_address:
            translated_refs.append(nat.destination_translation.translated_address)
        if nat.dynamic_destination_translation and nat.dynamic_destination_translation.translated_addresses:
            translated_refs.extend(nat.dynamic_destination_translation.translated_addresses)
        for reason in _match_refs(query, translated_refs, sc, matched_by_scope, matched_shared):
            reasons.append(f"translated: {reason}")
        if reasons:
            nat_rows.append({
                "kind": "NAT Rule",
                "name": nat.name,
                "scope": sc,
                "source": list(nat.source or ()),
                "destination": list(nat.destination or ()),
                "translated": translated_refs,
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    # 4. Security Policies
    policy_rows: list[dict[str, Any]] = []
    for rule in config.security_rules:
        sc = _scope_str(rule.scope)
        reasons = []
        if rule.name and (r := query_matches_name(query, rule.name)):
            reasons.append(f"rule name: {r}")
        for label, refs in (("source", rule.source), ("destination", rule.destination)):
            for reason in _match_refs(query, refs, sc, matched_by_scope, matched_shared):
                reasons.append(f"{label}: {reason}")
        if reasons:
            policy_rows.append({
                "name": rule.name,
                "scope": sc,
                "from_zones": list(rule.from_zones or ()),
                "to_zones": list(rule.to_zones or ()),
                "source": list(rule.source or ()),
                "destination": list(rule.destination or ()),
                "action": rule.action,
                "disabled": rule.disabled,
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    # 5. Static Routes (Virtual Routers & Logical Routers)
    route_rows: list[dict[str, Any]] = []

    def check_routes(router_name: str | None, router_scope: PANScope | None, routes: list[Any] | None) -> None:
        sc = _scope_str(router_scope)
        for route in routes or ():
            reasons = []
            if route.name and (r := query_matches_name(query, route.name)):
                reasons.append(f"route name: {r}")
            if route.destination and (r := query_matches_ip_text(query, route.destination)):
                reasons.append(f"destination {route.destination}: {r}")
            for nh_label, nh_val in (("nexthop-ip", route.nexthop_ip_address), ("nexthop", route.nexthop)):
                if nh_val and (r := query_matches_ip_text(query, nh_val)):
                    reasons.append(f"{nh_label} {nh_val}: {r}")
            if route.interface and (r := query_matches_name(query, route.interface)):
                reasons.append(f"interface '{route.interface}': {r}")
            if reasons:
                route_rows.append({
                    "route_id": route.name,
                    "scope": sc,
                    "router": router_name,
                    "destination": route.destination,
                    "gateway": route.nexthop_ip_address or route.nexthop,
                    "device": route.interface,
                    "match_reason": "; ".join(dict.fromkeys(reasons)),
                })

    for vr in config.virtual_routers:
        check_routes(vr.name, vr.scope, vr.static_routes)
    for lr in config.logical_routers:
        for vrf in lr.vrfs or ():
            check_routes(f"{lr.name}/{vrf.name}" if vrf.name else lr.name, lr.scope, vrf.static_routes)

    # 6. VPN & Interfaces
    vpn_iface_rows: list[dict[str, Any]] = []
    for iface in (*config.interfaces, *config.interface_units):
        sc = _scope_str(iface.scope)
        reasons = []
        if iface.name and (r := query_matches_name(query, iface.name)):
            reasons.append(f"interface name: {r}")
        for ip_val in iface.ipv4_addresses or ():
            if r := query_matches_ip_text(query, ip_val):
                reasons.append(f"ip {ip_val}: {r}")
        if reasons:
            vpn_iface_rows.append({
                "kind": "Interface",
                "name": iface.name,
                "scope": sc,
                "endpoint_or_ip": ", ".join(iface.ipv4_addresses or ()) or None,
                "detail": iface.interface_family,
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    for gw in config.ike_gateways:
        sc = _scope_str(gw.scope)
        reasons = []
        if gw.name and (r := query_matches_name(query, gw.name)):
            reasons.append(f"ike-gateway: {r}")
        if gw.peer_address and (r := query_matches_ip_text(query, gw.peer_address)):
            reasons.append(f"peer {gw.peer_address}: {r}")
        if gw.local_ip and (r := query_matches_ip_text(query, gw.local_ip)):
            reasons.append(f"local-ip {gw.local_ip}: {r}")
        if gw.local_interface and (r := query_matches_name(query, gw.local_interface)):
            reasons.append(f"local-interface '{gw.local_interface}': {r}")
        if reasons:
            vpn_iface_rows.append({
                "kind": "IKE Gateway",
                "name": gw.name,
                "scope": sc,
                "endpoint_or_ip": gw.peer_address,
                "detail": f"Interface: {gw.local_interface or 'Not reported'}",
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    for tunnel in config.ipsec_tunnels:
        sc = _scope_str(tunnel.scope)
        reasons = []
        if tunnel.name and (r := query_matches_name(query, tunnel.name)):
            reasons.append(f"ipsec-tunnel: {r}")
        if tunnel.tunnel_interface and (r := query_matches_name(query, tunnel.tunnel_interface)):
            reasons.append(f"tunnel-interface '{tunnel.tunnel_interface}': {r}")
        if tunnel.tunnel_monitor_destination_ip and (
            r := query_matches_ip_text(query, tunnel.tunnel_monitor_destination_ip)
        ):
            reasons.append(f"monitor-dst {tunnel.tunnel_monitor_destination_ip}: {r}")
        for proxy in tunnel.proxy_ids or ():
            if proxy.local and (r := query_matches_ip_text(query, proxy.local)):
                reasons.append(f"proxy-id '{proxy.name or ''}' local {proxy.local}: {r}")
            if proxy.remote and (r := query_matches_ip_text(query, proxy.remote)):
                reasons.append(f"proxy-id '{proxy.name or ''}' remote {proxy.remote}: {r}")
        if reasons:
            vpn_iface_rows.append({
                "kind": "IPsec Tunnel",
                "name": tunnel.name,
                "scope": sc,
                "endpoint_or_ip": tunnel.tunnel_interface,
                "detail": f"Gateways: {', '.join(tunnel.ike_gateways or ()) or 'None'}",
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    for gre in config.gre_tunnels:
        sc = _scope_str(gre.scope)
        reasons = []
        if gre.name and (r := query_matches_name(query, gre.name)):
            reasons.append(f"gre-tunnel: {r}")
        if gre.tunnel_interface and (r := query_matches_name(query, gre.tunnel_interface)):
            reasons.append(f"tunnel-interface '{gre.tunnel_interface}': {r}")
        for label, addr_dict in (("local", gre.local_address), ("peer", gre.peer_address)):
            for candidate in _dict_strings(addr_dict):
                if r := query_matches_ip_text(query, candidate):
                    reasons.append(f"{label} {candidate}: {r}")
        if reasons:
            vpn_iface_rows.append({
                "kind": "GRE Tunnel",
                "name": gre.name,
                "scope": sc,
                "endpoint_or_ip": ", ".join(_dict_strings(gre.peer_address)) or gre.tunnel_interface,
                "detail": f"Interface: {gre.tunnel_interface or 'Not reported'}",
                "match_reason": "; ".join(dict.fromkeys(reasons)),
            })

    categories = [
        {
            "key": "addresses_and_groups",
            "label": "Addresses & Groups",
            "count": len(addr_rows),
            "columns": ["kind", "name", "scope", "value", "members", "match_reason"],
            "rows": addr_rows,
        },
        {
            "key": "nat_vip_pools",
            "label": "NAT / VIP / IP Pools",
            "count": len(nat_rows),
            "columns": ["kind", "name", "scope", "source", "destination", "translated", "match_reason"],
            "rows": nat_rows,
        },
        {
            "key": "policies",
            "label": "Firewall / Security Policies",
            "count": len(policy_rows),
            "columns": ["name", "scope", "from_zones", "to_zones", "source", "destination", "action", "disabled", "match_reason"],
            "rows": policy_rows,
        },
        {
            "key": "static_routes",
            "label": "Static Routes",
            "count": len(route_rows),
            "columns": ["route_id", "scope", "router", "destination", "gateway", "device", "match_reason"],
            "rows": route_rows,
        },
        {
            "key": "vpn_and_interfaces",
            "label": "VPN & Interfaces",
            "count": len(vpn_iface_rows),
            "columns": ["kind", "name", "scope", "endpoint_or_ip", "detail", "match_reason"],
            "rows": vpn_iface_rows,
        },
    ]
    resolved_objects = sorted({name for sc_map in matched_by_scope.values() for name in sc_map})
    total_matches = sum(cat["count"] for cat in categories)
    return {
        "vendor": "palo_alto",
        "query": query.raw,
        "query_type": query.mode,
        "resolved_objects": resolved_objects,
        "total_matches": total_matches,
        "categories": categories,
    }
