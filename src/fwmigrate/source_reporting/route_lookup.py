"""Longest-Prefix-Match (LPM) Route Lookup for FortiGate and Palo Alto configs."""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Any

from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig


def _parse_int(val: Any, default: int) -> int:
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return default


def _parse_network(cidr_or_mask: str | None) -> IPv4Network | IPv6Network | None:
    raw = str(cidr_or_mask or "").strip()
    if not raw or raw in ("-", "none"):
        return None
    normalized = raw.replace(" ", "/", 1) if " " in raw and "/" not in raw else raw
    try:
        return ip_network(normalized, strict=False)
    except ValueError:
        return None


def lookup_fortigate_route(
    config: FGConfig,
    dest_ip: str,
    *,
    vdom: str | None = None,
) -> dict[str, Any]:
    """Perform LPM route lookup across FortiGate connected interfaces and static routes."""
    raw_ip = (dest_ip or "").strip()
    try:
        target = ip_address(raw_ip)
    except ValueError:
        return {"valid": False, "vendor": "fortigate", "error": f"Invalid IP address: '{raw_ip}'."}

    vdom_filter = (vdom or "").strip()
    vdom_set: set[str] = set()
    addr_subnets: dict[str, str] = {}
    for addr in config.addresses:
        if addr.subnet:
            addr_subnets[(addr.vdom or "root", addr.name)] = addr.subnet

    candidates: list[dict[str, Any]] = []

    for iface in config.interfaces:
        iface_vdom = iface.vdom or "root"
        vdom_set.add(iface_vdom)
        if vdom_filter and vdom_filter.lower() != "all" and iface_vdom.lower() != vdom_filter.lower():
            continue
        if (iface.type or "").strip().lower() == "zone":
            continue
        if (iface.status or "enable").strip().lower() in ("disable", "disabled", "down"):
            continue

        ip_candidates: list[str] = []
        if iface.ip:
            ip_candidates.append(iface.ip)
        for sec in iface.secondary_ips:
            if sec.ip:
                ip_candidates.append(sec.ip)
        if iface.ipv6 and iface.ipv6.ip6_address:
            ip_candidates.append(iface.ipv6.ip6_address)

        for ip_str in ip_candidates:
            net = _parse_network(ip_str)
            if net is None or net.version != target.version:
                continue
            if target in net:
                candidates.append(
                    {
                        "vdom": iface_vdom,
                        "type": "Connected",
                        "destination": str(net),
                        "prefix_len": net.prefixlen,
                        "gateway": "Directly Connected",
                        "interface": iface.name,
                        "distance": 0,
                        "priority": 0,
                        "comment": iface.alias or iface.description or "-",
                        "_sort": (-net.prefixlen, 0, 0),
                    }
                )

    for sr in config.static_routes:
        sr_vdom = sr.vdom or "root"
        vdom_set.add(sr_vdom)
        if vdom_filter and vdom_filter.lower() != "all" and sr_vdom.lower() != vdom_filter.lower():
            continue
        if (sr.status or "enable").strip().lower() in ("disable", "disabled"):
            continue

        dst_spec = sr.dst or (addr_subnets.get((sr_vdom, sr.dstaddr)) if sr.dstaddr else None)
        net = _parse_network(dst_spec)
        if net is None or net.version != target.version:
            continue
        if target in net:
            dist = sr.distance if sr.distance is not None else 10
            prio = sr.priority if sr.priority is not None else 0
            is_blackhole = (sr.blackhole or "").strip().lower() == "enable"
            gateway = "Blackhole" if is_blackhole else (sr.gateway or "-")
            iface_name = sr.device or ("blackhole" if is_blackhole else "-")
            candidates.append(
                {
                    "vdom": sr_vdom,
                    "type": "Blackhole" if is_blackhole else "Static",
                    "destination": str(net),
                    "prefix_len": net.prefixlen,
                    "gateway": gateway,
                    "interface": iface_name,
                    "distance": dist,
                    "priority": prio,
                    "comment": sr.comment or "-",
                    "_sort": (-net.prefixlen, dist, prio),
                }
            )

    candidates.sort(key=lambda c: c["_sort"])
    for cand in candidates:
        cand.pop("_sort", None)

    active_pr = sum(
        1
        for pr in config.policy_routes
        if (not vdom_filter or vdom_filter.lower() == "all" or (pr.vdom or "root").lower() == vdom_filter.lower())
        and (pr.status or "enable").strip().lower() not in ("disable", "disabled")
    )

    return {
        "valid": True,
        "vendor": "fortigate",
        "dest_ip": str(target),
        "winner": candidates[0] if candidates else None,
        "candidates": candidates,
        "active_policy_routes": active_pr,
        "vdoms": sorted(vdom_set or {"root"}),
    }


def _pa_interface_networks(config: PANOSConfig) -> dict[str, list[IPv4Network | IPv6Network]]:
    iface_nets: dict[str, list[IPv4Network | IPv6Network]] = {}

    def _add(name: str | None, ip_str: str | None) -> None:
        if not name:
            return
        net = _parse_network(ip_str)
        if net is not None:
            iface_nets.setdefault(name.strip(), []).append(net)

    for iface in config.interfaces:
        if (iface.link_state or "").strip().lower() == "down":
            continue
        for ip_str in iface.ipv4_addresses or []:
            _add(iface.name, ip_str)
        for ip6 in iface.ipv6_addresses or []:
            if (ip6.enable or "yes").lower() != "no":
                _add(iface.name, ip6.address)

    for unit in config.interface_units:
        for ip_str in unit.ipv4_addresses or []:
            _add(unit.name, ip_str)
        for ip6 in unit.ipv6_addresses or []:
            if (ip6.enable or "yes").lower() != "no":
                _add(unit.name, ip6.address)

    return iface_nets


def _extract_raw_interfaces(raw_extra: dict[str, Any]) -> list[str]:
    raw_intf = raw_extra.get("interface")
    if isinstance(raw_intf, list):
        return [str(x).strip() for x in raw_intf if str(x).strip()]
    if isinstance(raw_intf, dict):
        members = raw_intf.get("member")
        if isinstance(members, list):
            return [str(x).strip() for x in members if str(x).strip()]
        if isinstance(members, str) and members.strip():
            return [members.strip()]
    return []


def lookup_paloalto_route(
    config: PANOSConfig,
    dest_ip: str,
    *,
    virtual_router: str = "all",
) -> dict[str, Any]:
    """Perform LPM route lookup across Palo Alto Virtual Routers and Logical Routers."""
    raw_ip = (dest_ip or "").strip()
    try:
        target = ip_address(raw_ip)
    except ValueError:
        return {"valid": False, "vendor": "palo_alto", "error": f"Invalid IP address: '{raw_ip}'."}

    iface_nets = _pa_interface_networks(config)
    vr_filter = (virtual_router or "all").strip()
    vr_names: list[str] = []
    candidates: list[dict[str, Any]] = []

    def _eval_router(router_name: str, interfaces: list[str], static_routes: list[Any], static_ad: int) -> None:
        if router_name not in vr_names:
            vr_names.append(router_name)
        if vr_filter.lower() != "all" and router_name.lower() != vr_filter.lower():
            return

        for iname in interfaces:
            for net in iface_nets.get(iname.strip(), []):
                if net.version == target.version and target in net:
                    candidates.append(
                        {
                            "virtual_router": router_name,
                            "type": "Connected",
                            "route_name": f"connected ({iname.strip()})",
                            "destination": str(net),
                            "prefix_len": net.prefixlen,
                            "next_hop": "Directly Connected",
                            "interface": iname.strip(),
                            "ad": 0,
                            "metric": 0,
                            "_sort": (-net.prefixlen, 0, 0),
                        }
                    )

        for sr in static_routes:
            net = _parse_network(sr.destination)
            if net is None or net.version != target.version:
                continue
            if target in net:
                ad = _parse_int(sr.admin_distance, static_ad)
                metric = _parse_int(sr.metric, 10)
                nh_type = sr.nexthop_type or "-"
                nh_val = sr.nexthop_ip_address or sr.nexthop or "-"
                nh_display = f"{nh_type}: {nh_val}" if nh_type not in ("-", "none") and nh_val != "-" else (nh_type if nh_type != "-" else nh_val)
                candidates.append(
                    {
                        "virtual_router": router_name,
                        "type": "Static",
                        "route_name": sr.name or "-",
                        "destination": str(net),
                        "prefix_len": net.prefixlen,
                        "next_hop": nh_display,
                        "interface": sr.interface or "-",
                        "ad": ad,
                        "metric": metric,
                        "_sort": (-net.prefixlen, ad, metric),
                    }
                )

    for vr in config.virtual_routers:
        vr_name = vr.name or "default"
        ad_map = vr.admin_dists or {}
        static_ad = _parse_int(ad_map.get("static"), 10)
        _eval_router(vr_name, vr.interfaces or [], vr.static_routes or [], static_ad)

    for lr in config.logical_routers:
        lr_name = lr.name or "default"
        for vrf in lr.vrfs or []:
            vrf_label = f"{lr_name}/{vrf.name}" if vrf.name else lr_name
            vrf_intfs = _extract_raw_interfaces(vrf.raw_extra or {})
            _eval_router(vrf_label, vrf_intfs, vrf.static_routes or [], 10)

    candidates.sort(key=lambda c: c["_sort"])
    for cand in candidates:
        cand.pop("_sort", None)

    return {
        "valid": True,
        "vendor": "palo_alto",
        "dest_ip": str(target),
        "winner": candidates[0] if candidates else None,
        "candidates": candidates,
        "virtual_routers": sorted(vr_names),
    }
