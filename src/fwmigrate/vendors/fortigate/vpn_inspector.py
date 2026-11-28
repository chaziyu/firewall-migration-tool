"""FortiGate Site-to-Site VPN 'All-in-One' 4-layer inspector and misconfiguration checker."""

from __future__ import annotations

from typing import Any

from ...source_reporting.ip_match import weak_crypto_findings
from .derived import DerivedViews
from .model.source import FGConfig


def _vdom_of(item: Any) -> str:
    return getattr(item, "vdom", None) or "root"


def _is_disabled_status(status: Any) -> bool:
    return str(status or "").strip().lower() in {"disable", "disabled", "down", "no"}


def _inspect_tunnel(
    p1: Any,
    *,
    vpn_mode: str,
    phase2_items: list[Any],
    normalized_p2: dict[tuple[str, str, str], Any],
    interfaces_by_key: dict[tuple[str, str], Any],
    zones_by_vdom: dict[str, list[Any]],
    routes_by_vdom: dict[str, list[Any]],
    policies_by_vdom: dict[str, list[Any]],
    csnat_by_vdom: dict[str, list[Any]],
) -> dict[str, Any]:
    vdom = _vdom_of(p1)
    iface = interfaces_by_key.get((vdom, p1.name)) if vpn_mode == "route-based" else None

    # Zones containing this tunnel interface (or policy-based underlying interface)
    zone_names = sorted({
        zone.name
        for zone in zones_by_vdom.get(vdom, ())
        if p1.name in (zone.members or ())
    })
    match_intf_names = {p1.name, *zone_names}

    # Layer 1: Phase 1 + Phase 2
    p1_detail = {
        "name": p1.name,
        "vpn_mode": vpn_mode,
        "type": p1.type,
        "ike_version": p1.ike_version,
        "mode": p1.mode,
        "authmethod": p1.authmethod,
        "interface": p1.interface,
        "local_gw": p1.local_gw,
        "remote_gateway": p1.remote_gw or p1.remotegw_ddns,
        "proposal": list(p1.proposal),
        "dh_groups": list(p1.dhgrp) if p1.dhgrp is not None else [],
        "nattraversal": p1.nattraversal,
        "dpd": p1.dpd,
        "keylife": p1.keylife,
    }

    p2_rows: list[dict[str, Any]] = []
    for p2 in phase2_items:
        norm = normalized_p2.get((vpn_mode, vdom, p2.name))
        local_sel = (
            (norm.source_range if norm else None)
            or p2.src_subnet
            or (f"{p2.src_start_ip}-{p2.src_end_ip}" if p2.src_start_ip and p2.src_end_ip else None)
            or p2.src_name
        )
        remote_sel = (
            (norm.destination_range if norm else None)
            or p2.dst_subnet
            or (f"{p2.dst_start_ip}-{p2.dst_end_ip}" if p2.dst_start_ip and p2.dst_end_ip else None)
            or p2.dst_name
        )
        p2_rows.append({
            "name": p2.name,
            "phase1": p2.phase1name,
            "local_selector": local_sel,
            "remote_selector": remote_sel,
            "proposal": list(p2.proposal),
            "pfs": p2.pfs,
            "dh_groups": list(p2.dhgrp) if p2.dhgrp is not None else [],
            "auto_negotiate": p2.auto_negotiate,
        })

    # Layer 2: Tunnel Interface, Zone & VR/VRF Binding
    vrf = iface.vrf if iface is not None and iface.vrf is not None else None
    binding = {
        "tunnel_interface": iface.name if iface is not None else (p1.name if vpn_mode == "route-based" else None),
        "tunnel_interface_found": iface is not None,
        "tunnel_ip": iface.ip if iface is not None else None,
        "interface_status": iface.status if iface is not None else None,
        "underlying_interface": p1.interface,
        "zones": zone_names,
        "virtual_router": f"VRF {vrf}" if vrf is not None else f"VDOM {vdom}",
    }

    # Layer 3: Static Routes pointing to the tunnel
    route_rows: list[dict[str, Any]] = []
    for route in routes_by_vdom.get(vdom, ()):
        if route.device in match_intf_names:
            route_rows.append({
                "route_id": route.seq_num,
                "destination": route.dst or route.dstaddr,
                "gateway": route.gateway,
                "device": route.device,
                "distance": route.distance,
                "status": route.status,
            })

    # Layer 4: Firewall Policies (interface + zone membership)
    policy_rows: list[dict[str, Any]] = []
    nat_exposures: list[dict[str, Any]] = []
    for pol in policies_by_vdom.get(vdom, ()):
        src_match = [i for i in (pol.srcintf or ()) if i in match_intf_names]
        dst_match = [i for i in (pol.dstintf or ()) if i in match_intf_names]
        vpntunnel_match = pol.vpntunnel == p1.name
        if src_match or dst_match or vpntunnel_match:
            policy_rows.append({
                "policy_id": pol.policy_id,
                "name": pol.name,
                "srcintf": list(pol.srcintf or ()),
                "dstintf": list(pol.dstintf or ()),
                "srcaddr": list(pol.srcaddr or ()),
                "dstaddr": list(pol.dstaddr or ()),
                "services": list(pol.service or ()),
                "action": pol.action,
                "nat": pol.nat,
                "status": pol.status,
                "matched_zones": sorted({z for z in (*src_match, *dst_match) if z in zone_names}),
            })
            if (
                not _is_disabled_status(pol.status)
                and str(pol.action or "").strip().lower() == "accept"
                and str(pol.nat or "").strip().lower() == "enable"
            ):
                nat_exposures.append({
                    "kind": "Policy NAT",
                    "policy_id": pol.policy_id,
                    "name": pol.name or f"Policy #{pol.policy_id}",
                    "detail": "Firewall policy referencing tunnel has nat=enable",
                })

    for csnat in csnat_by_vdom.get(vdom, ()):
        if (
            not _is_disabled_status(csnat.status)
            and str(csnat.nat or "").strip().lower() != "disable"
            and any(intf in match_intf_names for intf in (csnat.dstintf or ()))
        ):
            nat_exposures.append({
                "kind": "Central SNAT",
                "policy_id": csnat.policy_id,
                "name": f"Central SNAT #{csnat.policy_id}" if csnat.policy_id is not None else "Central SNAT",
                "detail": f"Central SNAT rule targets {', '.join(csnat.dstintf or ())}",
            })

    # Automated Misconfiguration Checks
    findings: list[dict[str, str]] = []
    p1_raw_status = (p1.raw_extra or {}).get("status") if isinstance(p1.raw_extra, dict) else None
    tunnel_disabled = _is_disabled_status(p1_raw_status) or (
        iface is not None and _is_disabled_status(iface.status)
    )
    if tunnel_disabled:
        findings.append({
            "severity": "critical",
            "code": "TUNNEL_DISABLED",
            "message": "Tunnel or its virtual tunnel interface is administratively disabled.",
        })

    if not p2_rows:
        findings.append({
            "severity": "critical",
            "code": "MISSING_PHASE2",
            "message": "No Phase 2 selectors are bound to this Phase 1 gateway.",
        })

    if not p1.interface or (vpn_mode == "route-based" and interfaces_by_key and iface is None):
        findings.append({
            "severity": "warning",
            "code": "MISSING_TUNNEL_BINDING",
            "message": (
                "Phase 1 has no underlying interface binding."
                if not p1.interface
                else f"Tunnel interface '{p1.name}' was not found in system interfaces."
            ),
        })

    is_dynamic_dialup = str(p1.type or "").strip().lower() == "dynamic"
    if vpn_mode == "route-based" and not is_dynamic_dialup and not any(
        not _is_disabled_status(r.get("status")) for r in route_rows
    ):
        findings.append({
            "severity": "warning",
            "code": "MISSING_STATIC_ROUTE",
            "message": f"No active static route points to tunnel '{p1.name}' (or its zones).",
        })

    has_accept_policy = any(
        not _is_disabled_status(p.get("status"))
        and str(p.get("action") or "").strip().lower() == "accept"
        for p in policy_rows
    )
    if not has_accept_policy:
        findings.append({
            "severity": "warning",
            "code": "MISSING_ALLOW_POLICY",
            "message": "No enabled firewall policy with action=accept references this tunnel or its zones.",
        })

    for exposure in nat_exposures:
        findings.append({
            "severity": "warning",
            "code": "ACCIDENTAL_NAT",
            "message": f"Possible accidental SNAT on site-to-site traffic: {exposure['name']} ({exposure['detail']}).",
        })

    if str(p1.ike_version or "").strip() == "1":
        findings.append({
            "severity": "warning",
            "code": "LEGACY_IKEV1",
            "message": "Tunnel uses legacy IKEv1; prefer IKEv2 where supported.",
        })

    weak_p1 = weak_crypto_findings(p1.proposal, p1.dhgrp or ())
    if weak_p1:
        findings.append({
            "severity": "warning",
            "code": "WEAK_CRYPTO",
            "message": f"Weak Phase 1 cipher/DH algorithms detected: {', '.join(weak_p1)}.",
        })

    weak_p2: list[str] = []
    for p2 in phase2_items:
        weak_p2.extend(weak_crypto_findings(p2.proposal, p2.dhgrp or ()))
    weak_p2_unique = list(dict.fromkeys(weak_p2))
    if weak_p2_unique:
        findings.append({
            "severity": "warning",
            "code": "WEAK_CRYPTO",
            "message": f"Weak Phase 2 cipher/DH algorithms detected: {', '.join(weak_p2_unique)}.",
        })

    if tunnel_disabled:
        health = "disabled"
    elif any(f["severity"] == "critical" for f in findings):
        health = "critical"
    elif any(f["severity"] == "warning" for f in findings):
        health = "warning"
    else:
        health = "healthy"

    return {
        "health": health,
        "name": p1.name,
        "vdom": vdom,
        "vpn_mode": vpn_mode,
        "remote_gateway": p1_detail["remote_gateway"],
        "ike_version": p1.ike_version,
        "tunnel_interface": binding["tunnel_interface"] or p1.interface,
        "zones": zone_names,
        "virtual_router": binding["virtual_router"],
        "phase2_count": len(p2_rows),
        "route_count": len(route_rows),
        "policy_count": len(policy_rows),
        "finding_count": len(findings),
        "phase1": p1_detail,
        "phase2": p2_rows,
        "binding": binding,
        "routes": route_rows,
        "policies": policy_rows,
        "nat_exposures": nat_exposures,
        "findings": findings,
    }


def build_fortigate_vpn_inspector(config: FGConfig, derived: DerivedViews) -> list[dict[str, Any]]:
    """Build stitched 4-layer VPN inspector rows for all FortiGate IPsec tunnels."""
    interfaces_by_key = {(_vdom_of(iface), iface.name): iface for iface in config.interfaces}

    zones_by_vdom: dict[str, list[Any]] = {}
    for zone in config.zones:
        zones_by_vdom.setdefault(_vdom_of(zone), []).append(zone)

    routes_by_vdom: dict[str, list[Any]] = {}
    for route in config.static_routes:
        routes_by_vdom.setdefault(_vdom_of(route), []).append(route)

    policies_by_vdom: dict[str, list[Any]] = {}
    for pol in config.policies:
        policies_by_vdom.setdefault(_vdom_of(pol), []).append(pol)

    csnat_by_vdom: dict[str, list[Any]] = {}
    for item in config.central_snat:
        csnat_by_vdom.setdefault(_vdom_of(item), []).append(item)

    p2_route_map: dict[tuple[str, str], list[Any]] = {}
    for p2 in config.ipsec_phase2:
        if p2.phase1name:
            p2_route_map.setdefault((_vdom_of(p2), p2.phase1name), []).append(p2)

    p2_policy_map: dict[tuple[str, str], list[Any]] = {}
    for p2 in config.ipsec_policy_phase2:
        if p2.phase1name:
            p2_policy_map.setdefault((_vdom_of(p2), p2.phase1name), []).append(p2)

    normalized_p2 = {(item.vpn_type, item.vdom, item.name): item for item in derived.vpn.phase2}

    rows: list[dict[str, Any]] = []
    for p1 in config.ipsec_phase1:
        rows.append(_inspect_tunnel(
            p1,
            vpn_mode="route-based",
            phase2_items=p2_route_map.get((_vdom_of(p1), p1.name), []),
            normalized_p2=normalized_p2,
            interfaces_by_key=interfaces_by_key,
            zones_by_vdom=zones_by_vdom,
            routes_by_vdom=routes_by_vdom,
            policies_by_vdom=policies_by_vdom,
            csnat_by_vdom=csnat_by_vdom,
        ))
    for p1 in config.ipsec_policy_phase1:
        rows.append(_inspect_tunnel(
            p1,
            vpn_mode="policy-based",
            phase2_items=p2_policy_map.get((_vdom_of(p1), p1.name), []),
            normalized_p2=normalized_p2,
            interfaces_by_key=interfaces_by_key,
            zones_by_vdom=zones_by_vdom,
            routes_by_vdom=routes_by_vdom,
            policies_by_vdom=policies_by_vdom,
            csnat_by_vdom=csnat_by_vdom,
        ))
    return rows
