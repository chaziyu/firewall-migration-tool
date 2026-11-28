"""Palo Alto PAN-OS Site-to-Site IPSec VPN 'All-in-One' 4-layer inspector."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ...source_reporting.ip_match import weak_crypto_findings
from .model.source import PANOSConfig
from .source_model import PANOSDerivedViews, PANScope, pan_scope_identity


def _scope_str(scope: PANScope | None) -> str:
    return pan_scope_identity(scope) if scope else "<unscoped>"


def _is_yes(value: Any) -> bool:
    return str(value or "").strip().lower() in {"yes", "true", "1", "disabled", "disable"}


def _resolve_named(
    name: str | None,
    scope: str,
    by_scope: dict[tuple[str, str], Any],
    by_name: dict[str, Any],
) -> Any | None:
    if not name:
        return None
    return by_scope.get((scope, name)) or by_name.get(name)


def build_paloalto_vpn_inspector(config: PANOSConfig, derived: PANOSDerivedViews) -> list[dict[str, Any]]:
    """Build stitched 4-layer IPSec inspector rows for all PAN-OS IPSec tunnels."""
    ike_gw_scoped: dict[tuple[str, str], Any] = {}
    ike_gw_global: dict[str, Any] = {}
    for gw in config.ike_gateways:
        if gw.name:
            ike_gw_scoped[(_scope_str(gw.scope), gw.name)] = gw
            ike_gw_global.setdefault(gw.name, gw)

    ike_crypto_scoped: dict[tuple[str, str], Any] = {}
    ike_crypto_global: dict[str, Any] = {}
    for prof in config.ike_crypto_profiles:
        if prof.name:
            ike_crypto_scoped[(_scope_str(prof.scope), prof.name)] = prof
            ike_crypto_global.setdefault(prof.name, prof)

    ipsec_crypto_scoped: dict[tuple[str, str], Any] = {}
    ipsec_crypto_global: dict[str, Any] = {}
    for prof in config.ipsec_crypto_profiles:
        if prof.name:
            ipsec_crypto_scoped[(_scope_str(prof.scope), prof.name)] = prof
            ipsec_crypto_global.setdefault(prof.name, prof)

    topo_scoped: dict[tuple[str, str], Any] = {}
    topo_global: dict[str, Any] = {}
    for item in derived.interface_topology:
        topo_scoped[(item.scope, item.interface)] = item
        topo_global.setdefault(item.interface, item)

    iface_scoped: dict[tuple[str, str], Any] = {}
    iface_global: dict[str, Any] = {}
    for iface in (*config.interfaces, *config.interface_units):
        if iface.name:
            iface_scoped[(_scope_str(iface.scope), iface.name)] = iface
            iface_global.setdefault(iface.name, iface)

    zones_by_member: dict[str, set[str]] = defaultdict(set)
    for zone in config.zones:
        if not zone.name:
            continue
        for member in zone.members or ():
            zones_by_member[member].add(zone.name)

    routes_by_iface: dict[str, list[dict[str, Any]]] = defaultdict(list)
    vrs_by_iface: dict[str, set[str]] = defaultdict(set)

    for vr in config.virtual_routers:
        for intf in vr.interfaces or ():
            if vr.name:
                vrs_by_iface[intf].add(vr.name)
        for route in vr.static_routes or ():
            if route.interface:
                routes_by_iface[route.interface].append({
                    "route_id": route.name,
                    "router": vr.name,
                    "destination": route.destination,
                    "gateway": route.nexthop_ip_address or route.nexthop,
                    "device": route.interface,
                    "distance": route.admin_distance,
                })

    for lr in config.logical_routers:
        for vrf in lr.vrfs or ():
            router_label = f"{lr.name}/{vrf.name}" if vrf.name else lr.name
            for route in vrf.static_routes or ():
                if route.interface:
                    if router_label:
                        vrs_by_iface[route.interface].add(router_label)
                    routes_by_iface[route.interface].append({
                        "route_id": route.name,
                        "router": router_label,
                        "destination": route.destination,
                        "gateway": route.nexthop_ip_address or route.nexthop,
                        "device": route.interface,
                        "distance": route.admin_distance,
                    })

    rows: list[dict[str, Any]] = []
    for tunnel in config.ipsec_tunnels:
        sc = _scope_str(tunnel.scope)
        t_intf = tunnel.tunnel_interface

        # Layer 1: IKE Gateways, Crypto Profiles, Proxy IDs
        gw_details: list[dict[str, Any]] = []
        ike_versions: list[str] = []
        peer_addrs: list[str] = []
        weak_algos: list[str] = []
        any_gw_disabled = False

        for gw_name in tunnel.ike_gateways or ():
            gw = _resolve_named(gw_name, sc, ike_gw_scoped, ike_gw_global)
            if gw is None:
                gw_details.append({"name": gw_name, "resolved": False})
                continue
            gw_disabled = _is_yes((gw.raw_extra or {}).get("disabled") if isinstance(gw.raw_extra, dict) else None)
            if gw_disabled:
                any_gw_disabled = True
            if gw.ike_version:
                ike_versions.append(gw.ike_version)
            if gw.peer_address:
                peer_addrs.append(gw.peer_address)
            crypto_name = gw.ikev2_crypto_profile if str(gw.ike_version or "").startswith("ikev2") else gw.ikev1_crypto_profile
            crypto_name = crypto_name or gw.ikev2_crypto_profile or gw.ikev1_crypto_profile
            ike_prof = _resolve_named(crypto_name, sc, ike_crypto_scoped, ike_crypto_global)
            if ike_prof is not None:
                weak_algos.extend(weak_crypto_findings(
                    [*(ike_prof.encryption_algorithms or ()), *(ike_prof.authentication_algorithms or ())],
                    ike_prof.dh_groups or (),
                ))
            gw_details.append({
                "name": gw.name,
                "resolved": True,
                "disabled": gw_disabled,
                "ike_version": gw.ike_version,
                "local_interface": gw.local_interface,
                "local_ip": gw.local_ip,
                "peer_address": gw.peer_address,
                "authentication_method": gw.authentication_method,
                "ike_crypto_profile": crypto_name,
                "ike_crypto_encryption": list(ike_prof.encryption_algorithms or ()) if ike_prof else [],
                "ike_crypto_auth": list(ike_prof.authentication_algorithms or ()) if ike_prof else [],
                "ike_crypto_dh": list(ike_prof.dh_groups or ()) if ike_prof else [],
                "nat_traversal": gw.nat_traversal,
            })

        ipsec_prof = _resolve_named(tunnel.ipsec_crypto_profile, sc, ipsec_crypto_scoped, ipsec_crypto_global)
        if ipsec_prof is not None:
            weak_algos.extend(weak_crypto_findings(
                [*(ipsec_prof.esp_encryption or ()), *(ipsec_prof.esp_authentication or ()), *(ipsec_prof.ah_authentication or ())],
                [ipsec_prof.dh_group] if ipsec_prof.dh_group else (),
            ))

        p2_rows = [
            {
                "name": proxy.name,
                "local_selector": proxy.local,
                "remote_selector": proxy.remote,
                "protocol": proxy.protocol or proxy.protocol_number,
                "local_port": proxy.local_port,
                "remote_port": proxy.remote_port,
                "address_family": proxy.address_family,
            }
            for proxy in (tunnel.proxy_ids or ())
        ]

        # Layer 2: Tunnel Interface, Zone & VR Binding
        topo = _resolve_named(t_intf, sc, topo_scoped, topo_global)
        iface_obj = _resolve_named(t_intf, sc, iface_scoped, iface_global)
        bound_zones = sorted({
            *(topo.zones if topo else ()),
            *(zones_by_member.get(t_intf, set()) if t_intf else ()),
        })
        bound_vrs = sorted({
            *(topo.virtual_routers if topo else ()),
            *(vrs_by_iface.get(t_intf, set()) if t_intf else ()),
        })
        binding = {
            "tunnel_interface": t_intf,
            "tunnel_interface_found": iface_obj is not None or topo is not None,
            "tunnel_ip": ", ".join(getattr(iface_obj, "ipv4_addresses", None) or ()) or None,
            "zones": bound_zones,
            "virtual_routers": bound_vrs,
            "virtual_router": ", ".join(bound_vrs) or None,
        }

        # Layer 3: Static Routes pointing to tunnel interface
        route_rows = list(routes_by_iface.get(t_intf, ())) if t_intf else []

        # Layer 4: Security Rules matching bound zone(s)
        zone_set = set(bound_zones)
        policy_rows: list[dict[str, Any]] = []
        if zone_set:
            for rule in config.security_rules:
                from_z = set(rule.from_zones or ())
                to_z = set(rule.to_zones or ())
                if (from_z & zone_set) or (to_z & zone_set):
                    policy_rows.append({
                        "name": rule.name,
                        "scope": _scope_str(rule.scope),
                        "from_zones": list(rule.from_zones or ()),
                        "to_zones": list(rule.to_zones or ()),
                        "source": list(rule.source or ()),
                        "destination": list(rule.destination or ()),
                        "application": list(rule.application or ()),
                        "services": list(rule.service or ()),
                        "action": rule.action,
                        "disabled": rule.disabled,
                    })

        # Accidental NAT check across PAN-OS NAT rules
        nat_exposures: list[dict[str, Any]] = []
        for nat in config.nat_rules:
            if _is_yes(nat.disabled) or nat.source_translation is None:
                continue
            egress_match = (t_intf and nat.to_interface == t_intf) or bool(zone_set and (set(nat.to_zones or ()) & zone_set))
            if egress_match:
                nat_exposures.append({
                    "kind": "Source NAT",
                    "name": nat.name or "NAT rule",
                    "detail": f"to-zones={nat.to_zones or []}, to-interface={nat.to_interface or ''}",
                })

        # Automated Misconfiguration Checks
        findings: list[dict[str, str]] = []
        tunnel_disabled = _is_yes((tunnel.raw_extra or {}).get("disabled") if isinstance(tunnel.raw_extra, dict) else None) or any_gw_disabled
        if tunnel_disabled:
            findings.append({
                "severity": "critical",
                "code": "TUNNEL_DISABLED",
                "message": "IPsec tunnel or its IKE gateway is administratively disabled.",
            })

        if not p2_rows:
            findings.append({
                "severity": "info",
                "code": "MISSING_PHASE2",
                "message": "No explicit Proxy IDs configured (route-based 0.0.0.0/0 selector).",
            })

        if not t_intf or not bound_zones or not bound_vrs:
            missing_parts = []
            if not t_intf:
                missing_parts.append("tunnel interface")
            if not bound_zones:
                missing_parts.append("security zone")
            if not bound_vrs:
                missing_parts.append("virtual/logical router")
            findings.append({
                "severity": "warning",
                "code": "MISSING_TUNNEL_BINDING",
                "message": f"Incomplete tunnel interface binding: missing {', '.join(missing_parts)}.",
            })

        if not route_rows:
            findings.append({
                "severity": "warning",
                "code": "MISSING_STATIC_ROUTE",
                "message": f"No static route points to tunnel interface '{t_intf or 'unset'}'.",
            })

        has_allow_policy = any(
            not _is_yes(p.get("disabled")) and str(p.get("action") or "").strip().lower() == "allow"
            for p in policy_rows
        )
        if not has_allow_policy:
            findings.append({
                "severity": "warning",
                "code": "MISSING_ALLOW_POLICY",
                "message": "No enabled security rule with action=allow references the tunnel's zone(s).",
            })

        for exposure in nat_exposures:
            findings.append({
                "severity": "warning",
                "code": "ACCIDENTAL_NAT",
                "message": f"Possible accidental SNAT on site-to-site traffic: {exposure['name']} ({exposure['detail']}).",
            })

        if any(ver.strip().lower() in {"ikev1", "ikev2-preferred"} for ver in ike_versions):
            findings.append({
                "severity": "warning",
                "code": "LEGACY_IKEV1",
                "message": f"IKE gateway allows legacy IKEv1 ({', '.join(dict.fromkeys(ike_versions))}).",
            })

        weak_unique = list(dict.fromkeys(weak_algos))
        if weak_unique:
            findings.append({
                "severity": "warning",
                "code": "WEAK_CRYPTO",
                "message": f"Weak IKE/IPsec cipher or DH group detected: {', '.join(weak_unique)}.",
            })

        if tunnel_disabled:
            health = "disabled"
        elif any(f["severity"] == "critical" for f in findings):
            health = "critical"
        elif any(f["severity"] == "warning" for f in findings):
            health = "warning"
        else:
            health = "healthy"

        rows.append({
            "health": health,
            "name": tunnel.name,
            "scope": sc,
            "vpn_mode": "route-based",
            "remote_gateway": ", ".join(dict.fromkeys(peer_addrs)) or None,
            "ike_version": ", ".join(dict.fromkeys(ike_versions)) or None,
            "tunnel_interface": t_intf,
            "zones": bound_zones,
            "virtual_router": binding["virtual_router"],
            "phase2_count": len(p2_rows),
            "route_count": len(route_rows),
            "policy_count": len(policy_rows),
            "finding_count": len(findings),
            "phase1": {
                "ike_gateways": gw_details,
                "ipsec_crypto_profile": tunnel.ipsec_crypto_profile,
                "ipsec_esp_encryption": list(ipsec_prof.esp_encryption or ()) if ipsec_prof else [],
                "ipsec_esp_authentication": list(ipsec_prof.esp_authentication or ()) if ipsec_prof else [],
                "ipsec_dh_group": ipsec_prof.dh_group if ipsec_prof else None,
                "tunnel_monitor": tunnel.tunnel_monitor,
                "tunnel_monitor_destination_ip": tunnel.tunnel_monitor_destination_ip,
            },
            "phase2": p2_rows,
            "binding": binding,
            "routes": route_rows,
            "policies": policy_rows,
            "nat_exposures": nat_exposures,
            "findings": findings,
        })
    return rows
