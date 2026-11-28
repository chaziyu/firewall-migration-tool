"""End-to-End Packet Flow Simulator ('Trace Packet') for FortiGate and Palo Alto."""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Any

from fwmigrate.source_reporting.policy_lookup import (
    evaluate_fortigate_policy_lookup,
    evaluate_paloalto_policy_lookup,
)
from fwmigrate.source_reporting.route_lookup import lookup_fortigate_route, lookup_paloalto_route
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig


def _validate_ipv4(ip_str: str, label: str) -> tuple[str | None, str | None]:
    s = str(ip_str or "").strip()
    if not s:
        return None, f"Please enter a {label} IPv4 address."
    try:
        return str(IPv4Address(s)), None
    except ValueError:
        return None, f"Invalid {label} IPv4 address: '{s}'."


def _bare_ip(val: str | None) -> str:
    s = str(val or "").strip()
    if not s or s == "-":
        return ""
    if " " in s and "/" not in s:
        s = s.split(" ", 1)[0]
    if "/" in s:
        s = s.split("/", 1)[0]
    if ":" in s and not s.startswith("["):
        s = s.split(":", 1)[0]
    return s.strip()


def _fg_interface_aliases(config: FGConfig, vdom: str | None) -> dict[str, list[str]]:
    aliases: dict[str, list[str]] = {}
    for zone in config.zones:
        if vdom and vdom.lower() != "all" and (zone.vdom or "root").lower() != vdom.lower():
            continue
        for member in zone.members:
            bucket = aliases.setdefault(member, [member])
            if zone.name and zone.name not in bucket:
                bucket.append(zone.name)

    for sdwan in config.sdwans:
        if vdom and vdom.lower() != "all" and (sdwan.vdom or "root").lower() != vdom.lower():
            continue
        for member in sdwan.members:
            if not member.interface:
                continue
            bucket = aliases.setdefault(member.interface, [member.interface])
            m_zone = member.zone or "virtual-wan-link"
            if m_zone not in bucket:
                bucket.append(m_zone)
            if "virtual-wan-link" not in bucket:
                bucket.append("virtual-wan-link")
    return aliases


def _build_return_path_step(
    vendor: str,
    s_ip: str,
    post_dst_ip: str,
    src_iface: str,
    dst_iface: str,
    ing_winner: dict[str, Any] | None,
    eg_winner: dict[str, Any] | None,
    *,
    src_zone: str | None = None,
    dst_zone: str | None = None,
    active_policy_routes: int = 0,
    step_num: str = "6",
) -> tuple[str, dict[str, Any], str | None]:
    if src_iface == "-" or ing_winner is None:
        summary = "No Return Route (RPF / Drop Risk)"
        warn = (
            f"Return path check ({post_dst_ip} → {s_ip}): no connected or static route back to source {s_ip}; "
            "reply traffic will be blackholed or dropped by Strict RPF."
        )
        step = {
            "step": step_num,
            "stage": "Return Path & Symmetry Check",
            "outcome": summary,
            "details": f"Reverse LPM lookup for {s_ip} found no active route. Reply packets from {post_dst_ip} cannot return.",
            "tone": "danger",
        }
        return summary, step, warn

    ing_vr = str(ing_winner.get("virtual_router") or "").strip()
    eg_vr = str(eg_winner.get("virtual_router") or "").strip() if eg_winner else ""
    if vendor == "palo_alto" and ing_vr and eg_vr and ing_vr != eg_vr:
        summary = f"Cross-VR Asymmetry ({eg_vr} ≠ {ing_vr})"
        warn = (
            f"Return path check ({post_dst_ip} → {s_ip}): forward egress is in VR '{eg_vr}' via {dst_iface}, "
            f"while reverse route to {s_ip} is in VR '{ing_vr}' via {src_iface}."
        )
        step = {
            "step": step_num,
            "stage": "Return Path & Symmetry Check",
            "outcome": summary,
            "details": f"Return prefix {ing_winner.get('destination', '-')} resolves in VR '{ing_vr}' ({src_iface}), different from egress VR '{eg_vr}'.",
            "tone": "warn",
        }
        return summary, step, warn

    if src_iface == dst_iface:
        summary = f"Asymmetric / Hairpin ({dst_iface})"
        warn = (
            f"Return path check ({post_dst_ip} → {s_ip}): forward egress and reverse route both use '{dst_iface}'. "
            "Verify hosts do not bypass the firewall on the return leg (hairpin / asymmetric routing)."
        )
        step = {
            "step": step_num,
            "stage": "Return Path & Symmetry Check",
            "outcome": summary,
            "details": f"Return lookup for {s_ip} resolves back out {src_iface} ({ing_winner.get('destination', '-')}).",
            "tone": "warn",
        }
        return summary, step, warn

    ret_gw = ing_winner.get("gateway") or ing_winner.get("next_hop") or "Directly Connected"
    flow_label = f"{dst_iface} ({dst_zone}) → {src_iface} ({src_zone})" if dst_zone and src_zone else f"{dst_iface} → {src_iface}"
    summary = f"Symmetric ({flow_label})"
    extra = f" Note: {active_policy_routes} active policy route(s) may override static return LPM." if active_policy_routes > 0 else ""
    step = {
        "step": step_num,
        "stage": "Return Path & Symmetry Check",
        "outcome": summary,
        "details": (
            f"Reverse LPM for {s_ip} matches {ing_winner.get('destination', '-')} via {src_iface} "
            f"(Next Hop: {ret_gw}, {ing_winner.get('type', 'Route')}).{extra}"
        ),
        "tone": "success",
    }
    return summary, step, None


def trace_fortigate_packet(
    config: FGConfig,
    *,
    src_ip: str,
    dst_ip: str,
    dst_port: str = "443",
    protocol: str = "tcp",
    vdom: str | None = None,
    check_return: bool = True,
) -> dict[str, Any]:
    """Simulate end-to-end packet flow through a FortiGate configuration."""
    s_ip, err = _validate_ipv4(src_ip, "Source")
    if err or s_ip is None:
        return {"valid": False, "vendor": "fortigate", "error": err}
    d_ip, err = _validate_ipv4(dst_ip, "Destination")
    if err or d_ip is None:
        return {"valid": False, "vendor": "fortigate", "error": err}

    proto_clean = str(protocol or "tcp").strip().lower()
    port_clean = str(dst_port or "").strip()
    if proto_clean in ("icmp", "any"):
        svc_query = proto_clean
    elif port_clean:
        svc_query = f"{proto_clean}/{port_clean}"
    else:
        svc_query = proto_clean

    steps: list[dict[str, Any]] = []
    warnings: list[str] = []

    # Step 1: Ingress & RPF
    ing_res = lookup_fortigate_route(config, s_ip, vdom=vdom)
    ing_winner = ing_res.get("winner")
    src_iface = str(ing_winner.get("interface", "-")) if ing_winner else "-"
    if src_iface == "-":
        warnings.append(f"No route back to Source IP {s_ip} — Strict RPF would drop return/ingress packets.")
        steps.append({
            "step": "1",
            "stage": "Ingress & RPF Check",
            "outcome": "Unknown (RPF Drop Risk)",
            "details": f"No connected or static route matched {s_ip}.",
            "tone": "warn",
        })
    else:
        steps.append({
            "step": "1",
            "stage": "Ingress & RPF Check",
            "outcome": src_iface,
            "details": f"Source {s_ip} arrives via {src_iface} (matched {ing_winner.get('destination', '-')}, {ing_winner.get('type', '-')}).",
            "tone": "info",
        })

    # Step 2: Pre-NAT / DNAT (VIP)
    vip_name: str | None = None
    post_dst_ip = d_ip
    post_dst_port = port_clean
    for vip in config.vips:
        if vdom and vdom.lower() != "all" and (vip.vdom or "root").lower() != vdom.lower():
            continue
        if (vip.status or "enable").lower() == "disable":
            continue
        if _bare_ip(vip.extip) != d_ip:
            continue
        if (vip.portforward or "").lower() == "enable" and vip.extport and port_clean and vip.extport != port_clean:
            continue
        vip_name = vip.name
        if vip.mappedip:
            post_dst_ip = _bare_ip(vip.mappedip[0]) or d_ip
        if (vip.portforward or "").lower() == "enable" and vip.mappedport:
            post_dst_port = vip.mappedport
        break

    if vip_name:
        steps.append({
            "step": "2",
            "stage": "Pre-NAT / DNAT (VIP)",
            "outcome": f"DNAT via {vip_name}",
            "details": f"{d_ip}:{port_clean or '*'} → {post_dst_ip}:{post_dst_port or '*'}",
            "tone": "info",
        })
    else:
        steps.append({
            "step": "2",
            "stage": "Pre-NAT / DNAT (VIP)",
            "outcome": "No DNAT",
            "details": f"Destination remains {d_ip}",
            "tone": "info",
        })

    # Local-In check
    if not vip_name:
        own_ip_map: dict[str, tuple[str, str]] = {}
        for iface in config.interfaces:
            if vdom and vdom.lower() != "all" and (iface.vdom or "root").lower() != vdom.lower():
                continue
            if (iface.type or "").lower() == "zone" or (iface.status or "enable").lower() in ("disable", "disabled", "down"):
                continue
            acc = ", ".join(iface.allowaccess) if iface.allowaccess else "-"
            for raw in [iface.ip, *(s.ip for s in iface.secondary_ips)]:
                b = _bare_ip(raw)
                if b:
                    own_ip_map[b] = (iface.name, acc)
        if post_dst_ip in own_ip_map:
            own_iface, own_acc = own_ip_map[post_dst_ip]
            steps.append({
                "step": "3",
                "stage": "Local-In (To Firewall)",
                "outcome": f"Firewall Interface ({own_iface})",
                "details": f"Destination {post_dst_ip} is the firewall's own interface IP. Governed by allowaccess ({own_acc}) & local-in-policy, not forwarding policies.",
                "tone": "info",
            })
            return {
                "valid": True,
                "vendor": "fortigate",
                "verdict": "LOCAL-IN",
                "src": s_ip,
                "dst": f"{d_ip}:{port_clean or proto_clean}",
                "ingress": src_iface,
                "egress": f"{own_iface} (Local-In)",
                "policy": f"Local-In ({own_acc})",
                "nat": "None",
                "steps": steps,
                "warnings": warnings,
            }

    # Step 3: Egress Route (LPM)
    eg_res = lookup_fortigate_route(config, post_dst_ip, vdom=vdom)
    eg_winner = eg_res.get("winner")
    dst_iface = str(eg_winner.get("interface", "-")) if eg_winner else "-"
    active_pr = int(eg_res.get("active_policy_routes") or 0)
    if active_pr > 0:
        warnings.append(f"{active_pr} active Policy Route(s) exist and are evaluated before static/connected routes.")

    if dst_iface == "-":
        warnings.append(f"No route to destination {post_dst_ip} — traffic dropped at routing stage.")
        steps.append({
            "step": "3",
            "stage": "Egress Route (LPM)",
            "outcome": "No Route (Drop)",
            "details": f"No active connected or static route matched {post_dst_ip}.",
            "tone": "danger",
        })
        return {
            "valid": True,
            "vendor": "fortigate",
            "verdict": "DROP",
            "src": s_ip,
            "dst": f"{d_ip}:{port_clean or proto_clean}",
            "ingress": src_iface,
            "egress": "No Route",
            "policy": "Not evaluated (no route)",
            "nat": "None",
            "steps": steps,
            "warnings": warnings,
        }

    gw = eg_winner.get("gateway") or "-"
    steps.append({
        "step": "3",
        "stage": "Egress Route (LPM)",
        "outcome": dst_iface,
        "details": f"Matched {eg_winner.get('destination', '-')} via {dst_iface} (GW: {gw}, {eg_winner.get('type', '-')}).",
        "tone": "info",
    })

    if src_iface != "-" and src_iface == dst_iface:
        warnings.append(f"Ingress and egress both resolve to '{src_iface}' (hairpin / potential asymmetric path).")

    # Step 4: Firewall Policy
    aliases = _fg_interface_aliases(config, vdom)
    src_candidates = aliases.get(src_iface, [src_iface]) if src_iface != "-" else ["any"]
    dst_candidates = aliases.get(dst_iface, [dst_iface])
    dst_lookup_addr = vip_name or d_ip

    best_match: dict[str, Any] | None = None
    best_shadowed: list[dict[str, Any]] = []
    for s_cand in src_candidates:
        for d_cand in dst_candidates:
            res = evaluate_fortigate_policy_lookup(
                config,
                vdom=vdom,
                src_iface=s_cand,
                dst_iface=d_cand,
                src_addr=s_ip,
                dst_addr=dst_lookup_addr,
                protocol=svc_query,
            )
            if res.get("match") is not None and best_match is None:
                best_match = res["match"]
                best_shadowed = res.get("shadowed") or []

    if best_match is None:
        same_connected = (
            ing_winner is not None
            and eg_winner is not None
            and ing_winner.get("type") == "Connected"
            and eg_winner.get("type") == "Connected"
            and src_iface != "-"
            and src_iface == dst_iface
            and ing_winner.get("destination") == eg_winner.get("destination")
        )
        if same_connected:
            steps.append({
                "step": "4",
                "stage": "Firewall Policy",
                "outcome": "L2 Direct (Bypasses L3 Policy)",
                "details": f"Both {s_ip} and {post_dst_ip} belong to directly connected subnet {eg_winner.get('destination')} on {dst_iface}; hosts communicate at L2 unless hairpinned.",
                "tone": "info",
            })
            return {
                "valid": True,
                "vendor": "fortigate",
                "verdict": "L2 DIRECT",
                "src": s_ip,
                "dst": f"{d_ip}:{port_clean or proto_clean}",
                "ingress": src_iface,
                "egress": dst_iface,
                "policy": "N/A — L2 Switched (Same Connected Subnet)",
                "nat": "None",
                "steps": steps,
                "warnings": warnings,
            }

        steps.append({
            "step": "4",
            "stage": "Firewall Policy",
            "outcome": "Implicit DENY",
            "details": f"No policy matched ({', '.join(src_candidates)} → {', '.join(dst_candidates)}).",
            "tone": "danger",
        })
        return {
            "valid": True,
            "vendor": "fortigate",
            "verdict": "DENY",
            "src": s_ip,
            "dst": f"{d_ip}:{port_clean or proto_clean}",
            "ingress": src_iface,
            "egress": dst_iface,
            "policy": "Implicit DENY",
            "nat": "None",
            "steps": steps,
            "warnings": warnings,
        }

    pol_id = best_match.get("id", "?")
    pol_name = best_match.get("name", "-")
    action = str(best_match.get("action", "DENY")).upper()
    is_allow = action in ("ACCEPT", "ALLOW", "IPSEC")
    if best_shadowed:
        warnings.append(f"{len(best_shadowed)} subsequent shadowed policy(s) also match after #{pol_id}.")

    steps.append({
        "step": "4",
        "stage": "Firewall Policy",
        "outcome": f"#{pol_id} {pol_name} ({action})",
        "details": f"{best_match.get('src_interface', '-')} → {best_match.get('dst_interface', '-')} | Service: {best_match.get('service', '-')}",
        "tone": "success" if is_allow else "danger",
    })

    # Step 5: Outbound SNAT
    nat_flag = str(best_match.get("nat", "disable")).lower()
    if is_allow and nat_flag == "enable":
        nat_summary = f"SNAT Enabled (Masquerade / Pool on {dst_iface})"
        steps.append({
            "step": "5",
            "stage": "Outbound SNAT",
            "outcome": "SNAT Applied",
            "details": f"Source {s_ip} translated via egress interface {dst_iface} / policy IP Pool.",
            "tone": "info",
        })
    elif is_allow and config.central_snat:
        nat_summary = "Central SNAT Table Configured (check Central SNAT rules)"
        steps.append({
            "step": "5",
            "stage": "Outbound SNAT",
            "outcome": "Central SNAT Mode",
            "details": f"{len(config.central_snat)} Central SNAT rule(s) present in config.",
            "tone": "info",
        })
    else:
        nat_summary = "No SNAT"
        steps.append({
            "step": "5",
            "stage": "Outbound SNAT",
            "outcome": "No SNAT",
            "details": "Source IP is preserved (policy NAT disabled).",
            "tone": "info",
        })

    ret_summary: str | None = None
    if check_return:
        ret_summary, ret_step, ret_warn = _build_return_path_step(
            "fortigate",
            s_ip,
            post_dst_ip,
            src_iface,
            dst_iface,
            ing_winner,
            eg_winner,
            active_policy_routes=active_pr,
            step_num="6",
        )
        steps.append(ret_step)
        if ret_warn and not (src_iface == dst_iface and any("hairpin" in w for w in warnings)):
            warnings.append(ret_warn)

    result: dict[str, Any] = {
        "valid": True,
        "vendor": "fortigate",
        "verdict": "ALLOW" if is_allow else "DENY",
        "src": s_ip,
        "dst": f"{d_ip}:{port_clean or proto_clean}",
        "ingress": src_iface,
        "egress": dst_iface,
        "policy": f"#{pol_id} — {pol_name} ({action})",
        "nat": nat_summary if not vip_name else f"DNAT ({vip_name}) + {nat_summary}",
        "steps": steps,
        "warnings": warnings,
    }
    if ret_summary is not None:
        result["return_path"] = ret_summary
    return result


def trace_paloalto_packet(
    config: PANOSConfig,
    *,
    src_ip: str,
    dst_ip: str,
    dst_port: str = "443",
    protocol: str = "tcp",
    virtual_router: str = "all",
    scope: str | None = None,
    check_return: bool = True,
) -> dict[str, Any]:
    """Simulate end-to-end packet flow through a Palo Alto PAN-OS configuration."""
    s_ip, err = _validate_ipv4(src_ip, "Source")
    if err or s_ip is None:
        return {"valid": False, "vendor": "palo_alto", "error": err}
    d_ip, err = _validate_ipv4(dst_ip, "Destination")
    if err or d_ip is None:
        return {"valid": False, "vendor": "palo_alto", "error": err}

    zone_map: dict[str, str] = {}
    for zone in config.zones:
        if zone.name:
            for member in zone.members or []:
                zone_map[member.strip()] = zone.name

    proto_clean = str(protocol or "tcp").strip().lower()
    port_clean = str(dst_port or "443").strip()

    steps: list[dict[str, Any]] = []
    warnings: list[str] = []

    # Step 1: Ingress & RPF
    ing_res = lookup_paloalto_route(config, s_ip, virtual_router=virtual_router)
    ing_w = ing_res.get("winner")
    src_iface = str(ing_w.get("interface", "-")) if ing_w else "-"
    src_zone = zone_map.get(src_iface, "any") if src_iface != "-" else "any"
    if src_iface == "-":
        warnings.append(f"No reverse route to {s_ip} — check asymmetric routing or Strict RPF.")
        steps.append({
            "step": "1",
            "stage": "Ingress & RPF Check",
            "outcome": "Unknown (No Reverse Route)",
            "details": f"No route matched {s_ip}; Security policy will evaluate with zone 'any'.",
            "tone": "warn",
        })
    else:
        steps.append({
            "step": "1",
            "stage": "Ingress & RPF Check",
            "outcome": f"{src_iface} (Zone: {src_zone})",
            "details": f"Matched {ing_w.get('destination', '-')} via {src_iface}.",
            "tone": "info",
        })

    # Local-In check
    pa_own_ips: dict[str, tuple[str, str]] = {}
    for iface in config.interfaces:
        if (iface.link_state or "").lower() == "down" or not iface.name:
            continue
        mprof = iface.management_profile or "-"
        for raw_ip in iface.ipv4_addresses or []:
            b = _bare_ip(raw_ip)
            if b:
                pa_own_ips[b] = (iface.name, mprof)
    for unit in config.interface_units:
        if not unit.name:
            continue
        mprof = unit.management_profile or "-"
        for raw_ip in unit.ipv4_addresses or []:
            b = _bare_ip(raw_ip)
            if b:
                pa_own_ips[b] = (unit.name, mprof)
    for sys_set in config.system_settings:
        mgt = _bare_ip(sys_set.ip_address)
        if mgt:
            pa_own_ips[mgt] = ("Management (MGT)", "MGT Services")

    if d_ip in pa_own_ips:
        own_iface, own_prof = pa_own_ips[d_ip]
        steps.append({
            "step": "2",
            "stage": "Local-In (To Firewall)",
            "outcome": f"Firewall Interface ({own_iface})",
            "details": f"Destination {d_ip} is the firewall's own interface IP. Governed by Interface Mgmt Profile ({own_prof}).",
            "tone": "info",
        })
        return {
            "valid": True,
            "vendor": "palo_alto",
            "verdict": "LOCAL-IN",
            "src": s_ip,
            "dst": f"{d_ip}:{port_clean}",
            "ingress": f"{src_iface} ({src_zone})",
            "egress": f"{own_iface} (Local-In)",
            "policy": f"Local-In ({own_prof})",
            "nat": "None",
            "steps": steps,
            "warnings": warnings,
        }

    # Step 2: Egress Route (LPM)
    eg_res = lookup_paloalto_route(config, d_ip, virtual_router=virtual_router)
    eg_w = eg_res.get("winner")
    dst_iface = str(eg_w.get("interface", "-")) if eg_w else "-"
    dst_zone = zone_map.get(dst_iface, "any") if dst_iface != "-" else "any"
    if dst_iface == "-":
        warnings.append(f"No route matched destination {d_ip} — packet dropped at routing lookup.")
        steps.append({
            "step": "2",
            "stage": "Egress Route (LPM)",
            "outcome": "No Route (Drop)",
            "details": f"No active connected or static route matched {d_ip}.",
            "tone": "danger",
        })
        return {
            "valid": True,
            "vendor": "palo_alto",
            "verdict": "DROP",
            "src": s_ip,
            "dst": f"{d_ip}:{port_clean}",
            "ingress": f"{src_iface} ({src_zone})",
            "egress": "No Route",
            "policy": "Not evaluated (no route)",
            "nat": "None",
            "steps": steps,
            "warnings": warnings,
        }

    nh = eg_w.get("next_hop") or "-"
    steps.append({
        "step": "2",
        "stage": "Egress Route (LPM)",
        "outcome": f"{dst_iface} (Zone: {dst_zone})",
        "details": f"Matched {eg_w.get('destination', '-')} via {dst_iface} (Next Hop: {nh}).",
        "tone": "info",
    })

    # Step 3: NAT Policy Match
    nat_res = evaluate_paloalto_policy_lookup(
        config,
        scope=scope,
        policy_type="nat",
        src_zone=src_zone,
        dst_zone=dst_zone,
        src_addr=s_ip,
        dst_addr=d_ip,
        dst_port=port_clean,
        protocol=proto_clean,
    )
    nat_match = nat_res.get("match")
    if nat_match:
        nat_name = nat_match["name"]
        src_t = nat_match.get("src_translation", "None")
        dst_t = nat_match.get("dst_translation", "None")
        nat_summary = f"{nat_name}: Src={src_t} | Dst={dst_t}"
        steps.append({
            "step": "3",
            "stage": "NAT Rule Evaluation",
            "outcome": f"Matched: {nat_name}",
            "details": f"Src Translation: {src_t} · Dst Translation: {dst_t}",
            "tone": "info",
        })
    else:
        nat_summary = "No NAT Rule Matched"
        steps.append({
            "step": "3",
            "stage": "NAT Rule Evaluation",
            "outcome": "No NAT",
            "details": "No NAT rule matched this 5-tuple and zone pair.",
            "tone": "info",
        })

    # Step 4: Security Policy Match
    sec_res = evaluate_paloalto_policy_lookup(
        config,
        scope=scope,
        policy_type="security",
        src_zone=src_zone,
        dst_zone=dst_zone,
        src_addr=s_ip,
        dst_addr=d_ip,
        dst_port=port_clean,
        protocol=proto_clean,
    )
    sec_match = sec_res.get("match")
    if sec_match:
        action = str(sec_match.get("action") or "ALLOW").upper()
        is_allow = action == "ALLOW"
        verdict = "ALLOW" if is_allow else "DENY"
        pol_summary = f"{sec_match['name']} ({action})"
        shadowed = sec_res.get("shadowed") or []
        if shadowed:
            warnings.append(f"{len(shadowed)} subsequent shadowed rule(s) also match after '{sec_match['name']}'.")
        steps.append({
            "step": "4",
            "stage": "Security Policy",
            "outcome": pol_summary,
            "details": f"Zones: {sec_match.get('src_zone', src_zone)} → {sec_match.get('dst_zone', dst_zone)} | App: {sec_match.get('application', '-')}",
            "tone": "success" if is_allow else "danger",
        })
    else:
        same_connected = (
            ing_w is not None
            and eg_w is not None
            and ing_w.get("type") == "Connected"
            and eg_w.get("type") == "Connected"
            and src_iface != "-"
            and src_iface == dst_iface
            and ing_w.get("destination") == eg_w.get("destination")
        )
        if same_connected:
            verdict = "L2 DIRECT"
            pol_summary = "N/A — L2 Switched (Same Connected Subnet)"
            steps.append({
                "step": "4",
                "stage": "Security Policy",
                "outcome": "L2 Direct (Bypasses L3 Policy)",
                "details": f"Both {s_ip} and {d_ip} belong to directly connected subnet {eg_w.get('destination')} on {dst_iface}; hosts communicate at L2.",
                "tone": "info",
            })
        elif src_zone != "any" and src_zone == dst_zone and str(sec_res.get("action", "")).upper() == "ALLOW":
            verdict = "ALLOW"
            pol_summary = "intrazone-default (ALLOW)"
            steps.append({
                "step": "4",
                "stage": "Security Policy",
                "outcome": pol_summary,
                "details": f"No explicit rule matched, so traffic within same zone '{src_zone}' hits PAN-OS default intrazone-default (allow).",
                "tone": "success",
            })
        else:
            verdict = "DENY"
            pol_summary = "Implicit Deny / interzone-default"
            steps.append({
                "step": "4",
                "stage": "Security Policy",
                "outcome": "No Rule Matched (Deny)",
                "details": str(sec_res.get("reason", "No matching security rule.")),
                "tone": "danger",
            })

    ret_summary: str | None = None
    if check_return and verdict != "L2 DIRECT":
        ret_summary, ret_step, ret_warn = _build_return_path_step(
            "palo_alto",
            s_ip,
            d_ip,
            src_iface,
            dst_iface,
            ing_w,
            eg_w,
            src_zone=src_zone,
            dst_zone=dst_zone,
            step_num="5",
        )
        steps.append(ret_step)
        if ret_warn:
            warnings.append(ret_warn)

    result: dict[str, Any] = {
        "valid": True,
        "vendor": "palo_alto",
        "verdict": verdict,
        "src": s_ip,
        "dst": f"{d_ip}:{port_clean}",
        "ingress": f"{src_iface} ({src_zone})",
        "egress": f"{dst_iface} ({dst_zone})",
        "policy": pol_summary,
        "nat": nat_summary,
        "steps": steps,
        "warnings": warnings,
    }
    if ret_summary is not None:
        result["return_path"] = ret_summary
    return result
