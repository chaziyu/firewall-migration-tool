"""Firewall-aware structural configuration diff for FortiGate and Palo Alto."""

from __future__ import annotations

from typing import Any, Callable

from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity


def _join(values: list[Any] | None, default: str = "-") -> str:
    if not values:
        return default
    cleaned = [str(v).strip() for v in values if v is not None and str(v).strip()]
    return ", ".join(cleaned) if cleaned else default


def _val(v: Any, default: str = "-") -> str:
    if v is None:
        return default
    s = str(v).strip()
    return s if s else default


def _diff_records(
    before_rows: list[dict[str, Any]],
    after_rows: list[dict[str, Any]],
    key_fn: Callable[[dict[str, Any]], str],
    compare_fields: list[str],
    summary_fields: list[str],
) -> list[dict[str, Any]]:
    before_map: dict[str, dict[str, Any]] = {}
    for row in before_rows:
        key = key_fn(row)
        if key:
            before_map[key] = row

    after_map: dict[str, dict[str, Any]] = {}
    for row in after_rows:
        key = key_fn(row)
        if key:
            after_map[key] = row

    all_keys = list(dict.fromkeys([*before_map.keys(), *after_map.keys()]))
    diffs: list[dict[str, Any]] = []

    for key in all_keys:
        b = before_map.get(key)
        a = after_map.get(key)
        if b is None and a is not None:
            summary = " · ".join(
                f"{f}: {a.get(f, '-')}"
                for f in summary_fields
                if a.get(f, "-") not in ("", "-", None)
            )
            diffs.append({
                "change": "Added",
                "item": key,
                "details": summary or "New entry added",
                "change_type": "added",
            })
        elif a is None and b is not None:
            summary = " · ".join(
                f"{f}: {b.get(f, '-')}"
                for f in summary_fields
                if b.get(f, "-") not in ("", "-", None)
            )
            diffs.append({
                "change": "Removed",
                "item": key,
                "details": summary or "Entry removed",
                "change_type": "removed",
            })
        elif b is not None and a is not None:
            changed: list[str] = []
            for f in compare_fields:
                bv = str(b.get(f, "-"))
                av = str(a.get(f, "-"))
                if bv != av:
                    changed.append(f"{f}: {bv} → {av}")
            if changed:
                diffs.append({
                    "change": "Modified",
                    "item": key,
                    "details": "; ".join(changed),
                    "change_type": "modified",
                })
    return diffs


def _finalize_diff(
    vendor: str,
    domain_map: dict[str, list[dict[str, Any]]],
    before_name: str,
    after_name: str,
) -> dict[str, Any]:
    added = modified = removed = 0
    domains: list[dict[str, Any]] = []
    for name, rows in domain_map.items():
        if not rows:
            continue
        for r in rows:
            ct = r["change_type"]
            if ct == "added":
                added += 1
            elif ct == "modified":
                modified += 1
            elif ct == "removed":
                removed += 1
        domains.append({"name": name, "count": len(rows), "rows": rows})

    total = added + modified + removed
    return {
        "vendor": vendor,
        "before_name": before_name,
        "after_name": after_name,
        "has_diff": total > 0,
        "summary": {
            "added": added,
            "modified": modified,
            "removed": removed,
            "total": total,
        },
        "domains": domains,
    }


def _fg_policy_rows(cfg: FGConfig) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for p in cfg.policies:
        vdom = p.vdom or "root"
        pid = str(p.policy_id) if p.policy_id is not None else "-"
        pname = p.name or "-"
        key = f"[{vdom}] #{pid}" if p.policy_id is not None else f"[{vdom}] {pname}"
        rows.append({
            "_key": key,
            "Name": pname,
            "Src Interface": _join(p.srcintf, "any"),
            "Dst Interface": _join(p.dstintf, "any"),
            "Source": _join(p.srcaddr or p.srcaddr6, "all"),
            "Destination": _join(p.dstaddr or p.dstaddr6, "all"),
            "Service": _join(p.service, "ALL"),
            "Action": _val(p.action, "deny"),
            "NAT": _val(p.nat, "disable"),
            "Status": _val(p.status, "enable"),
        })
    return rows


def _fg_nat_rows(cfg: FGConfig) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for v in cfg.vips:
        vdom = v.vdom or "root"
        rows.append({
            "_key": f"[{vdom}] VIP: {v.name}",
            "Interface": _val(v.extintf),
            "Mapped From": _val(v.extip),
            "Mapped To": _join(v.mappedip),
            "External IP Range": "-",
            "Type": _val(v.type, "static-nat"),
        })
    for p in cfg.ip_pools:
        vdom = p.vdom or "root"
        ip_range = f"{p.startip}-{p.endip}" if p.startip and p.endip else _val(p.startip)
        rows.append({
            "_key": f"[{vdom}] IP Pool: {p.name}",
            "Interface": _val(p.associated_interface),
            "Mapped From": "-",
            "Mapped To": "-",
            "External IP Range": ip_range,
            "Type": _val(p.type, "overload"),
        })
    for cs in cfg.central_snat:
        vdom = cs.vdom or "root"
        pid = str(cs.policy_id) if cs.policy_id is not None else "-"
        rows.append({
            "_key": f"[{vdom}] Central SNAT #{pid}",
            "Interface": f"{_join(cs.srcintf, 'any')} → {_join(cs.dstintf, 'any')}",
            "Mapped From": _join(cs.orig_addr or cs.orig_addr6, "all"),
            "Mapped To": _join(cs.dst_addr or cs.dst_addr6, "all"),
            "External IP Range": _join(cs.nat_ippool or cs.nat_ippool6, "interface-ip"),
            "Type": _val(cs.status, "enable"),
        })
    return rows


def _fg_route_rows(cfg: FGConfig) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for r in cfg.static_routes:
        vdom = r.vdom or "root"
        seq = str(r.seq_num) if r.seq_num is not None else "-"
        dst = _val(r.dst or r.dstaddr)
        rows.append({
            "_key": f"[{vdom}] Seq {seq} ({dst})",
            "Destination": dst,
            "Gateway": "Blackhole" if (r.blackhole or "").lower() == "enable" else _val(r.gateway),
            "Interface": _val(r.device),
            "Distance": str(r.distance if r.distance is not None else 10),
            "Priority": str(r.priority if r.priority is not None else 0),
            "Status": _val(r.status, "enable"),
        })
    return rows


def _fg_vpn_rows(cfg: FGConfig) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for t in cfg.ipsec_phase1:
        vdom = t.vdom or "root"
        # Explicitly exclude secret/credential fields (only non-secret tunnel attributes).
        rows.append({
            "_key": f"[{vdom}] {t.name}",
            "Interface": _val(t.interface),
            "Remote GW": _val(t.remote_gw or t.remotegw_ddns),
            "IKE Version": _val(t.ike_version, "1"),
            "Proposal": _join(t.proposal),
            "DH Group": _join(list(t.dhgrp or [])),
            "Mode": _val(t.mode),
        })
    return rows


def _fg_iface_rows(cfg: FGConfig) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for i in cfg.interfaces:
        vdom = i.vdom or "root"
        rows.append({
            "_key": f"[{vdom}] {i.name}",
            "Type": _val(i.type, "physical"),
            "IP/Netmask": _val(i.ip),
            "Allow Access": _join(i.allowaccess),
            "Status": _val(i.status, "up"),
            "Members": _join(i.members),
        })
    for z in cfg.zones:
        vdom = z.vdom or "root"
        rows.append({
            "_key": f"[{vdom}] Zone: {z.name}",
            "Type": "zone",
            "IP/Netmask": "-",
            "Allow Access": "-",
            "Status": _val(z.intrazone, "deny"),
            "Members": _join(z.members),
        })
    return rows


def diff_fortigate_configs(
    before: FGConfig,
    after: FGConfig,
    *,
    before_name: str = "Current",
    after_name: str = "Comparison",
) -> dict[str, Any]:
    """Compare two FortiGate FGConfig snapshots across 5 structural domains."""
    domain_map = {
        "Firewall Policies": _diff_records(
            _fg_policy_rows(before),
            _fg_policy_rows(after),
            key_fn=lambda r: r["_key"],
            compare_fields=["Name", "Src Interface", "Dst Interface", "Source", "Destination", "Service", "Action", "NAT", "Status"],
            summary_fields=["Src Interface", "Dst Interface", "Source", "Destination", "Service", "Action"],
        ),
        "NAT / VIPs & IP Pools": _diff_records(
            _fg_nat_rows(before),
            _fg_nat_rows(after),
            key_fn=lambda r: r["_key"],
            compare_fields=["Interface", "Mapped From", "Mapped To", "External IP Range", "Type"],
            summary_fields=["Interface", "Mapped From", "Mapped To", "External IP Range"],
        ),
        "Static Routes": _diff_records(
            _fg_route_rows(before),
            _fg_route_rows(after),
            key_fn=lambda r: r["_key"],
            compare_fields=["Destination", "Gateway", "Interface", "Distance", "Priority", "Status"],
            summary_fields=["Destination", "Gateway", "Interface", "Distance"],
        ),
        "IPSec VPN Tunnels": _diff_records(
            _fg_vpn_rows(before),
            _fg_vpn_rows(after),
            key_fn=lambda r: r["_key"],
            compare_fields=["Interface", "Remote GW", "IKE Version", "Proposal", "DH Group", "Mode"],
            summary_fields=["Interface", "Remote GW", "IKE Version", "Proposal"],
        ),
        "Interfaces & Zones": _diff_records(
            _fg_iface_rows(before),
            _fg_iface_rows(after),
            key_fn=lambda r: r["_key"],
            compare_fields=["Type", "IP/Netmask", "Allow Access", "Status", "Members"],
            summary_fields=["Type", "IP/Netmask", "Status", "Members"],
        ),
    }
    return _finalize_diff("fortigate", domain_map, before_name, after_name)


def _pa_scope_tag(scope: PANScope | None) -> str:
    if scope is None:
        return "shared"
    return scope.vsys or scope.device_group or scope.name or pan_scope_identity(scope)


def _pa_sec_rows(cfg: PANOSConfig) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for r in cfg.security_rules:
        sc = _pa_scope_tag(r.scope)
        pos = r.rulebase_position or "local"
        rows.append({
            "_key": f"[{sc}/{pos}] {r.name or '-'}",
            "Source Zone": _join(r.from_zones, "any"),
            "Source Addr": _join(r.source, "any"),
            "Dest Zone": _join(r.to_zones, "any"),
            "Dest Addr": _join(r.destination, "any"),
            "Application": _join(r.application, "any"),
            "Service": _join(r.service, "application-default"),
            "Action": _val(r.action, "allow"),
            "Disabled": _val(r.disabled, "no"),
        })
    return rows


def _pa_nat_rows(cfg: PANOSConfig) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for r in cfg.nat_rules:
        sc = _pa_scope_tag(r.scope)
        pos = r.rulebase_position or "local"
        src_t = "None"
        if r.source_translation is not None:
            st = r.source_translation
            if getattr(st, "translated_addresses", None):
                src_t = f"{st.translation_type or 'src'}: {_join(st.translated_addresses)}"
            elif getattr(st, "translated_address", None):
                src_t = f"{st.translation_type or 'static'}: {st.translated_address}"
            elif getattr(st, "interface", None):
                src_t = f"{st.translation_type or 'interface'}: {st.interface}"
            else:
                src_t = _val(st.translation_type, "Configured")
        dst_t = "None"
        if r.destination_translation is not None:
            dt = r.destination_translation
            dst_t = f"{_val(dt.translated_address)}{f':{dt.translated_port}' if dt.translated_port else ''}"
        elif r.dynamic_destination_translation is not None:
            ddt = r.dynamic_destination_translation
            dst_t = f"{_join(ddt.translated_addresses)}{f':{ddt.translated_port}' if ddt.translated_port else ''}"
        rows.append({
            "_key": f"[{sc}/{pos}] {r.name or '-'}",
            "Source Zone": _join(r.from_zones, "any"),
            "Dest Zone": _join(r.to_zones, "any"),
            "Source Addr": _join(r.source, "any"),
            "Dest Addr": _join(r.destination, "any"),
            "Service": _val(r.service, "any"),
            "Src Translation": src_t,
            "Dst Translation": dst_t,
            "Disabled": _val(r.disabled, "no"),
        })
    return rows


def _pa_route_rows(cfg: PANOSConfig) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for vr in cfg.virtual_routers:
        vr_name = vr.name or "default"
        for rt in vr.static_routes or []:
            rows.append({
                "_key": f"{vr_name}: {rt.name or '-'}",
                "Destination": _val(rt.destination),
                "Interface": _val(rt.interface),
                "NH Type": _val(rt.nexthop_type),
                "NH Value": _val(rt.nexthop_ip_address or rt.nexthop),
                "Metric": _val(rt.metric, "10"),
                "AD": _val(rt.admin_distance, "10"),
            })
    for lr in cfg.logical_routers:
        lr_name = lr.name or "default"
        for vrf in lr.vrfs or []:
            vrf_label = f"{lr_name}/{vrf.name}" if vrf.name else lr_name
            for rt in vrf.static_routes or []:
                rows.append({
                    "_key": f"{vrf_label}: {rt.name or '-'}",
                    "Destination": _val(rt.destination),
                    "Interface": _val(rt.interface),
                    "NH Type": _val(rt.nexthop_type),
                    "NH Value": _val(rt.nexthop_ip_address or rt.nexthop),
                    "Metric": _val(rt.metric, "10"),
                    "AD": _val(rt.admin_distance, "10"),
                })
    return rows


def _pa_vpn_rows(cfg: PANOSConfig) -> list[dict[str, Any]]:
    gw_by_name = {gw.name: gw for gw in cfg.ike_gateways if gw.name}
    rows: list[dict[str, Any]] = []
    for tun in cfg.ipsec_tunnels:
        gws = tun.ike_gateways or []
        gw_obj = gw_by_name.get(gws[0]) if gws else None
        # Explicitly exclude secret/credential fields (e.g. pre_shared_key_configured).
        rows.append({
            "_key": _val(tun.name),
            "IKE GW": _join(gws),
            "IKE Interface": _val(gw_obj.local_interface if gw_obj else None),
            "IKE Peer IP": _val(gw_obj.peer_address if gw_obj else None),
            "Tunnel Intf": _val(tun.tunnel_interface),
            "Crypto": _val(tun.ipsec_crypto_profile),
        })
    return rows


def _pa_iface_rows(cfg: PANOSConfig) -> list[dict[str, Any]]:
    zone_by_iface: dict[str, str] = {}
    for z in cfg.zones:
        if z.name:
            for m in z.members or []:
                zone_by_iface[m.strip()] = z.name

    vr_by_iface: dict[str, str] = {}
    for vr in cfg.virtual_routers:
        if vr.name:
            for m in vr.interfaces or []:
                vr_by_iface[m.strip()] = vr.name

    rows: list[dict[str, Any]] = []
    for iface in cfg.interfaces:
        name = _val(iface.name)
        rows.append({
            "_key": name,
            "Type": _val(iface.interface_family),
            "IP Address": _join(iface.ipv4_addresses),
            "Zone": zone_by_iface.get(name, "-"),
            "Virtual Router": vr_by_iface.get(name, "-"),
            "Mgmt Profile": _val(iface.management_profile),
            "Link State": _val(iface.link_state, "auto"),
        })
    for unit in cfg.interface_units:
        name = _val(unit.name)
        rows.append({
            "_key": name,
            "Type": f"{_val(unit.interface_family)} subinterface",
            "IP Address": _join(unit.ipv4_addresses),
            "Zone": zone_by_iface.get(name, "-"),
            "Virtual Router": vr_by_iface.get(name, "-"),
            "Mgmt Profile": _val(unit.management_profile),
            "Link State": "unit",
        })
    return rows


def diff_paloalto_configs(
    before: PANOSConfig,
    after: PANOSConfig,
    *,
    before_name: str = "Current",
    after_name: str = "Comparison",
) -> dict[str, Any]:
    """Compare two Palo Alto PANOSConfig snapshots across 5 structural domains."""
    domain_map = {
        "Security Policies": _diff_records(
            _pa_sec_rows(before),
            _pa_sec_rows(after),
            key_fn=lambda r: r["_key"],
            compare_fields=["Source Zone", "Source Addr", "Dest Zone", "Dest Addr", "Application", "Service", "Action", "Disabled"],
            summary_fields=["Source Zone", "Dest Zone", "Source Addr", "Dest Addr", "Action"],
        ),
        "NAT Policies": _diff_records(
            _pa_nat_rows(before),
            _pa_nat_rows(after),
            key_fn=lambda r: r["_key"],
            compare_fields=["Source Zone", "Dest Zone", "Source Addr", "Dest Addr", "Service", "Src Translation", "Dst Translation", "Disabled"],
            summary_fields=["Source Zone", "Dest Zone", "Src Translation", "Dst Translation"],
        ),
        "Static Routes": _diff_records(
            _pa_route_rows(before),
            _pa_route_rows(after),
            key_fn=lambda r: r["_key"],
            compare_fields=["Destination", "Interface", "NH Type", "NH Value", "Metric", "AD"],
            summary_fields=["Destination", "Interface", "NH Value"],
        ),
        "IPSec Tunnels": _diff_records(
            _pa_vpn_rows(before),
            _pa_vpn_rows(after),
            key_fn=lambda r: r["_key"],
            compare_fields=["IKE GW", "IKE Interface", "IKE Peer IP", "Tunnel Intf", "Crypto"],
            summary_fields=["IKE GW", "IKE Peer IP", "Tunnel Intf", "Crypto"],
        ),
        "Interfaces": _diff_records(
            _pa_iface_rows(before),
            _pa_iface_rows(after),
            key_fn=lambda r: r["_key"],
            compare_fields=["Type", "IP Address", "Zone", "Virtual Router", "Mgmt Profile", "Link State"],
            summary_fields=["IP Address", "Zone", "Virtual Router"],
        ),
    }
    return _finalize_diff("palo_alto", domain_map, before_name, after_name)
