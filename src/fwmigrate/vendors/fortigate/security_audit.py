"""FortiGate security audit, certificate expiry, exposure, posture, and hygiene analyzers."""

from __future__ import annotations

from datetime import datetime, timezone
from re import search as re_search
from typing import Any

from ...source_reporting.audit_report import render_security_audit_html
from ...source_reporting.certificates import parse_pem_certificate, summarize_certificates
from ...source_reporting.exposure import (
    CRITICAL_VIP_PORTS,
    HIGH_RISK_VIP_PORTS,
    bare_ip,
    build_exposure_targets,
    clean_interface_name,
    is_public_ip,
)
from ...source_reporting.ip_match import weak_crypto_findings
from .derived import DerivedViews
from .extraction.source_metadata import FortiGateSourceMetadata
from .model.source import FGConfig
from .vpn_inspector import build_fortigate_vpn_inspector

_MGMT_PROTOCOLS = ("HTTP", "HTTPS", "SSH")


def _is_disabled(status: Any) -> bool:
    return str(status or "").strip().lower() in {"disable", "disabled", "down"}


def _policy_has_profile(pol: Any) -> bool:
    if str(pol.utm_status or "").strip().lower() == "enable":
        return True
    return any(
        bool(getattr(pol, field, None))
        for field in (
            "profile_group",
            "av_profile",
            "ips_sensor",
            "application_list",
            "webfilter_profile",
            "dnsfilter_profile",
            "ssl_ssh_profile",
            "file_filter_profile",
            "emailfilter_profile",
            "waf_profile",
        )
    )


def _preview_names(names: list[str], limit: int = 8) -> str:
    if not names:
        return "None"
    shown = names[:limit]
    tail = f" (+{len(names) - limit} more)" if len(names) > limit else ""
    return ", ".join(shown) + tail


def inspect_fortigate_certificates(
    config: FGConfig,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Inspect public X.509 PEM certificates across local, CA, and remote FortiGate stores."""
    now_dt = now or datetime.now(timezone.utc)
    store_labels = {"local": "Local", "ca": "CA", "remote": "Remote"}
    rows: list[dict[str, Any]] = []
    for cert in config.certificates:
        store_label = store_labels.get(cert.store, cert.store)
        parsed = parse_pem_certificate(cert.certificate, now=now_dt) if cert.certificate else None
        if parsed is not None:
            rows.append(
                {
                    "name": cert.name,
                    "store": store_label,
                    "vdom": cert.vdom or "root",
                    "common_name": parsed["common_name"],
                    "san": parsed["san"],
                    "issuer": parsed["issuer"],
                    "not_before": parsed["not_before"],
                    "expires": parsed["expires"],
                    "days_left": str(parsed["days_left"]),
                    "status": parsed["status"],
                }
            )
            continue
        rows.append(
            {
                "name": cert.name,
                "store": store_label,
                "vdom": cert.vdom or "root",
                "common_name": "-",
                "san": "-",
                "issuer": "-",
                "not_before": "-",
                "expires": "-",
                "days_left": "-",
                "status": "No PEM",
            }
        )
    return rows


def _local_in_restricted_ifaces(config: FGConfig) -> dict[str, set[str]]:
    restricted: dict[str, set[str]] = {}
    for pol in config.local_in_policies:
        if _is_disabled(pol.status):
            continue
        action = str(pol.action or "accept").strip().lower()
        srcaddrs = [s.strip() for s in pol.srcaddr or () if s.strip()]
        if action == "deny" or any(s.lower() != "all" for s in srcaddrs):
            bucket = restricted.setdefault(pol.vdom or "root", set())
            for iface in pol.intf or ():
                if iface.strip():
                    bucket.add(iface.strip())
    return restricted


def _admins_trusthost_restricted(config: FGConfig) -> tuple[bool, bool]:
    if not config.administrators:
        return False, False
    for admin in config.administrators:
        valid = [
            th
            for th in admin.trusthosts or ()
            if th.strip() not in {"0.0.0.0 0.0.0.0", "0.0.0.0/0", "::/0"}
        ]
        if not valid:
            return True, False
    return True, True


def find_fortigate_exposure(config: FGConfig) -> list[dict[str, Any]]:
    """Detect public-IP management access, WAN-behind-NAT exposure, and high-risk public VIP DNAT."""
    global_cfg = config.system_global[0] if config.system_global else None
    port_map = {
        "HTTP": int(global_cfg.admin_port if global_cfg and global_cfg.admin_port else 80),
        "HTTPS": int(global_cfg.admin_sport if global_cfg and global_cfg.admin_sport else 443),
        "SSH": int(global_cfg.admin_ssh_port if global_cfg and global_cfg.admin_ssh_port else 22),
    }

    local_in_by_vdom = _local_in_restricted_ifaces(config)
    has_admins, all_trusthost = _admins_trusthost_restricted(config)

    sdwan_members: set[tuple[str, str]] = {
        (sdwan.vdom or "root", member.interface.strip())
        for sdwan in config.sdwans
        for member in sdwan.members or ()
        if member.interface and member.interface.strip()
    }

    intf_to_vip_public_ips: dict[tuple[str, str], list[str]] = {}
    for vip in config.vips:
        v_intf = str(vip.extintf or "").strip()
        v_ext = bare_ip(vip.extip)
        if v_intf and v_intf.lower() != "any" and is_public_ip(v_ext):
            bucket = intf_to_vip_public_ips.setdefault((vip.vdom or "root", v_intf), [])
            if v_ext not in bucket:
                bucket.append(v_ext)

    findings: list[dict[str, Any]] = []
    for iface in config.interfaces:
        if str(iface.type or "").strip().lower() == "zone":
            continue
        if _is_disabled(iface.status):
            continue

        vdom = iface.vdom or "root"
        iface_name = clean_interface_name(iface.name)
        local_in_ifaces = local_in_by_vdom.get(vdom, set())

        candidate_endpoints: list[tuple[str, list[str]]] = []
        if iface.ip or iface.allowaccess:
            candidate_endpoints.append((iface.ip or "", list(iface.allowaccess or ())))
        for sec in iface.secondary_ips or ():
            candidate_endpoints.append((sec.ip or "", list(sec.allowaccess or iface.allowaccess or ())))

        matched_primary = False
        for ip_field, raw_access in candidate_endpoints:
            tokens = {str(t).strip().upper() for t in raw_access if str(t).strip()}
            protocols = [p for p in _MGMT_PROTOCOLS if p in tokens]
            if not protocols:
                continue

            bare = bare_ip(ip_field)
            if is_public_ip(bare):
                matched_primary = True
                if iface_name in local_in_ifaces or "any" in local_in_ifaces:
                    restricted = True
                    note = "Restricted (local-in-policy)"
                elif has_admins and all_trusthost:
                    restricted = True
                    note = "Restricted (admin trusthost)"
                else:
                    restricted = False
                    note = "Unrestricted (no trusthost / local-in-policy)"

                severity = "critical" if ("HTTP" in protocols or not restricted) else "warn"
                findings.append(
                    {
                        "interface": iface_name,
                        "vdom": vdom,
                        "ip": bare,
                        "protocols": protocols,
                        "display_protocols": [f"{p} ({port_map[p]})" for p in protocols],
                        "note": note,
                        "restricted": restricted,
                        "severity": severity,
                        "targets": build_exposure_targets([bare], protocols, port_map),
                    }
                )
            elif not matched_primary:
                role_low = str(iface.role or "").strip().lower()
                is_wan_like = (
                    role_low == "wan"
                    or iface_name.lower().startswith("wan")
                    or (vdom, iface_name) in sdwan_members
                )
                if is_wan_like and ip_field.strip():
                    matched_primary = True
                    inferred_ips = intf_to_vip_public_ips.get((vdom, iface_name), [])
                    if inferred_ips:
                        note = (
                            f"WAN Behind NAT (inferred public IP via VIP: {', '.join(inferred_ips)})"
                            " — verify upstream DMZ/forwarding"
                        )
                        targets = build_exposure_targets(inferred_ips, protocols, port_map)
                    else:
                        note = "WAN Behind NAT (private IP) — check upstream router DMZ / port-forwarding"
                        targets = []
                    findings.append(
                        {
                            "interface": iface_name,
                            "vdom": vdom,
                            "ip": ip_field.strip(),
                            "protocols": protocols,
                            "display_protocols": [f"{p} ({port_map[p]})" for p in protocols],
                            "note": note,
                            "restricted": False,
                            "severity": "warn",
                            "targets": targets,
                        }
                    )

    if config.vips and config.policies:
        for vip in config.vips:
            if _is_disabled(vip.status):
                continue
            ext_ip = bare_ip(vip.extip)
            if not vip.name or not is_public_ip(ext_ip):
                continue
            port_str = str(vip.extport or vip.mappedport or "").strip()
            if not port_str.isdigit():
                continue
            vip_port = int(port_str)
            if vip_port not in HIGH_RISK_VIP_PORTS:
                continue
            vdom = vip.vdom or "root"
            matching_pols = [
                pol
                for pol in config.policies
                if (pol.vdom or "root") == vdom
                and not _is_disabled(pol.status)
                and str(pol.action or "").strip().upper() == "ACCEPT"
                and vip.name in (pol.dstaddr or ())
            ]
            if not matching_pols:
                continue

            proto_label = HIGH_RISK_VIP_PORTS[vip_port]
            any_src_all = any(
                s.strip().lower() in {"all", "any"}
                for pol in matching_pols
                for s in (pol.srcaddr or ())
            )
            severity = "critical" if (vip_port in CRITICAL_VIP_PORTS and any_src_all) else "warn"
            pol_ids = ", ".join(f"#{pol.policy_id if pol.policy_id is not None else '?'}" for pol in matching_pols)
            mapped_to = ", ".join(vip.mappedip or ()) or "-"
            findings.append(
                {
                    "interface": f"VIP: {vip.name} ({vip.extintf or 'any'})",
                    "vdom": vdom,
                    "ip": ext_ip,
                    "protocols": [proto_label],
                    "display_protocols": [f"{proto_label} ({vip_port}) → {mapped_to}"],
                    "note": (
                        f"Public DNAT via Policy {pol_ids} · Source: "
                        f"{'all (Unrestricted)' if any_src_all else 'Restricted'}"
                    ),
                    "restricted": not any_src_all,
                    "severity": severity,
                    "targets": [{"ip": ext_ip, "port": vip_port, "protocol": proto_label}],
                }
            )

    return findings


def evaluate_fortigate_posture(
    config: FGConfig,
    *,
    metadata: FortiGateSourceMetadata | None = None,
) -> dict[str, str]:
    """Infer Internet connectivity and local disk / log storage posture from explicit FGConfig."""
    has_default = False
    is_sdwan_default = False
    for rt in config.static_routes:
        if _is_disabled(rt.status):
            continue
        dst = str(rt.dst or "").strip()
        is_zero = dst in {"0.0.0.0 0.0.0.0", "0.0.0.0/0"} or (not dst and not rt.dstaddr and bool(rt.sdwan_zone))
        if is_zero:
            has_default = True
            dev_low = str(rt.device or "").strip().lower()
            if rt.sdwan_zone or dev_low in {"virtual-wan-link", "sdwan"}:
                is_sdwan_default = True

    has_dhcp_pppoe = any(
        not _is_disabled(iface.status) and str(iface.mode or "").strip().lower() in {"dhcp", "pppoe"}
        for iface in config.interfaces
    )

    has_public_wan = any(
        str(iface.type or "").strip().lower() != "zone"
        and not _is_disabled(iface.status)
        and is_public_ip(iface.ip)
        for iface in config.interfaces
    )

    has_outbound_nat = any(
        not _is_disabled(pol.status)
        and str(pol.action or "").strip().upper() == "ACCEPT"
        and str(pol.nat or "").strip().lower() == "enable"
        for pol in config.policies
    )

    has_public_vip = any(
        not _is_disabled(vip.status) and is_public_ip(vip.extip)
        for vip in config.vips
    )

    has_public_vpn = any(
        is_public_ip(p1.remote_gw)
        for p1 in config.ipsec_phase1
    )

    has_public_dns = any(
        is_public_ip(dns.primary) or is_public_ip(dns.secondary)
        for dns in config.system_dns
    )

    signals: list[str] = []
    if has_default:
        signals.append("SD-WAN default route" if is_sdwan_default else "0.0.0.0/0 route")
    if has_public_wan:
        signals.append("public WAN IP")
    elif has_dhcp_pppoe:
        signals.append("DHCP/PPPoE WAN")
    if has_outbound_nat:
        signals.append("outbound NAT")
    if has_public_vip:
        signals.append("public VIPs")
    if has_public_vpn:
        signals.append("public IPSec peer")
    if has_public_dns:
        signals.append("public DNS")

    if (has_default or has_dhcp_pppoe) and (has_public_wan or has_dhcp_pppoe):
        internet = "Connected (Direct Public IP)"
    elif has_default and (has_outbound_nat or has_public_vip or has_public_vpn or has_public_dns):
        internet = "Connected (Behind Upstream NAT)"
    elif has_public_wan or has_public_vip or has_public_vpn:
        internet = "Likely Connected (Public Peers / VIPs)"
    else:
        internet = "Internal / Air-Gapped"

    internet_sub = ", ".join(signals[:4]) if signals else "No default route, public WAN IP, or outbound NAT"

    model = str((metadata.hardware_model if metadata else None) or "Unknown")
    disk_present = bool(config.log_disk_settings)
    disk_enabled = any(not _is_disabled(d.status) for d in config.log_disk_settings)
    has_sys_storage = bool(config.system_storages)

    remote_log_targets: list[str] = []
    if any(not _is_disabled(s.status) and s.status is not None for s in config.syslog_settings):
        remote_log_targets.append("Syslog")
    if any(not _is_disabled(f.status) and f.status is not None for f in config.fortianalyzer_settings):
        remote_log_targets.append("FortiAnalyzer")
    if any(not _is_disabled(g.status) and g.status is not None for g in config.log_fortiguard_settings):
        remote_log_targets.append("FortiCloud")

    m_num = re_search(r"(\d+)(?:[A-Z]|$)", model.upper())
    last_digit = m_num.group(1)[-1] if m_num else ""

    if "VM" in model.upper():
        disk = "Yes (Virtual Disk)"
        disk_sub = "Disk logging enabled" if (disk_present and disk_enabled) else "Virtual appliance storage"
    elif last_digit == "1":
        disk = "Yes (Onboard SSD)"
        if disk_present and disk_enabled:
            disk_sub = "Disk logging enabled"
        elif disk_present:
            disk_sub = "Disk logging disabled"
        else:
            disk_sub = "Hardware SSD model (*1 series)"
    elif disk_present or has_sys_storage:
        disk = "Yes (Log Disk Configured)"
        disk_sub = "Disk logging enabled" if disk_enabled else "Disk logging disabled"
    elif last_digit == "0":
        disk = "No (Diskless Model)"
        disk_sub = f"Remote logging: {', '.join(remote_log_targets)}" if remote_log_targets else "Memory-only logs (no Syslog/FAZ)"
    else:
        disk = "Unknown"
        disk_sub = f"Remote logging: {', '.join(remote_log_targets)}" if remote_log_targets else "No disk config block"

    return {
        "internet": internet,
        "internet_sub": internet_sub,
        "disk": disk,
        "disk_sub": disk_sub,
    }


def _parse_fg_onetime_end(end_str: str | None) -> datetime | None:
    raw = str(end_str or "").strip()
    if not raw:
        return None
    for fmt in ("%H:%M %Y/%m/%d", "%Y/%m/%d %H:%M", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def analyze_fortigate_hygiene(
    config: FGConfig,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Identify unreferenced FortiGate objects, rule hygiene issues, and draft cleanup CLI."""
    now_dt = now or datetime.now(timezone.utc)
    referenced: set[tuple[str, str]] = set()
    used_schedules: set[tuple[str, str]] = set()

    def _ref(vdom: str | None, name: str | None) -> None:
        cleaned = str(name or "").strip()
        if cleaned:
            referenced.add((vdom or "root", cleaned))

    for pol in config.policies:
        vdom = pol.vdom or "root"
        for tok in (*(pol.srcaddr or ()), *(pol.dstaddr or ()), *(pol.srcaddr6 or ()), *(pol.dstaddr6 or ()), *(pol.service or ()), *(pol.poolname or ()), *(pol.poolname6 or ())):
            _ref(vdom, tok)
        if pol.schedule:
            _ref(vdom, pol.schedule)
            used_schedules.add((vdom, pol.schedule.strip()))

    for pp in config.proxy_policies:
        vdom = pp.vdom or "root"
        for tok in (*(pp.srcaddr or ()), *(pp.dstaddr or ()), *(pp.srcaddr6 or ()), *(pp.dstaddr6 or ()), *(pp.service or ()), *(pp.poolname or ())):
            _ref(vdom, tok)
        if pp.schedule:
            _ref(vdom, pp.schedule)

    for snat in config.central_snat:
        vdom = snat.vdom or "root"
        for tok in (*(snat.orig_addr or ()), *(snat.orig_addr6 or ()), *(snat.dst_addr or ()), *(snat.dst_addr6 or ()), *(snat.nat_ippool or ()), *(snat.nat_ippool6 or ())):
            _ref(vdom, tok)

    for lip in config.local_in_policies:
        vdom = lip.vdom or "root"
        for tok in (*(lip.srcaddr or ()), *(lip.dstaddr or ()), *(lip.service or ())):
            _ref(vdom, tok)
        if lip.schedule:
            _ref(vdom, lip.schedule)

    for grp in config.address_groups:
        for member in grp.members or ():
            _ref(grp.vdom, member)

    for sgrp in config.service_groups:
        for member in sgrp.members or ():
            _ref(sgrp.vdom, member)

    for vgrp in config.vip_groups:
        for member in vgrp.members or ():
            _ref(vgrp.vdom, member)

    for p2 in (*config.ipsec_phase2, *config.ipsec_policy_phase2):
        _ref(p2.vdom, p2.src_name)
        _ref(p2.vdom, p2.dst_name)
        _ref(p2.vdom, p2.src_name6)
        _ref(p2.vdom, p2.dst_name6)

    for portal in config.ssl_vpn_portals:
        for tok in (*(portal.ip_pools or ()), *(portal.split_tunneling_routing_address or ())):
            _ref(portal.vdom, tok)

    for ssl_s in config.ssl_vpn_settings:
        for tok in (*(ssl_s.tunnel_ip_pools or ()), *(ssl_s.source_address or ())):
            _ref(ssl_s.vdom, tok)

    unused_objects: list[dict[str, str]] = []
    cleanup_cmds: dict[str, list[str]] = {
        "firewall addrgrp": [],
        "firewall address": [],
        "firewall service group": [],
        "firewall service custom": [],
        "firewall vip": [],
        "firewall ippool": [],
    }

    for addr in config.addresses:
        if addr.address_family != "ipv4":
            continue
        if addr.name.lower() in {"all", "any", "none"}:
            continue
        if (addr.vdom or "root", addr.name) not in referenced:
            detail = addr.subnet or addr.fqdn or (f"{addr.start_ip}-{addr.end_ip}" if addr.start_ip and addr.end_ip else "-")
            unused_objects.append({"category": f"Address ({addr.type or 'ipmask'})", "name": addr.name, "scope": addr.vdom or "root", "value": detail})
            cleanup_cmds["firewall address"].append(addr.name)

    for grp in config.address_groups:
        if grp.address_family != "ipv4":
            continue
        if (grp.vdom or "root", grp.name) not in referenced:
            unused_objects.append({"category": "Address Group", "name": grp.name, "scope": grp.vdom or "root", "value": ", ".join(grp.members or ()) or "-"})
            cleanup_cmds["firewall addrgrp"].append(grp.name)

    for svc in config.services:
        if svc.name.upper() in {"ALL", "ANY", "ALL_TCP", "ALL_UDP", "ALL_ICMP", "PING"}:
            continue
        if (svc.vdom or "root", svc.name) not in referenced:
            detail = svc.tcp_portrange or svc.udp_portrange or svc.protocol or "-"
            unused_objects.append({"category": "Service", "name": svc.name, "scope": svc.vdom or "root", "value": detail})
            cleanup_cmds["firewall service custom"].append(svc.name)

    for sgrp in config.service_groups:
        if (sgrp.vdom or "root", sgrp.name) not in referenced:
            unused_objects.append({"category": "Service Group", "name": sgrp.name, "scope": sgrp.vdom or "root", "value": ", ".join(sgrp.members or ()) or "-"})
            cleanup_cmds["firewall service group"].append(sgrp.name)

    for vip in config.vips:
        if (vip.vdom or "root", vip.name) not in referenced:
            unused_objects.append({"category": "Virtual IP (VIP)", "name": vip.name, "scope": vip.vdom or "root", "value": f"{vip.extip or '-'} → {', '.join(vip.mappedip or ()) or '-'}"})
            cleanup_cmds["firewall vip"].append(vip.name)

    for pool in config.ip_pools:
        if (pool.vdom or "root", pool.name) not in referenced:
            unused_objects.append({"category": "IP Pool", "name": pool.name, "scope": pool.vdom or "root", "value": f"{pool.startip or '-'}-{pool.endip or '-'}"})
            cleanup_cmds["firewall ippool"].append(pool.name)

    hygiene_issues: list[dict[str, str]] = []
    disabled_count = broad_count = extra_count = 0

    for pol in config.policies:
        pid = pol.policy_id if pol.policy_id is not None else "?"
        label = f"#{pid} {pol.name or '-'} ({pol.vdom or 'root'})"
        if _is_disabled(pol.status):
            disabled_count += 1
            hygiene_issues.append(
                {
                    "finding": "Disabled Policy",
                    "target": label,
                    "details": f"{', '.join(pol.srcintf or ())} → {', '.join(pol.dstintf or ())}",
                    "severity": "Warning",
                    "tone": "warn",
                }
            )
            continue

        if str(pol.action or "").strip().upper() == "ACCEPT":
            srcs = {s.strip().lower() for s in pol.srcaddr or ()}
            dsts = {d.strip().lower() for d in pol.dstaddr or ()}
            svcs = {s.strip().lower() for s in pol.service or ()}
            if (srcs & {"all", "any"}) and (dsts & {"all", "any"}) and (svcs & {"all", "any"}):
                broad_count += 1
                hygiene_issues.append(
                    {
                        "finding": "Overly Broad Allow Policy",
                        "target": label,
                        "details": f"{', '.join(pol.srcintf or ())} → {', '.join(pol.dstintf or ())} allows all/all/ALL",
                        "severity": "Critical",
                        "tone": "danger",
                    }
                )
            log_low = str(pol.logtraffic or "").strip().lower()
            if log_low in {"disable", "none", ""}:
                extra_count += 1
                hygiene_issues.append(
                    {
                        "finding": "Allow Policy Without Logging",
                        "target": label,
                        "details": f"logtraffic={pol.logtraffic or 'not explicitly configured'}",
                        "severity": "Warning",
                        "tone": "warn",
                    }
                )

    for sched in config.one_time_schedules:
        end_dt = _parse_fg_onetime_end(sched.end or sched.end_utc)
        if end_dt is not None and end_dt < now_dt:
            extra_count += 1
            in_pol = " (referenced by policy)" if (sched.vdom or "root", sched.name) in used_schedules else " (unreferenced)"
            hygiene_issues.append(
                {
                    "finding": "Expired One-Time Schedule",
                    "target": f"{sched.name} ({sched.vdom or 'root'})",
                    "details": f"Ended {end_dt.strftime('%Y-%m-%d %H:%M')} UTC{in_pol}",
                    "severity": "Warning",
                    "tone": "warn",
                }
            )

    cli_lines: list[str] = []
    for block_name, names in cleanup_cmds.items():
        if not names:
            continue
        cli_lines.append(f"config {block_name}")
        for name in dict.fromkeys(names):
            cli_lines.append(f'    delete "{name}"')
        cli_lines.append("end")
        cli_lines.append("")

    return {
        "unused_objects": unused_objects,
        "hygiene_issues": hygiene_issues,
        "counts": {
            "unused": len(unused_objects),
            "disabled": disabled_count,
            "broad": broad_count,
            "extra": extra_count,
        },
        "cleanup_cli": "\n".join(cli_lines).strip(),
    }


def run_fortigate_quick_audit(
    config: FGConfig,
    hygiene: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Summarize high/medium/info security audit findings from FGConfig."""
    any_any: list[str] = []
    no_profile: list[str] = []
    unlogged: list[str] = []
    disabled_pols: list[str] = []

    for pol in config.policies:
        pid = pol.policy_id if pol.policy_id is not None else "?"
        label = f"#{pid} {pol.name or '-'}"
        if _is_disabled(pol.status):
            disabled_pols.append(label)
            continue
        if str(pol.action or "").strip().upper() != "ACCEPT":
            continue
        srcs = {s.strip().lower() for s in pol.srcaddr or ()}
        dsts = {d.strip().lower() for d in pol.dstaddr or ()}
        svcs = {s.strip().lower() for s in pol.service or ()}
        if (srcs & {"all", "any"}) and (dsts & {"all", "any"}) and (svcs & {"all", "any"}):
            any_any.append(label)
        if not _policy_has_profile(pol):
            no_profile.append(label)
        if str(pol.logtraffic or "").strip().lower() in {"disable", "none", ""}:
            unlogged.append(label)

    weak_vpn_high: list[str] = []
    weak_vpn_med: list[str] = []
    for p1 in (*config.ipsec_phase1, *config.ipsec_policy_phase1):
        weak_algos = weak_crypto_findings(p1.proposal)
        if weak_algos:
            weak_vpn_high.append(f"P1 {p1.name} ({', '.join(weak_algos)})")
        if str(p1.ike_version or "").strip() == "1":
            weak_vpn_med.append(f"P1 {p1.name} (IKEv1)")
        weak_dh = weak_crypto_findings((), p1.dhgrp or ())
        if weak_dh:
            weak_vpn_med.append(f"P1 {p1.name} ({', '.join(weak_dh)})")

    for p2 in (*config.ipsec_phase2, *config.ipsec_policy_phase2):
        weak_algos = weak_crypto_findings(p2.proposal)
        if weak_algos:
            weak_vpn_high.append(f"P2 {p2.name} ({', '.join(weak_algos)})")
        if str(p2.pfs or "").strip().lower() != "disable":
            weak_dh = weak_crypto_findings((), p2.dhgrp or ())
            if weak_dh:
                weak_vpn_med.append(f"P2 {p2.name} ({', '.join(weak_dh)})")

    unused_addrs = [
        obj["name"]
        for obj in (hygiene or {}).get("unused_objects", ())
        if str(obj.get("category", "")).startswith("Address (")
    ]

    no_trusthost: list[str] = []
    super_no_2fa: list[str] = []
    for admin in config.administrators:
        valid_th = [
            th
            for th in (admin.trusthosts or ())
            if th.strip() and th.strip() not in {"0.0.0.0 0.0.0.0", "0.0.0.0/0", "::/0"}
        ]
        if not valid_th:
            no_trusthost.append(admin.name)
        if str(admin.accprofile or "").strip() == "super_admin":
            tf = str(admin.two_factor or "").strip().lower()
            tfa = str(admin.two_factor_authentication or "").strip().lower()
            if tf in {"", "disable", "disabled"} and tfa in {"", "disable", "disabled"}:
                super_no_2fa.append(admin.name)

    pp_on = any(
        str(g.admin_password_policy or "").strip().lower() == "enable"
        for g in config.system_global
    ) or any(
        str((p.raw_extra or {}).get("status", "")).strip().lower() == "enable"
        for p in config.password_policies
    )
    lock_thresh = next(
        (g.admin_lockout_threshold for g in config.system_global if g.admin_lockout_threshold is not None),
        None,
    )
    lock_dur = next(
        (g.admin_lockout_duration for g in config.system_global if g.admin_lockout_duration is not None),
        None,
    )
    eff_thresh = 3 if lock_thresh is None else lock_thresh
    eff_dur = 60 if lock_dur is None else lock_dur
    lockout_weak = bool(config.system_global) and (eff_thresh == 0 or eff_thresh > 10 or eff_dur == 0)

    findings: list[dict[str, Any]] = []
    if any_any:
        findings.append({"severity": "High", "category": "Overly Permissive ANY-ANY Allow Rules", "count": len(any_any), "details": _preview_names(any_any)})
    if weak_vpn_high:
        findings.append({"severity": "High", "category": "Weak VPN Encryption / Hash (DES/3DES/MD5/SHA1)", "count": len(weak_vpn_high), "details": _preview_names(weak_vpn_high)})
    if no_profile:
        findings.append({"severity": "Medium", "category": "Allow Policies Missing Security Profiles", "count": len(no_profile), "details": _preview_names(no_profile)})
    if weak_vpn_med:
        findings.append({"severity": "Medium", "category": "Legacy VPN IKEv1 or Weak DH Group (1/2/5)", "count": len(weak_vpn_med), "details": _preview_names(weak_vpn_med)})
    if no_trusthost:
        findings.append({"severity": "Medium", "category": "Admin Accounts Without Trusted Hosts", "count": len(no_trusthost), "details": _preview_names(no_trusthost)})
    if super_no_2fa:
        findings.append({"severity": "Medium", "category": "Super-Admin Accounts Without 2FA", "count": len(super_no_2fa), "details": _preview_names(super_no_2fa)})
    if config.administrators and not pp_on:
        findings.append({"severity": "Medium", "category": "Admin Password Policy Disabled", "count": 1, "details": "Admin password-policy is disabled (no minimum complexity enforced)."})
    if lockout_weak:
        findings.append({"severity": "Medium", "category": "Admin Login Lockout Disabled or Weak", "count": 1, "details": f"admin-lockout-threshold={eff_thresh}, admin-lockout-duration={eff_dur}s"})
    if unlogged:
        findings.append({"severity": "Info", "category": "Unlogged Allow Policies", "count": len(unlogged), "details": _preview_names(unlogged)})
    if disabled_pols:
        findings.append({"severity": "Info", "category": "Disabled Firewall Policies", "count": len(disabled_pols), "details": _preview_names(disabled_pols)})
    if unused_addrs:
        findings.append({"severity": "Info", "category": "Unused Address Objects (Best-Effort)", "count": len(unused_addrs), "details": _preview_names(unused_addrs)})

    return {
        "findings": findings,
        "high_count": sum(1 for f in findings if f["severity"] == "High"),
        "med_count": sum(1 for f in findings if f["severity"] == "Medium"),
        "info_count": sum(1 for f in findings if f["severity"] == "Info"),
    }


def build_fortigate_security_audit(
    config: FGConfig,
    derived: DerivedViews,
    *,
    metadata: FortiGateSourceMetadata | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build complete Phase 2 security audit payload for FortiGate."""
    certificates = inspect_fortigate_certificates(config, now=now)
    exposure = find_fortigate_exposure(config)
    posture = evaluate_fortigate_posture(config, metadata=metadata)
    hygiene = analyze_fortigate_hygiene(config, now=now)
    quick_audit = run_fortigate_quick_audit(config, hygiene=hygiene)
    vpn_health = build_fortigate_vpn_inspector(config, derived)
    return {
        "vendor": "fortigate",
        "certificates": certificates,
        "certificate_summary": summarize_certificates(certificates),
        "exposure": exposure,
        "posture": posture,
        "hygiene": hygiene,
        "quick_audit": quick_audit,
        "vpn_health": vpn_health,
    }


def export_fortigate_audit_html(
    config: FGConfig,
    derived: DerivedViews,
    *,
    metadata: FortiGateSourceMetadata | None = None,
    lifecycle_card: dict[str, Any] | None = None,
    filename: str = "fortigate.conf",
    now: datetime | None = None,
) -> bytes:
    """Render standalone HTML security audit report for a FortiGate configuration."""
    audit = build_fortigate_security_audit(config, derived, metadata=metadata, now=now)
    hostname = next((g.hostname for g in config.system_global if g.hostname), None) or "FortiGate"
    overview_items = [
        ("Hostname", hostname),
        ("Hardware Model", (metadata.hardware_model if metadata else None) or "-"),
        ("FortiOS Version", (metadata.fortios_version if metadata else None) or "-"),
        ("Interfaces", str(len(config.interfaces))),
        ("Firewall Policies", str(len(config.policies))),
        ("IPSec Tunnels", str(len(config.ipsec_phase1))),
    ]
    return render_security_audit_html(
        vendor_label="FortiGate",
        hostname=hostname,
        filename=filename,
        overview_items=overview_items,
        lifecycle_card=lifecycle_card,
        posture=audit["posture"],
        exposure_findings=audit["exposure"],
        certificates=audit["certificates"],
        vpn_inspections=audit["vpn_health"],
        quick_audit=audit["quick_audit"],
        hygiene=audit["hygiene"],
    )
