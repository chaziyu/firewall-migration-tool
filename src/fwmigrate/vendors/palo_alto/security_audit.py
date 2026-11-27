"""Palo Alto PAN-OS security audit, certificate expiry, exposure, posture, and hygiene analyzers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...source_reporting.audit_report import render_security_audit_html
from ...source_reporting.certificates import (
    classify_expiry,
    parse_panos_cert_time,
    parse_pem_certificate,
    summarize_certificates,
)
from ...source_reporting.exposure import (
    bare_ip,
    build_exposure_targets,
    clean_interface_name,
    is_public_ip,
)
from ...source_reporting.ip_match import weak_crypto_findings
from .model.source import PANOSConfig
from .source_model import PANOSDerivedViews, PANScope, pan_scope_identity
from .vpn_inspector import build_paloalto_vpn_inspector

_MGMT_PROTOCOLS = ("HTTP", "HTTPS", "SSH")
_PA_PORT_MAP = {"HTTP": 80, "HTTPS": 443, "SSH": 22}


def _scope_label(scope: PANScope | None) -> str:
    return pan_scope_identity(scope) if scope else "shared"


def _is_yes(value: Any) -> bool:
    return str(value or "").strip().lower() in {"yes", "true", "1"}


def _preview_names(names: list[str], limit: int = 8) -> str:
    if not names:
        return "None"
    shown = names[:limit]
    tail = f" (+{len(names) - limit} more)" if len(names) > limit else ""
    return ", ".join(shown) + tail


def inspect_paloalto_certificates(
    config: PANOSConfig,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Inspect public X.509 PEM certificates and XML validity metadata from PANOSConfig."""
    now_dt = now or datetime.now(timezone.utc)
    rows: list[dict[str, Any]] = []
    for cert in config.certificates:
        scope_text = _scope_label(cert.scope)
        if cert.public_key:
            parsed = parse_pem_certificate(cert.public_key, now=now_dt)
            if parsed is not None:
                rows.append(
                    {
                        "name": cert.name or "-",
                        "store": scope_text,
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

        nb_dt = parse_panos_cert_time(cert.not_valid_before)
        exp_dt = parse_panos_cert_time(cert.not_valid_after)
        if exp_dt is not None:
            days_left, status = classify_expiry(exp_dt, now=now_dt)
            days_str = str(days_left)
            exp_str = exp_dt.strftime("%Y-%m-%d")
        else:
            status = "No PEM"
            days_str = "-"
            exp_str = cert.not_valid_after or "-"

        rows.append(
            {
                "name": cert.name or "-",
                "store": scope_text,
                "common_name": cert.common_name or "-",
                "san": "-",
                "issuer": cert.issuer or "-",
                "not_before": nb_dt.strftime("%Y-%m-%d") if nb_dt is not None else (cert.not_valid_before or "-"),
                "expires": exp_str,
                "days_left": days_str,
                "status": status,
            }
        )
    return rows


def _permitted_is_restricted(permitted: list[str] | None) -> bool:
    tokens = [p.strip().lower() for p in (permitted or ()) if p and p.strip()]
    if not tokens:
        return False
    return not any(tok in {"any", "-", "none", "0.0.0.0/0", "::/0"} for tok in tokens)


def find_paloalto_exposure(
    config: PANOSConfig,
    derived: PANOSDerivedViews,
) -> list[dict[str, Any]]:
    """Detect public management interface (MGT) and dataplane interface exposures."""
    findings: list[dict[str, Any]] = []

    for sys_cfg in config.system_settings:
        mgt_ips = [bare_ip(ip) for ip in (sys_cfg.ip_address, sys_cfg.ipv6_address) if is_public_ip(ip)]
        if not mgt_ips:
            continue
        service = sys_cfg.service or {}
        # In PAN-OS, MGT HTTP/HTTPS/SSH are enabled unless disable-* is explicitly "yes".
        enabled_protos = [
            proto
            for proto, flag in (("HTTP", "disable-http"), ("HTTPS", "disable-https"), ("SSH", "disable-ssh"))
            if not _is_yes(service.get(flag))
        ]
        if not enabled_protos:
            continue
        restricted = _permitted_is_restricted(sys_cfg.permitted_ip)
        permitted_text = ", ".join(sys_cfg.permitted_ip or ()) or "any (Unrestricted)"
        severity = "critical" if ("HTTP" in enabled_protos or not restricted) else "warn"
        findings.append(
            {
                "interface": "Management (MGT)",
                "scope": _scope_label(sys_cfg.scope),
                "ip": ", ".join(mgt_ips),
                "protocols": enabled_protos,
                "display_protocols": [f"{p} ({_PA_PORT_MAP[p]})" for p in enabled_protos],
                "note": f"Permitted IPs: {permitted_text}",
                "restricted": restricted,
                "severity": severity,
                "targets": build_exposure_targets(mgt_ips, enabled_protos, _PA_PORT_MAP),
            }
        )

    profile_map: dict[tuple[str, str], tuple[list[str], list[str] | None]] = {}
    profile_global: dict[str, tuple[list[str], list[str] | None]] = {}
    for prof in config.management_profiles:
        if not prof.name:
            continue
        protos = [proto for proto in _MGMT_PROTOCOLS if _is_yes(prof.protocols.get(proto.lower()))]
        if not protos:
            continue
        entry = (protos, prof.permitted_ips)
        profile_map[(_scope_label(prof.scope), prof.name)] = entry
        profile_global.setdefault(prof.name, entry)

    if not profile_global:
        return findings

    seen: set[tuple[str, str]] = set()
    for topo in derived.interface_topology:
        if str(topo.link_state or "").strip().lower() == "down":
            continue
        if str(topo.parent_link_state or "").strip().lower() == "down":
            continue
        if not topo.management_profile:
            continue
        prof_info = profile_map.get((topo.scope, topo.management_profile)) or profile_global.get(topo.management_profile)
        if not prof_info:
            continue
        public_ips = [bare_ip(ip) for ip in (*topo.ipv4_addresses, *topo.ipv6_addresses) if is_public_ip(ip)]
        if not public_ips:
            continue
        iface_name = clean_interface_name(topo.interface)
        key = (topo.scope, iface_name)
        if key in seen:
            continue
        seen.add(key)

        protos, permitted_ips = prof_info
        restricted = _permitted_is_restricted(permitted_ips)
        permitted_text = ", ".join(permitted_ips or ()) or "any (Unrestricted)"
        severity = "critical" if ("HTTP" in protos or not restricted) else "warn"
        findings.append(
            {
                "interface": iface_name,
                "scope": topo.scope,
                "ip": ", ".join(public_ips),
                "protocols": protos,
                "display_protocols": [f"{p} ({_PA_PORT_MAP[p]})" for p in protos],
                "note": f"Profile: {topo.management_profile} · Permitted IPs: {permitted_text}",
                "restricted": restricted,
                "severity": severity,
                "targets": build_exposure_targets(public_ips, protos, _PA_PORT_MAP),
            }
        )

    return findings


def evaluate_paloalto_posture(
    config: PANOSConfig,
    derived: PANOSDerivedViews,
) -> dict[str, str]:
    """Infer PAN-OS Internet connectivity and local/syslog storage posture."""
    has_default = any(
        str(rt.destination or "").strip() in {"0.0.0.0/0", "::/0"}
        for rt in derived.static_routes
    )
    has_bgp = any(
        _is_yes(vr.bgp.enable)
        for vr in config.virtual_routers
        if vr.bgp is not None
    ) or any(
        _is_yes(vrf.bgp.enable)
        for lr in config.logical_routers
        for vrf in (lr.vrfs or ())
        if vrf.bgp is not None
    )

    has_public_intf = any(
        str(topo.link_state or "").strip().lower() != "down"
        and str(topo.parent_link_state or "").strip().lower() != "down"
        and any(is_public_ip(ip) for ip in (*topo.ipv4_addresses, *topo.ipv6_addresses))
        for topo in derived.interface_topology
    ) or any(
        is_public_ip(sys_cfg.ip_address) or is_public_ip(sys_cfg.ipv6_address)
        for sys_cfg in config.system_settings
    )

    has_public_vpn = any(
        is_public_ip(gw.peer_address)
        for gw in config.ike_gateways
    )

    has_outbound_nat = any(
        not _is_yes(rule.disabled) and rule.source_translation is not None
        for rule in config.nat_rules
    )

    signals: list[str] = []
    if has_default:
        signals.append("0.0.0.0/0 route")
    elif has_bgp:
        signals.append("BGP enabled")
    if has_public_intf:
        signals.append("public interface IP")
    if has_outbound_nat:
        signals.append("source NAT")
    if has_public_vpn:
        signals.append("public IPSec peer")

    if (has_default or has_bgp) and has_public_intf:
        internet = "Connected (Direct Public IP)"
    elif (has_default or has_bgp) and (has_outbound_nat or has_public_vpn):
        internet = "Connected (Behind Upstream NAT)"
    elif has_public_intf or has_public_vpn:
        internet = "Likely Connected (Public Peers / IP)"
    else:
        internet = "Internal / Air-Gapped"

    internet_sub = ", ".join(signals[:4]) if signals else "No default route, public interface IP, or source NAT"
    syslog_count = len(config.syslog_server_profiles)
    disk = "Yes (PAN-OS Local Disk)"
    disk_sub = (
        f"Local disk + {syslog_count} Syslog profile(s)"
        if syslog_count
        else "Local log storage (no Syslog profiles)"
    )
    return {
        "internet": internet,
        "internet_sub": internet_sub,
        "disk": disk,
        "disk_sub": disk_sub,
    }


def _parse_pa_onetime_end(non_recurring: list[str] | None) -> datetime | None:
    ends: list[datetime] = []
    for part in non_recurring or ():
        token = str(part).strip()
        if not token:
            continue
        end_tok = token.split("-", 1)[1].strip() if "-" in token else token
        for fmt in ("%Y/%m/%d@%H:%M", "%Y/%m/%d"):
            try:
                ends.append(datetime.strptime(end_tok, fmt).replace(tzinfo=timezone.utc))
                break
            except ValueError:
                continue
    return max(ends) if ends else None


def analyze_paloalto_hygiene(
    config: PANOSConfig,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Find unused PAN-OS objects, broad/disabled rules, and expired schedules."""
    now_dt = now or datetime.now(timezone.utc)
    referenced: set[str] = set()
    used_schedules: set[str] = set()

    def _ref_many(items: list[str] | None) -> None:
        for tok in items or ():
            cleaned = str(tok or "").strip()
            if cleaned:
                referenced.add(cleaned)

    for rule in config.security_rules:
        _ref_many(rule.source)
        _ref_many(rule.destination)
        _ref_many(rule.service)
        if rule.schedule:
            sched = rule.schedule.strip()
            referenced.add(sched)
            used_schedules.add(sched)

    for nat in config.nat_rules:
        _ref_many(nat.source)
        _ref_many(nat.destination)
        if nat.service:
            referenced.add(nat.service.strip())
        if nat.source_translation is not None:
            _ref_many(getattr(nat.source_translation, "translated_addresses", None))
            if getattr(nat.source_translation, "translated_address", None):
                referenced.add(nat.source_translation.translated_address.strip())
        if nat.destination_translation is not None and nat.destination_translation.translated_address:
            referenced.add(nat.destination_translation.translated_address.strip())
        if nat.dynamic_destination_translation is not None:
            _ref_many(nat.dynamic_destination_translation.translated_addresses)

    for rule in (*config.pbf_rules, *config.decryption_rules, *config.qos_rules, *config.authentication_rules, *config.dos_rules):
        _ref_many(getattr(rule, "source", None))
        _ref_many(getattr(rule, "destination", None))
        _ref_many(getattr(rule, "service", None))
        if getattr(rule, "schedule", None):
            referenced.add(rule.schedule.strip())

    for rule in config.app_override_rules:
        _ref_many(rule.source)
        _ref_many(rule.destination)

    for grp in config.address_groups:
        _ref_many(grp.static_members)
    for sgrp in config.service_groups:
        _ref_many(sgrp.members)

    unused_objects: list[dict[str, str]] = []
    for addr in config.addresses:
        if not addr.name or addr.name in referenced:
            continue
        kind = "IP Netmask" if addr.ip_netmask else ("IP Range" if addr.ip_range else ("FQDN" if addr.fqdn else "Address"))
        val = addr.ip_netmask or addr.ip_range or addr.fqdn or addr.ip_wildcard or "-"
        unused_objects.append({"category": f"Address ({kind})", "name": addr.name, "scope": _scope_label(addr.scope), "value": val})

    for grp in config.address_groups:
        if not grp.name or grp.name in referenced:
            continue
        kind = "Dynamic" if grp.dynamic_filter else "Static"
        val = grp.dynamic_filter or ", ".join(grp.static_members or ()) or "-"
        unused_objects.append({"category": f"Address Group ({kind})", "name": grp.name, "scope": _scope_label(grp.scope), "value": val})

    for svc in config.services:
        if not svc.name or svc.name.lower() in {"any", "application-default"} or svc.name in referenced:
            continue
        proto_parts = []
        if svc.tcp and svc.tcp.port:
            proto_parts.append(f"tcp/{svc.tcp.port}")
        if svc.udp and svc.udp.port:
            proto_parts.append(f"udp/{svc.udp.port}")
        if svc.sctp and svc.sctp.port:
            proto_parts.append(f"sctp/{svc.sctp.port}")
        unused_objects.append({"category": "Custom Service", "name": svc.name, "scope": _scope_label(svc.scope), "value": ", ".join(proto_parts) or "-"})

    for sgrp in config.service_groups:
        if not sgrp.name or sgrp.name in referenced:
            continue
        unused_objects.append({"category": "Service Group", "name": sgrp.name, "scope": _scope_label(sgrp.scope), "value": ", ".join(sgrp.members or ()) or "-"})

    hygiene_issues: list[dict[str, str]] = []
    disabled_count = broad_count = extra_count = 0

    for rule in config.security_rules:
        rname = f"{rule.name or '-'} ({_scope_label(rule.scope)})"
        zones_detail = f"{', '.join(rule.from_zones or ())} → {', '.join(rule.to_zones or ())}"
        if _is_yes(rule.disabled):
            disabled_count += 1
            hygiene_issues.append(
                {
                    "finding": "Disabled Security Rule",
                    "target": rname,
                    "details": zones_detail,
                    "severity": "Warning",
                    "tone": "warn",
                }
            )
            continue

        if str(rule.action or "").strip().lower() == "allow":
            srcs = {s.strip().lower() for s in rule.source or ()}
            dsts = {d.strip().lower() for d in rule.destination or ()}
            apps = {a.strip().lower() for a in rule.application or ()}
            svcs = {s.strip().lower() for s in rule.service or ()}
            if srcs == {"any"} and dsts == {"any"} and apps == {"any"} and svcs == {"any"}:
                broad_count += 1
                hygiene_issues.append(
                    {
                        "finding": "Overly Broad Allow Rule",
                        "target": rname,
                        "details": f"{zones_detail} allows any/any/any/any",
                        "severity": "Critical",
                        "tone": "danger",
                    }
                )

    for sched in config.schedules:
        if not sched.non_recurring:
            continue
        end_dt = _parse_pa_onetime_end(sched.non_recurring)
        if end_dt is not None and end_dt < now_dt:
            extra_count += 1
            in_pol = " (referenced by rule)" if (sched.name or "") in used_schedules else " (unreferenced)"
            hygiene_issues.append(
                {
                    "finding": "Expired One-Time Schedule",
                    "target": f"{sched.name or '-'} ({_scope_label(sched.scope)})",
                    "details": f"Ended {end_dt.strftime('%Y-%m-%d %H:%M')} UTC{in_pol}",
                    "severity": "Warning",
                    "tone": "warn",
                }
            )

    return {
        "unused_objects": unused_objects,
        "hygiene_issues": hygiene_issues,
        "counts": {
            "unused": len(unused_objects),
            "disabled": disabled_count,
            "broad": broad_count,
            "extra": extra_count,
        },
        "cleanup_cli": "",
    }


def run_paloalto_quick_audit(
    config: PANOSConfig,
    hygiene: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Summarize high/medium/info security audit findings from PANOSConfig."""
    any_any: list[str] = []
    no_profile: list[str] = []
    disabled_rules: list[str] = []

    for rule in config.security_rules:
        rname = rule.name or "-"
        if _is_yes(rule.disabled):
            disabled_rules.append(rname)
            continue
        if str(rule.action or "").strip().lower() != "allow":
            continue
        srcs = {s.strip().lower() for s in rule.source or ()}
        dsts = {d.strip().lower() for d in rule.destination or ()}
        apps = {a.strip().lower() for a in rule.application or ()}
        svcs = {s.strip().lower() for s in rule.service or ()}
        if "any" in srcs and "any" in dsts and "any" in apps and bool(svcs & {"any", "application-default"}):
            any_any.append(rname)
        ps = rule.profile_setting
        if ps is None or (not ps.groups and not ps.profiles):
            no_profile.append(rname)

    weak_vpn_high: list[str] = []
    weak_vpn_med: list[str] = []
    for gw in config.ike_gateways:
        if str(gw.ike_version or "").strip().lower() == "ikev1":
            weak_vpn_med.append(f"GW {gw.name or '-'} (IKEv1)")
    for prof in config.ike_crypto_profiles:
        weak_algos = weak_crypto_findings([*(prof.encryption_algorithms or ()), *(prof.authentication_algorithms or ())])
        if weak_algos:
            weak_vpn_high.append(f"IKE {prof.name or '-'} ({', '.join(weak_algos)})")
        weak_dh = weak_crypto_findings((), prof.dh_groups or ())
        if weak_dh:
            weak_vpn_med.append(f"IKE {prof.name or '-'} ({', '.join(weak_dh)})")
    for prof in config.ipsec_crypto_profiles:
        weak_algos = weak_crypto_findings([*(prof.esp_encryption or ()), *(prof.esp_authentication or ()), *(prof.ah_authentication or ())])
        if weak_algos:
            weak_vpn_high.append(f"IPSec {prof.name or '-'} ({', '.join(weak_algos)})")
        weak_dh = weak_crypto_findings((), (prof.dh_group,))
        if weak_dh:
            weak_vpn_med.append(f"IPSec {prof.name or '-'} ({', '.join(weak_dh)})")

    unused_addrs = [
        obj["name"]
        for obj in (hygiene or {}).get("unused_objects", ())
        if str(obj.get("category", "")).startswith("Address (")
    ]

    mgt_unrestricted = any(
        bool(sys_cfg.ip_address and str(sys_cfg.ip_address).strip() not in {"-", "Unknown"})
        and not _permitted_is_restricted(sys_cfg.permitted_ip)
        for sys_cfg in config.system_settings
    )
    pwd_comp_disabled = bool(config.password_complexities) and any(
        not _is_yes(pc.enabled) and str(pc.enabled or "").strip().lower() != "enable"
        for pc in config.password_complexities
    )

    has_global_lockout = False
    for setup in config.device_setup_settings:
        mgmt = setup.management if isinstance(setup.management, dict) else {}
        lockout_cfg = mgmt.get("admin-lockout") if isinstance(mgmt, dict) else None
        if isinstance(lockout_cfg, dict):
            fa = str(lockout_cfg.get("failed-attempts") or "").strip()
            if fa and fa != "0":
                has_global_lockout = True
                break

    has_prof_lockout = any(
        str((prof.lockout or {}).get("failed-attempts") or "").strip() not in {"", "-", "0"}
        for prof in config.authentication_profiles
    )
    lockout_missing = bool(config.device_setup_settings or config.administrators) and not has_global_lockout and not has_prof_lockout

    super_local_no_auth = [
        admin.name or "-"
        for admin in config.administrators
        if str(admin.built_in_role or "").strip().lower() == "superuser"
        and not str(admin.authentication_profile or "").strip()
    ]

    findings: list[dict[str, Any]] = []
    if any_any:
        findings.append({"severity": "High", "category": "Overly Permissive ANY-ANY Allow Rules", "count": len(any_any), "details": _preview_names(any_any)})
    if weak_vpn_high:
        findings.append({"severity": "High", "category": "Weak VPN Encryption / Hash (DES/3DES/MD5/SHA1)", "count": len(weak_vpn_high), "details": _preview_names(weak_vpn_high)})
    if no_profile:
        findings.append({"severity": "Medium", "category": "Allow Rules Missing Security Profiles", "count": len(no_profile), "details": _preview_names(no_profile)})
    if weak_vpn_med:
        findings.append({"severity": "Medium", "category": "Legacy VPN IKEv1 or Weak DH Group (1/2/5)", "count": len(weak_vpn_med), "details": _preview_names(weak_vpn_med)})
    if mgt_unrestricted:
        findings.append({"severity": "Medium", "category": "Management Interface Unrestricted (Permitted IPs: Any)", "count": 1, "details": "MGT interface has no <permitted-ip> restriction configured."})
    if pwd_comp_disabled:
        findings.append({"severity": "Medium", "category": "Admin Password Complexity Disabled", "count": 1, "details": "deviceconfig system password-complexity is not enabled."})
    if lockout_missing:
        findings.append({"severity": "Info", "category": "Admin Login Lockout Not Configured", "count": 1, "details": "No failed-attempts lockout threshold configured in management settings or auth profiles."})
    if super_local_no_auth:
        findings.append({"severity": "Info", "category": "Local Superuser Without External Auth Profile", "count": len(super_local_no_auth), "details": _preview_names(super_local_no_auth)})
    if disabled_rules:
        findings.append({"severity": "Info", "category": "Disabled Security Rules", "count": len(disabled_rules), "details": _preview_names(disabled_rules)})
    if unused_addrs:
        findings.append({"severity": "Info", "category": "Unused Address Objects (Best-Effort)", "count": len(unused_addrs), "details": _preview_names(unused_addrs)})

    return {
        "findings": findings,
        "high_count": sum(1 for f in findings if f["severity"] == "High"),
        "med_count": sum(1 for f in findings if f["severity"] == "Medium"),
        "info_count": sum(1 for f in findings if f["severity"] == "Info"),
    }


def build_paloalto_security_audit(
    config: PANOSConfig,
    derived: PANOSDerivedViews,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build complete Phase 2 security audit payload for PAN-OS."""
    certificates = inspect_paloalto_certificates(config, now=now)
    exposure = find_paloalto_exposure(config, derived)
    posture = evaluate_paloalto_posture(config, derived)
    hygiene = analyze_paloalto_hygiene(config, now=now)
    quick_audit = run_paloalto_quick_audit(config, hygiene=hygiene)
    vpn_health = build_paloalto_vpn_inspector(config, derived)
    return {
        "vendor": "palo_alto",
        "certificates": certificates,
        "certificate_summary": summarize_certificates(certificates),
        "exposure": exposure,
        "posture": posture,
        "hygiene": hygiene,
        "quick_audit": quick_audit,
        "vpn_health": vpn_health,
    }


def export_paloalto_audit_html(
    config: PANOSConfig,
    derived: PANOSDerivedViews,
    *,
    lifecycle_card: dict[str, Any] | None = None,
    filename: str = "panos-config.xml",
    now: datetime | None = None,
) -> bytes:
    """Render standalone HTML security audit report for a PAN-OS configuration."""
    audit = build_paloalto_security_audit(config, derived, now=now)
    hostname = config.hostname or next((s.hostname for s in config.system_settings if s.hostname), None) or "Palo Alto"
    overview_items = [
        ("Hostname", hostname),
        ("PAN-OS Version", config.detail_version or config.source_version or "-"),
        ("Scopes", str(len(config.scopes))),
        ("Interfaces", str(len(config.interfaces) + len(config.interface_units))),
        ("Security Rules", str(len(config.security_rules))),
        ("IPSec Tunnels", str(len(config.ipsec_tunnels))),
    ]
    return render_security_audit_html(
        vendor_label="Palo Alto PAN-OS",
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
