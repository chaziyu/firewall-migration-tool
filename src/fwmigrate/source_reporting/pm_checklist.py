"""Backup-config Preventive Maintenance (PM) Lookup evaluator for FortiGate and Palo Alto."""

from __future__ import annotations

from datetime import date, timedelta
from functools import lru_cache
from io import BytesIO
from typing import Any

from ..vendors.fortigate.derived import DerivedViews
from ..vendors.fortigate.extraction.source_metadata import FortiGateSourceMetadata
from ..vendors.fortigate.model.source import FGConfig
from ..vendors.fortigate.security_audit import (
    evaluate_fortigate_posture,
    find_fortigate_exposure,
)
from ..vendors.fortigate.vpn_inspector import build_fortigate_vpn_inspector
from ..vendors.palo_alto.model.source import PANOSConfig
from ..vendors.palo_alto.security_audit import (
    evaluate_paloalto_posture,
    find_paloalto_exposure,
)
from ..vendors.palo_alto.source_model import PANOSDerivedViews
from .exposure import clean_interface_name
from .lifecycle import evaluate_fortigate_lifecycle, evaluate_paloalto_lifecycle

# FortiOS `set timezone <code>` IDs for GMT+8
_FG_GMT8_CODES: dict[str, str] = {
    "55": "GMT+8 (Beijing, Hong Kong, Urumqi)",
    "56": "GMT+8 (Irkutsk, Ulaan Bataar)",
    "57": "GMT+8 (Kuala Lumpur, Singapore)",
    "58": "GMT+8 (Perth)",
    "59": "GMT+8 (Taipei)",
}

# Common PAN-OS IANA / POSIX timezone strings for GMT+8
_PA_GMT8_TOKENS = (
    "asia/singapore",
    "asia/kuala_lumpur",
    "asia/hong_kong",
    "asia/shanghai",
    "asia/taipei",
    "asia/manila",
    "asia/brunei",
    "asia/macau",
    "asia/kuching",
    "australia/perth",
    "etc/gmt-8",
    "gmt+8",
    "utc+8",
    "+08",
)

PM_LEGEND = [
    {"label": "Pass (green)", "variant": "success"},
    {"label": "Info (blue)", "variant": "info"},
    {"label": "Warn (amber)", "variant": "warn"},
    {"label": "Fail (red)", "variant": "danger"},
]


@lru_cache(maxsize=1)
def _excel_styles() -> dict[str, Any]:
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side

    return {
        "status_fills": {
            "pass": PatternFill("solid", fgColor="E8F8F0"),
            "warn": PatternFill("solid", fgColor="FFF3CD"),
            "fail": PatternFill("solid", fgColor="FDECEA"),
            "info": PatternFill("solid", fgColor="EAF4FB"),
        },
        "status_fonts": {
            "pass": Font(bold=True, color="166534"),
            "warn": Font(bold=True, color="854D0E"),
            "fail": Font(bold=True, color="991B1B"),
            "info": Font(bold=True, color="075985"),
        },
        "title_fill": PatternFill("solid", fgColor="17324D"),
        "title_font": Font(color="FFFFFF", bold=True, size=14),
        "meta_label_font": Font(bold=True, color="334155"),
        "cell_border": Border(bottom=Side(style="hair", color="E2E8F0")),
        "align_center": Alignment(vertical="center"),
        "align_center_wrap": Alignment(vertical="center", wrap_text=True),
        "align_top_wrap": Alignment(vertical="top", wrap_text=True),
    }


def _is_disabled(status: Any) -> bool:
    return str(status or "").strip().lower() in {"disable", "disabled", "down"}


def _is_yes(value: Any) -> bool:
    return str(value or "").strip().lower() in {"yes", "true", "1"}


def _row(
    no: str,
    category: str,
    task: str,
    status: str,
    finding: str,
    guidance: str,
) -> dict[str, str]:
    return {
        "no": no,
        "category": category,
        "task": task,
        "status": status,
        "finding": finding,
        "guidance": guidance,
    }


def _summarize(rows: list[dict[str, str]]) -> dict[str, int]:
    counts = {"pass": 0, "warn": 0, "fail": 0, "info": 0, "total": len(rows)}
    for row in rows:
        key = row["status"].strip().lower()
        if key in counts:
            counts[key] += 1
    return counts


def _fg_allowaccess_ifaces(config: FGConfig, proto: str) -> list[str]:
    """Return active non-zone interfaces whose allowaccess includes `proto`."""
    target = proto.lower()
    out: list[str] = []
    for iface in config.interfaces:
        if str(iface.type or "").strip().lower() == "zone":
            continue
        if _is_disabled(iface.status):
            continue
        tokens = {str(t).strip().lower() for t in (iface.allowaccess or ()) if str(t).strip()}
        if target in tokens:
            name = clean_interface_name(iface.name)
            ip = str(iface.ip or "-").strip()
            out.append(f"{name} ({ip})" if ip and ip != "-" else name)
    return out


def _fg_extract_log_managers(config: FGConfig) -> list[str]:
    """Return enabled remote log targets from typed FortiAnalyzer, FortiCloud, and Syslog models."""
    targets: list[str] = []
    faz_labels = {
        "fortianalyzer": "FortiAnalyzer",
        "fortianalyzer2": "FortiAnalyzer 2",
        "fortianalyzer3": "FortiAnalyzer 3",
    }
    for faz in config.fortianalyzer_settings:
        if _is_disabled(faz.status):
            continue
        enabled = str(faz.status or "").strip().lower() == "enable"
        server = str(faz.server or "").strip()
        if enabled or server:
            label = faz_labels.get(faz.target_name, "FortiAnalyzer")
            targets.append(f"{label} ({server})" if server else label)

    for fg_log in config.log_fortiguard_settings:
        if _is_disabled(fg_log.status):
            continue
        if str(fg_log.status or "").strip().lower() == "enable":
            targets.append("FortiCloud")

    syslog_labels = {
        "syslogd": "Syslog",
        "syslogd2": "Syslog 2",
        "syslogd3": "Syslog 3",
        "syslogd4": "Syslog 4",
    }
    for sys_log in config.syslog_settings:
        if _is_disabled(sys_log.status):
            continue
        enabled = str(sys_log.status or "").strip().lower() == "enable"
        server = str(sys_log.server or "").strip()
        if enabled or server:
            label = syslog_labels.get(sys_log.syslog_name, "Syslog")
            targets.append(f"{label} ({server})" if server else label)

    return targets


def _fg_mgmt_exposures(exposure: list[dict[str, Any]], proto: str) -> list[dict[str, Any]]:
    return [
        finding
        for finding in exposure
        if not str(finding.get("interface", "")).startswith("VIP:")
        and proto in (finding.get("protocols") or ())
    ]


def evaluate_fortigate_pm_checklist(
    config: FGConfig,
    derived: DerivedViews,
    *,
    metadata: FortiGateSourceMetadata | None = None,
    lifecycle: dict[str, Any] | None = None,
    posture: dict[str, str] | None = None,
    exposure: list[dict[str, Any]] | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate the 15 config-verifiable Preventive Maintenance checks for FortiGate."""
    global_cfg = config.system_global[0] if config.system_global else None
    hostname = str((global_cfg.hostname if global_cfg else None) or "Unknown")
    serial = str((metadata.serial_number if metadata else None) or "Unknown")
    model = str((metadata.hardware_model if metadata else None) or "Unknown")
    firmware = str((metadata.fortios_version if metadata else None) or "Unknown")

    lc = lifecycle or evaluate_fortigate_lifecycle(
        model,
        firmware,
        serial_raw=serial if serial != "Unknown" else None,
        cache_only=True,
        today=today,
    )
    pos = posture or evaluate_fortigate_posture(config, metadata=metadata)
    exp = exposure if exposure is not None else find_fortigate_exposure(config)
    vpn_tunnels = build_fortigate_vpn_inspector(config, derived)

    rows: list[dict[str, str]] = []

    # 1.1 Hard Disk Space
    disk_val = pos.get("disk", "Unknown")
    disk_sub = pos.get("disk_sub", "")
    disk_status = "Pass" if disk_val.startswith("Yes") else "Info"
    rows.append(
        _row(
            "1.1",
            "Hardware Status",
            "Hard Disk Space",
            disk_status,
            f"{disk_val} — {disk_sub}" if disk_sub else disk_val,
            "Verify live disk usage < 80% in Log & Report > Log Settings > Local Logs."
            if disk_status == "Pass"
            else "Diskless/memory-only model; confirm remote log manager (FAZ/FortiCloud/Syslog) is active.",
        )
    )

    # 1.4 Interface Monitoring
    non_zones = [
        iface for iface in config.interfaces
        if str(iface.type or "").strip().lower() != "zone"
    ]
    enabled_if = [iface for iface in non_zones if not _is_disabled(iface.status)]
    disabled_if = len(non_zones) - len(enabled_if)
    vlans = sum(
        1
        for iface in non_zones
        if iface.vlanid is not None or "vlan" in str(iface.type or "").lower()
    )
    rows.append(
        _row(
            "1.4",
            "Hardware Status",
            "Interface Monitoring",
            "Pass" if enabled_if else "Warn",
            f"{len(enabled_if)} enabled, {disabled_if} disabled, {vlans} VLAN/sub-interfaces ({len(non_zones)} total).",
            "Confirm physical link state and port utilization in Network > Interfaces.",
        )
    )

    # 3.1 Firewall Firmware Version
    fw_ver = str(lc.get("firmware_version") or firmware)
    fw_branch = str(lc.get("firmware_branch") or "Unknown")
    latest_in_branch = lc.get("latest_in_branch")
    branch_status = str(lc.get("branch_status") or "unknown")
    patch_status = str(lc.get("patch_status") or "unknown")
    if branch_status == "eos":
        fw_status = "Fail"
        fw_finding = f"FortiOS {fw_ver} (Branch {fw_branch} is End-of-Support)."
        fw_guide = "Plan upgrade to a supported FortiOS branch following the Fortinet upgrade path."
    elif patch_status == "update_available" and latest_in_branch:
        fw_status = "Warn"
        fw_finding = f"FortiOS {fw_ver} (latest in {fw_branch} branch is {latest_in_branch})."
        fw_guide = f"Review release notes and schedule patch upgrade to {latest_in_branch}."
    elif branch_status == "supported":
        fw_status = "Pass"
        fw_finding = f"FortiOS {fw_ver} (Branch {fw_branch} supported" + (
            f", up to date with {latest_in_branch})." if latest_in_branch else ")."
        )
        fw_guide = "Installed firmware is on a supported branch."
    else:
        fw_status = "Info"
        fw_finding = f"FortiOS {fw_ver} (lifecycle metadata unavailable)."
        fw_guide = "Verify recommended FortiOS release on Fortinet Support Portal."
    rows.append(_row("3.1", "Product Life Cycle", "Firewall Firmware Version", fw_status, fw_finding, fw_guide))

    # 3.2 Final Firmware Release (FFR)
    last_sup = str(lc.get("last_supported_firmware") or "Unknown")
    capped_eos = bool(lc.get("last_supported_capped_eos"))
    model_disp = str(lc.get("model_display") or model)
    if last_sup.lower() == "unknown":
        ffr_status = "Info"
        ffr_finding = f"Model {model_disp} — FFR not listed in offline catalog."
        ffr_guide = "Check Last Supported Firmware at support.fortinet.com/welcome/#/lifecycle."
    elif capped_eos:
        ffr_status = "Fail"
        ffr_finding = f"Model {model_disp} capped at {last_sup} (EOS branch)."
        ffr_guide = "Hardware can no longer run a supported FortiOS branch; plan hardware refresh."
    elif last_sup.lower() == "active":
        ffr_status = "Pass"
        ffr_finding = f"Model {model_disp} — Active (no Final Firmware Release cap announced)."
        ffr_guide = "No FFR restriction."
    else:
        ffr_status = "Warn"
        ffr_finding = f"Model {model_disp} — Final Firmware Release: {last_sup}."
        ffr_guide = f"Track lifecycle; hardware will not upgrade beyond {last_sup}."
    rows.append(_row("3.2", "Product Life Cycle", "Final Firmware Release (FFR)", ffr_status, ffr_finding, ffr_guide))

    # 3.3 End of Support (EOS)
    hw_status = str(lc.get("hw_status") or "unknown")
    hw_eos = lc.get("hw_eos") or "Not announced / Unknown"
    branch_eos = lc.get("branch_eos") or "Unknown"
    if hw_status == "eos" or branch_status == "eos":
        eos_status = "Fail"
    elif hw_status == "eos_soon" or branch_status == "eoes":
        eos_status = "Warn"
    elif hw_status in ("supported", "active") or branch_status == "supported":
        eos_status = "Pass"
    else:
        eos_status = "Info"
    rows.append(
        _row(
            "3.3",
            "Product Life Cycle",
            "End of Support (EOS)",
            eos_status,
            f"Hardware EoS: {hw_eos} · FortiOS {fw_branch} EoS: {branch_eos}.",
            "Plan hardware/firmware replacement before EoS."
            if eos_status in ("Fail", "Warn")
            else "Within active support lifecycle.",
        )
    )

    # 4.1 VPN Tunnels
    if not vpn_tunnels:
        vpn_status = "Info"
        vpn_finding = "No IPSec site-to-site tunnels configured."
        vpn_guide = "N/A unless VPN tunnels are expected."
    else:
        vpn_issues = sum(
            1
            for tunnel in vpn_tunnels
            if str(tunnel.get("health", "")).lower() in {"error", "fail", "critical", "warn", "warning"}
        )
        vpn_status = "Warn" if vpn_issues else "Pass"
        vpn_finding = f"{len(vpn_tunnels)} IPSec tunnel(s) configured" + (
            f" ({vpn_issues} with config/health warnings)." if vpn_issues else " (no config issues detected)."
        )
        vpn_guide = "Verify live tunnel up/down stats via CLI: get vpn ipsec tunnel summary."
    rows.append(_row("4.1", "VPN", "VPN Tunnels", vpn_status, vpn_finding, vpn_guide))

    # 5.1 Firewall Routing Table
    active_routes = [r for r in config.static_routes if not _is_disabled(r.status)]
    has_default = any(
        str(r.dst or "").strip() in {"0.0.0.0/0", "0.0.0.0 0.0.0.0", "::/0"}
        or (not r.dst and not r.dstaddr and bool(r.sdwan_zone))
        for r in active_routes
    )
    sdwan_members = sum(len(s.members or ()) for s in config.sdwans)
    extras: list[str] = []
    if sdwan_members:
        extras.append(f"SD-WAN ({sdwan_members} members)")
    if config.policy_routes:
        extras.append(f"{len(config.policy_routes)} policy route(s)")
    if any(b.bgp_as or b.neighbors for b in config.router_bgp):
        extras.append("BGP")
    if any(o.router_id or o.areas for o in config.router_ospf):
        extras.append("OSPF")
    rt_finding = (
        f"{len(active_routes)} active static route(s) ({len(config.static_routes) - len(active_routes)} disabled), "
        f"default route: {'Yes' if has_default else 'No'}."
    )
    if extras:
        rt_finding += " Also: " + ", ".join(extras) + "."
    rows.append(
        _row(
            "5.1",
            "Routing Table",
            "Firewall Routing Table",
            "Pass" if (active_routes or extras) else "Warn",
            rt_finding,
            "Review active routing table and gateway reachability in Network > Static Routes.",
        )
    )

    # 6.2 GUI Accessibility
    https_port = str(global_cfg.admin_sport if global_cfg and global_cfg.admin_sport else 443)
    http_port = str(global_cfg.admin_port if global_cfg and global_cfg.admin_port else 80)
    https_ifs = _fg_allowaccess_ifaces(config, "https")
    http_ifs = _fg_allowaccess_ifaces(config, "http")
    pub_gui = _fg_mgmt_exposures(exp, "HTTP") + _fg_mgmt_exposures(exp, "HTTPS")
    if any(f.get("severity") == "critical" for f in pub_gui):
        gui_status = "Fail"
        gui_guide = (
            "Restrict public GUI access with admin trusthosts or move management behind VPN/internal interface; disable HTTP."
        )
    elif pub_gui or http_ifs:
        gui_status = "Warn"
        gui_guide = "Prefer HTTPS-only management and restrict public interfaces with trusthosts."
    elif https_ifs:
        gui_status = "Pass"
        gui_guide = "Verify live web GUI login on management interface."
    else:
        gui_status = "Info"
        gui_guide = "No interface explicitly lists HTTPS allowaccess; verify GUI access method."
    gui_parts = [f"Ports: HTTPS {https_port} / HTTP {http_port}"]
    if https_ifs:
        gui_parts.append(f"HTTPS on {', '.join(https_ifs[:4])}")
    if http_ifs:
        gui_parts.append(f"HTTP on {', '.join(http_ifs[:4])}")
    rows.append(_row("6.2", "Configuration", "GUI Accessibility", gui_status, "; ".join(gui_parts) + ".", gui_guide))

    # 6.3 CLI/SSH Accessibility
    ssh_port = str(global_cfg.admin_ssh_port if global_cfg and global_cfg.admin_ssh_port else 22)
    ssh_ifs = _fg_allowaccess_ifaces(config, "ssh")
    pub_ssh = _fg_mgmt_exposures(exp, "SSH")
    if any(f.get("severity") == "critical" for f in pub_ssh):
        ssh_status = "Fail"
        ssh_guide = "Restrict public SSH access with admin trusthosts or disable SSH on WAN."
    elif pub_ssh:
        ssh_status = "Warn"
        ssh_guide = "SSH is on a public interface (trusthost restricted); verify authorized IPs."
    elif ssh_ifs:
        ssh_status = "Pass"
        ssh_guide = "Verify CLI/SSH login (`get system status`)."
    else:
        ssh_status = "Info"
        ssh_guide = "SSH allowaccess not explicitly enabled on any interface (use GUI CLI console if needed)."
    ssh_finding = (
        f"SSH port {ssh_port}; enabled on {', '.join(ssh_ifs[:4])}."
        if ssh_ifs
        else f"SSH port {ssh_port}; not enabled on any interface."
    )
    rows.append(_row("6.3", "Configuration", "CLI/SSH Accessibility", ssh_status, ssh_finding, ssh_guide))

    # 6.5 Firewall Date & Time (GMT+8 + NTP)
    tz_code = str((global_cfg.timezone if global_cfg and global_cfg.timezone else None) or "-").strip()
    ntp_cfg = config.system_ntp[0] if config.system_ntp else None
    ntp_enabled = bool(ntp_cfg) and str(ntp_cfg.ntpsync or "enable").strip().lower() != "disable"
    ntp_server_list = [s.server for s in (ntp_cfg.ntpservers if ntp_cfg else ()) if s.server]
    if ntp_cfg and str(ntp_cfg.type or "").strip().lower() == "fortiguard" and not ntp_server_list:
        ntp_server_list = ["FortiGuard"]
    ntp_servers = ", ".join(ntp_server_list) if ntp_server_list else "Not configured"
    is_gmt8 = tz_code in _FG_GMT8_CODES
    tz_label = _FG_GMT8_CODES.get(tz_code, f"Code {tz_code}" if tz_code != "-" else "Not explicitly set (default)")
    if is_gmt8 and ntp_enabled:
        dt_status = "Pass"
        dt_guide = "Timezone is GMT+8 and NTP sync is enabled."
    elif not ntp_enabled and not is_gmt8:
        dt_status = "Warn"
        dt_guide = "Set timezone to GMT+8 (e.g. code 57 Kuala Lumpur/Singapore) and enable NTP sync."
    elif not is_gmt8:
        dt_status = "Warn"
        dt_guide = "Confirm timezone matches GMT+8 requirement in System > Settings."
    else:
        dt_status = "Warn"
        dt_guide = "Enable NTP synchronization in System > Settings (`config system ntp`)."
    rows.append(
        _row(
            "6.5",
            "Configuration",
            "Firewall Date & Time",
            dt_status,
            f"Timezone: {tz_label} · NTP: {'Enabled' if ntp_enabled else 'Disabled/Default'} ({ntp_servers}).",
            dt_guide,
        )
    )

    # 6.6 Firewall Internet Access
    inet_val = pos.get("internet", "Unknown")
    inet_sub = pos.get("internet_sub", "")
    inet_status = "Pass" if inet_val.startswith("Connected") else "Info"
    rows.append(
        _row(
            "6.6",
            "Configuration",
            "Firewall Internet Access",
            inet_status,
            f"{inet_val} ({inet_sub})." if inet_sub else inet_val,
            "Matches expected connectivity posture."
            if inet_status == "Pass"
            else "Config indicates internal/air-gapped posture; confirm against site design.",
        )
    )

    # 6.7 High Availability
    ha = config.ha_config[0] if config.ha_config else None
    ha_enabled = bool(ha and ha.mode and str(ha.mode).strip().lower() != "standalone")
    if ha_enabled and ha is not None:
        hb = ha.hbdev or ", ".join(ha.monitor or ()) or "—"
        ha_status = "Pass"
        ha_finding = (
            f"HA Enabled ({ha.mode or 'Cluster'}, group '{ha.group_name or '—'}', "
            f"priority {ha.priority if ha.priority is not None else '—'}, heartbeat: {hb})."
        )
        ha_guide = "Verify HA cluster sync status and secondary member health in System > HA."
    else:
        ha_status = "Info"
        ha_finding = "Standalone mode (HA not configured)."
        ha_guide = "No HA cluster configured; skip HA sync check."
    rows.append(_row("6.7", "Configuration", "High Availability", ha_status, ha_finding, ha_guide))

    # 6.8 Logging (Event Log)
    mem_enabled = any(str(m.status or "").strip().lower() == "enable" for m in config.log_memory_settings)
    local_log_on = disk_val.startswith("Yes") or mem_enabled
    implicit_log = (config.log_settings[0].fwpolicy_implicit_log if config.log_settings else None) or "-"
    rows.append(
        _row(
            "6.8",
            "Configuration",
            "Logging (Event Log)",
            "Pass" if local_log_on else "Warn",
            f"Local storage: {disk_val}. Implicit policy log: {implicit_log}.",
            "Review critical errors/warnings from past 3 months in Log & Report > System Events.",
        )
    )

    # 6.9 Log Manager
    log_mgrs = _fg_extract_log_managers(config)
    rows.append(
        _row(
            "6.9",
            "Configuration",
            "Log Manager",
            "Pass" if log_mgrs else "Warn",
            "Configured: " + ", ".join(log_mgrs) + "."
            if log_mgrs
            else "No FortiAnalyzer, FortiCloud, or Syslog server enabled.",
            "Confirm log transmission status in Log & Report > Log Settings."
            if log_mgrs
            else "Configure FortiAnalyzer, FortiCloud, or Syslog for centralized log retention.",
        )
    )

    # 6.10 Backup Configurations
    rows.append(
        _row(
            "6.10",
            "Configuration",
            "Backup Configurations",
            "Pass",
            f"Valid FortiOS backup parsed — Hostname: {hostname}, Model: {model_disp}, S/N: {serial}, Firmware: {firmware}.",
            "Archive this sanitized backup snapshot per change-management policy.",
        )
    )

    return {
        "vendor": "fortigate",
        "vendor_label": "FortiGate",
        "hostname": hostname,
        "subtitle": f"{model_disp} · FortiOS {firmware} · S/N {serial}",
        "rows": rows,
        "summary": _summarize(rows),
        "legend": PM_LEGEND,
    }


def _pa_extract_ntp_servers(ntp_servers: dict[str, Any] | None) -> tuple[str, str]:
    if not isinstance(ntp_servers, dict):
        return "-", "-"

    def _addr(key: str) -> str:
        node = ntp_servers.get(key)
        if isinstance(node, dict):
            return str(node.get("ntp-server-address") or node.get("address") or "-").strip() or "-"
        if isinstance(node, str) and node.strip():
            return node.strip()
        return "-"

    return _addr("primary-ntp-server"), _addr("secondary-ntp-server")


def evaluate_paloalto_pm_checklist(
    config: PANOSConfig,
    derived: PANOSDerivedViews,
    *,
    lifecycle: dict[str, Any] | None = None,
    posture: dict[str, str] | None = None,
    exposure: list[dict[str, Any]] | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Evaluate the 10 config-verifiable Preventive Maintenance checks for Palo Alto."""
    sys_cfg = config.system_settings[0] if config.system_settings else None
    ha = config.ha_configs[0] if config.ha_configs else None
    hostname = str((sys_cfg.hostname if sys_cfg and sys_cfg.hostname else config.hostname) or "Unknown")
    sw_version = str(config.detail_version or config.source_version or "Unknown")
    timezone = str((sys_cfg.timezone if sys_cfg and sys_cfg.timezone else None) or "-")

    ref_today = today or date.today()
    lc = lifecycle or evaluate_paloalto_lifecycle(
        sw_version,
        is_exact_version=bool(config.detail_version),
        cache_only=True,
        today=ref_today,
    )
    pos = posture or evaluate_paloalto_posture(config, derived)
    exp = exposure if exposure is not None else find_paloalto_exposure(config, derived)

    rows: list[dict[str, str]] = []

    # 1.1 Hard Disk Space
    disk_sub = pos.get("disk_sub", "")
    rows.append(
        _row(
            "1.1",
            "Hardware Status",
            "Hard Disk Space",
            "Pass",
            f"{pos.get('disk', 'Yes (PAN-OS Local Disk)')} — {disk_sub}" if disk_sub else pos.get("disk", "Yes (PAN-OS Local Disk)"),
            "Verify all disk partitions < 90% via CLI: show system disk-space.",
        )
    )

    # 1.4 Firewall Port Monitoring
    eth_ifs = [i for i in config.interfaces if i.interface_family == "ethernet"]
    ae_ifs = [i for i in config.interfaces if i.interface_family == "aggregate-ethernet"]
    active_eth = [i for i in eth_ifs if str(i.link_state or "").strip().lower() != "down"]
    rows.append(
        _row(
            "1.4",
            "Hardware Status",
            "Firewall Port Monitoring",
            "Pass" if active_eth else "Warn",
            (
                f"{len(active_eth)} active Ethernet interface(s) ({len(eth_ifs) - len(active_eth)} disabled), "
                f"{len(ae_ifs)} AE interface(s), {len(config.zones)} zone(s)."
            ),
            "Verify physical link state in Network > Interfaces > Ethernet.",
        )
    )

    # 4.2 GUI Accessibility
    mgmt_ip = str((sys_cfg.ip_address if sys_cfg and sys_cfg.ip_address else None) or "Not configured")
    permitted_list = [p for p in (sys_cfg.permitted_ip or () if sys_cfg else ()) if p]
    permitted = ", ".join(permitted_list) if permitted_list else "Any (Unrestricted)"
    service = (sys_cfg.service if sys_cfg else None) or {}
    https_on = not _is_yes(service.get("disable-https"))
    http_on = not _is_yes(service.get("disable-http"))
    pub_gui = [f for f in exp if any(p in ("HTTP", "HTTPS") for p in (f.get("protocols") or ()))]
    if any(f.get("severity") == "critical" for f in pub_gui):
        gui_status = "Fail"
        gui_guide = "Restrict public management GUI with permitted-ip and disable HTTP."
    elif http_on or pub_gui or permitted.startswith("Any"):
        gui_status = "Warn"
        gui_guide = "Disable HTTP if enabled and configure Permitted IP Addresses on management interface."
    elif https_on:
        gui_status = "Pass"
        gui_guide = "HTTPS enabled with Permitted IPs restricted; verify live web login."
    else:
        gui_status = "Info"
        gui_guide = "HTTPS is disabled on management interface; verify GUI access path."
    rows.append(
        _row(
            "4.2",
            "Configuration",
            "GUI Accessibility",
            gui_status,
            f"Mgmt IP: {mgmt_ip} · HTTPS: {'Enabled' if https_on else 'Disabled'}, HTTP: {'Enabled' if http_on else 'Disabled'} · Permitted IPs: {permitted}.",
            gui_guide,
        )
    )

    # 4.3 CLI/SSH Accessibility
    ssh_on = not _is_yes(service.get("disable-ssh"))
    pub_ssh = [f for f in exp if "SSH" in (f.get("protocols") or ())]
    if any(f.get("severity") == "critical" for f in pub_ssh):
        ssh_status = "Fail"
        ssh_guide = "Restrict public SSH management with permitted-ip."
    elif pub_ssh or (ssh_on and permitted.startswith("Any")):
        ssh_status = "Warn"
        ssh_guide = "Configure Permitted IP Addresses on management interface to limit SSH exposure."
    elif ssh_on:
        ssh_status = "Pass"
        ssh_guide = "SSH enabled with Permitted IPs restricted; verify SSH login."
    else:
        ssh_status = "Info"
        ssh_guide = "SSH is disabled on management interface."
    rows.append(
        _row(
            "4.3",
            "Configuration",
            "CLI/SSH Accessibility",
            ssh_status,
            f"SSH: {'Enabled' if ssh_on else 'Disabled'} on {mgmt_ip} · Permitted IPs: {permitted}.",
            ssh_guide,
        )
    )

    # 4.4 Firewall Firmware Version
    pa_branch = str(lc.get("panos_branch") or "Unknown")
    branch_status = str(lc.get("branch_status") or "unknown")
    patch_status = str(lc.get("patch_status") or "unknown")
    latest_in_branch = lc.get("latest_in_branch")
    branch_eos = lc.get("branch_eos") or "Unknown"
    if branch_status == "eos":
        fw_status = "Fail"
        fw_finding = f"PAN-OS {sw_version} (Branch {pa_branch} reached EOL on {branch_eos})."
        fw_guide = "Plan upgrade to a supported PAN-OS release."
    elif patch_status == "update_available" and latest_in_branch:
        fw_status = "Warn"
        fw_finding = f"PAN-OS {sw_version} (Branch {pa_branch} EoS: {branch_eos}; latest: {latest_in_branch})."
        fw_guide = f"Check Preferred release in Device > Software (latest in branch: {latest_in_branch})."
    elif branch_status == "supported":
        fw_status = "Pass"
        fw_finding = f"PAN-OS {sw_version} (Branch {pa_branch} supported until {branch_eos})."
        fw_guide = "Confirm preferred release via `request system software info preferred`."
    else:
        fw_status = "Info"
        fw_finding = f"PAN-OS {sw_version} (lifecycle metadata unavailable)."
        fw_guide = "Verify PAN-OS version & preferred release in Device > Software."
    rows.append(_row("4.4", "Configuration", "Firewall Firmware Version", fw_status, fw_finding, fw_guide))

    # 4.5 Firewall Date & Time (GMT+8 + NTP)
    p_ntp, s_ntp = _pa_extract_ntp_servers(sys_cfg.ntp_servers if sys_cfg else None)
    has_ntp = (p_ntp not in ("", "-")) or (s_ntp not in ("", "-"))
    is_gmt8 = any(tok in timezone.lower() for tok in _PA_GMT8_TOKENS)
    if is_gmt8 and has_ntp:
        dt_status = "Pass"
        dt_guide = "Timezone is GMT+8 and NTP server(s) configured; verify live sync with `show ntp`."
    elif not has_ntp:
        dt_status = "Warn"
        dt_guide = "Configure primary/secondary NTP servers and confirm GMT+8 timezone (`show clock` / `show ntp`)."
    else:
        dt_status = "Warn"
        dt_guide = "Confirm timezone matches GMT+8 requirement (`show clock`)."
    ntp_txt = ", ".join(x for x in (p_ntp, s_ntp) if x and x != "-") or "Not configured"
    rows.append(
        _row(
            "4.5",
            "Configuration",
            "Firewall Date & Time",
            dt_status,
            f"Timezone: {timezone} · NTP Servers: {ntp_txt}.",
            dt_guide,
        )
    )

    # 4.6 Firewall Internet Access
    inet_val = pos.get("internet", "Unknown")
    inet_sub = pos.get("internet_sub", "")
    inet_status = "Pass" if inet_val.startswith("Connected") else "Info"
    rows.append(
        _row(
            "4.6",
            "Configuration",
            "Firewall Internet Access",
            inet_status,
            f"{inet_val} ({inet_sub})." if inet_sub else inet_val,
            "Verify external connectivity via CLI: ping host 8.8.8.8.",
        )
    )

    # 4.7 High Availability
    if ha is not None and _is_yes(ha.enabled):
        group = ha.group if isinstance(ha.group, dict) else {}
        mode_map = group.get("mode") if isinstance(group.get("mode"), dict) else (ha.mode if isinstance(ha.mode, dict) else {})
        mode_lbl = "Active-Active" if "active-active" in mode_map else "Active-Passive"
        group_id = group.get("group-id") or "—"
        peer_ip = group.get("peer-ip") or "—"
        iface_map = ha.interface if isinstance(ha.interface, dict) else {}
        ha1 = iface_map.get("ha1") if isinstance(iface_map.get("ha1"), dict) else {}
        ha1_port = ha1.get("port") or "—"
        ha_status = "Pass"
        ha_finding = f"HA Enabled ({mode_lbl}, Group {group_id}, Peer {peer_ip}, HA1 {ha1_port})."
        ha_guide = "Verify HA peer state and config sync in Main Dashboard > HA."
    else:
        ha_status = "Info"
        ha_finding = "Standalone mode (HA not configured)."
        ha_guide = "No HA configured; skip HA sync check."
    rows.append(_row("4.7", "Configuration", "High Availability (if any)", ha_status, ha_finding, ha_guide))

    # 4.8 Event Logging (+ dynamic 3-month PAN-OS log filter)
    three_months_ago = (ref_today - timedelta(days=90)).strftime("%Y/%m/%d")
    pa_filter = (
        f"(receive_time geq '{three_months_ago} 00:00:00') and "
        "((severity eq critical) or (severity eq high) or (severity eq medium))"
    )
    syslog_count = len(config.syslog_server_profiles)
    log_fwd_count = len(config.log_forwarding_profiles)
    rows.append(
        _row(
            "4.8",
            "Configuration",
            "Event Logging",
            "Pass" if (syslog_count or log_fwd_count) else "Info",
            f"{syslog_count} Syslog profile(s), {log_fwd_count} Log Forwarding profile(s).",
            f"Monitor > Logs > System filter (past 90 days): {pa_filter}",
        )
    )

    # 4.9 Backup Configurations
    rows.append(
        _row(
            "4.9",
            "Configuration",
            "Backup Configurations",
            "Pass",
            f"Valid PAN-OS XML backup parsed — Hostname: {hostname}, PAN-OS: {sw_version}.",
            "Archive this backup snapshot per change-management policy.",
        )
    )

    return {
        "vendor": "palo_alto",
        "vendor_label": "Palo Alto",
        "hostname": hostname,
        "subtitle": f"PAN-OS {sw_version} · {timezone}",
        "rows": rows,
        "summary": _summarize(rows),
        "legend": PM_LEGEND,
    }


def export_pm_checklist_excel(result: dict[str, Any]) -> bytes:
    """Render a PM Lookup evaluation result to a formatted single-sheet Excel workbook."""
    from openpyxl import Workbook

    from .excel_style import excel_safe_value, style_report_header

    styles = _excel_styles()
    wb = Workbook()
    ws = wb.active
    ws.title = "PM Lookup"
    ws.sheet_view.showGridLines = True
    ws.sheet_view.zoomScale = 90

    widths = (10, 22, 30, 12, 54, 54)
    for idx, width in enumerate(widths, start=1):
        col_letter = chr(ord("A") + idx - 1)
        ws.column_dimensions[col_letter].width = width

    ws.merge_cells("A1:F1")
    title_cell = ws.cell(1, 1, excel_safe_value(f"{result['vendor_label']} Preventive Maintenance (PM) Lookup"))
    title_cell.fill = styles["title_fill"]
    title_cell.font = styles["title_font"]
    title_cell.alignment = styles["align_center"]
    ws.row_dimensions[1].height = 28

    summary = result["summary"]
    meta_rows = [
        ("Hostname", result["hostname"], "Summary", result["subtitle"]),
        (
            "Checks",
            f"{summary['total']} total",
            "Status Breakdown",
            f"Pass: {summary['pass']} · Warn: {summary['warn']} · Fail: {summary['fail']} · Info: {summary['info']}",
        ),
    ]
    for r_idx, (k1, v1, k2, v2) in enumerate(meta_rows, start=2):
        c1 = ws.cell(r_idx, 1, excel_safe_value(k1))
        c2 = ws.cell(r_idx, 2, excel_safe_value(v1))
        c3 = ws.cell(r_idx, 3, excel_safe_value(k2))
        ws.merge_cells(start_row=r_idx, start_column=4, end_row=r_idx, end_column=6)
        c4 = ws.cell(r_idx, 4, excel_safe_value(v2))
        c1.font = styles["meta_label_font"]
        c3.font = styles["meta_label_font"]
        for cell in (c1, c2, c3, c4):
            cell.alignment = styles["align_center_wrap"]
            cell.border = styles["cell_border"]
        ws.row_dimensions[r_idx].height = 20

    header_row = 5
    headers = ("No.", "Category", "Task", "Status", "Config Finding", "Recommendation / Follow-up")
    ws.row_dimensions[header_row].height = 26
    for col_idx, header in enumerate(headers, start=1):
        cell = ws.cell(header_row, col_idx, header)
        style_report_header(cell)

    for offset, row in enumerate(result["rows"], start=1):
        r_idx = header_row + offset
        values = (
            row["no"],
            row["category"],
            row["task"],
            row["status"],
            row["finding"],
            row["guidance"],
        )
        status_key = row["status"].strip().lower()
        status_fill = styles["status_fills"].get(status_key)
        status_font = styles["status_fonts"].get(status_key)
        for col_idx, val in enumerate(values, start=1):
            cell = ws.cell(r_idx, col_idx, excel_safe_value(val))
            cell.alignment = styles["align_top_wrap"]
            cell.border = styles["cell_border"]
            if col_idx == 4 and status_fill is not None and status_font is not None:
                cell.fill = status_fill
                cell.font = status_font
        ws.row_dimensions[r_idx].height = 34

    ws.freeze_panes = f"A{header_row + 1}"
    ws.auto_filter.ref = f"A{header_row}:F{header_row + len(result['rows'])}"

    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()
