"""Self-contained HTML / Print-to-PDF Security Audit Report renderer (CSP-safe, no scripts)."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Any


def _e(val: Any) -> str:
    return escape(str(val if val is not None and val != "" else "-"), quote=True)


def _badge_html(text: str, tone: str = "muted") -> str:
    cls = {
        "allow": "b-allow",
        "success": "b-allow",
        "warn": "b-warn",
        "warning": "b-warn",
        "deny": "b-deny",
        "danger": "b-deny",
        "critical": "b-deny",
        "info": "b-info",
    }.get(tone, "b-muted")
    return f'<span class="badge {cls}">{_e(text)}</span>'


def _kv_grid_html(items: list[tuple[str, str]]) -> str:
    cells = "".join(
        f'<div class="kv-box"><div class="kv-lbl">{_e(label)}</div><div class="kv-val">{_e(value)}</div></div>'
        for label, value in items
    )
    return f'<div class="kv-grid">{cells}</div>'


def _table_html(
    columns: list[str],
    rows: list[dict[str, Any]],
    row_tones: list[str] | None = None,
    empty_msg: str = "None",
) -> str:
    if not rows:
        return f'<p class="muted">{_e(empty_msg)}</p>'
    ths = "".join(f"<th>{_e(col)}</th>" for col in columns)
    trs: list[str] = []
    for idx, row in enumerate(rows):
        tone = row_tones[idx] if row_tones and idx < len(row_tones) else ""
        tr_cls = f' class="tr-{_e(tone)}"' if tone else ""
        tds = "".join(f"<td>{_e(row.get(col, '-'))}</td>" for col in columns)
        trs.append(f"<tr{tr_cls}>{tds}</tr>")
    return f"<table><thead><tr>{ths}</tr></thead><tbody>{''.join(trs)}</tbody></table>"


def render_security_audit_html(
    *,
    vendor_label: str,
    hostname: str,
    filename: str,
    overview_items: list[tuple[str, str]],
    lifecycle_card: dict[str, Any] | None,
    posture: dict[str, Any],
    exposure_findings: list[dict[str, Any]],
    certificates: list[dict[str, Any]],
    vpn_inspections: list[dict[str, Any]],
    quick_audit: dict[str, Any],
    hygiene: dict[str, Any],
    generated_at: str | None = None,
) -> bytes:
    """Render a standalone, script-free HTML audit report suitable for browser Print-to-PDF."""
    timestamp = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    exp_crit = sum(1 for f in exposure_findings if f.get("severity") == "critical")
    cert_bad = sum(1 for c in certificates if c.get("status") in ("Expired", "Expiring Soon"))
    vpn_err = sum(1 for v in vpn_inspections if v.get("health") == "critical")
    audit_high = int(quick_audit.get("high_count", 0))
    audit_med = int(quick_audit.get("med_count", 0))
    hyg_counts = hygiene.get("counts") or {}

    lifecycle_rows = (lifecycle_card or {}).get("rows") or []
    lc_table = _table_html(
        ["Property", "Value"],
        [{"Property": r.get("label", "-"), "Value": r.get("value", "-")} for r in lifecycle_rows],
        empty_msg="No lifecycle data available.",
    )

    posture_html = _kv_grid_html(
        [
            ("Internet Connectivity", f"{posture.get('internet', 'Unknown')} — {posture.get('internet_sub', '')}"),
            ("Local Disk & Logging", f"{posture.get('disk', 'Unknown')} — {posture.get('disk_sub', '')}"),
        ]
    )

    exp_rows = [
        {
            "Interface / VIP": f.get("interface", "-"),
            "IP": f.get("ip", "-"),
            "Exposed Services": ", ".join(f.get("display_protocols") or f.get("protocols") or []),
            "Severity": "Critical" if f.get("severity") == "critical" else "Warning",
            "Notes": f.get("note", "-"),
        }
        for f in exposure_findings
    ]
    exp_tones = ["danger" if f.get("severity") == "critical" else "warn" for f in exposure_findings]
    exp_html = _table_html(
        ["Interface / VIP", "IP", "Exposed Services", "Severity", "Notes"],
        exp_rows,
        exp_tones,
        empty_msg="No public management or high-risk VIP exposures detected.",
    )

    cert_flagged = [c for c in certificates if c.get("status") in ("Expired", "Expiring Soon")]
    cert_slice = cert_flagged if cert_flagged else certificates[:25]
    cert_rows = [
        {
            "Name": c.get("name", "-"),
            "Store / Scope": c.get("store", "-"),
            "Common Name": c.get("common_name", "-"),
            "Expires": c.get("expires", "-"),
            "Days Left": str(c.get("days_left", "-")),
            "Status": c.get("status", "-"),
        }
        for c in cert_slice
    ]
    cert_tones = [
        "danger" if c.get("status") == "Expired" else ("warn" if c.get("status") == "Expiring Soon" else "allow")
        for c in cert_slice
    ]
    cert_html = _table_html(
        ["Name", "Store / Scope", "Common Name", "Expires", "Days Left", "Status"],
        cert_rows,
        cert_tones,
        empty_msg="No certificates found in configuration.",
    )

    vpn_rows = []
    vpn_tones = []
    for vpn in vpn_inspections:
        findings = vpn.get("findings") or []
        finding_summary = "; ".join(f"{f.get('code', '')}: {f.get('message', '')}" for f in findings)
        health = str(vpn.get("health", "unknown")).lower()
        vpn_rows.append(
            {
                "Tunnel": vpn.get("name", "-"),
                "Remote Peer": vpn.get("remote_gateway") or "-",
                "Tunnel Intf / Zones": f"{vpn.get('tunnel_interface') or '-'} ({', '.join(vpn.get('zones') or ()) or 'No Zone'})",
                "Routes": str(vpn.get("route_count", 0)),
                "Policies": str(vpn.get("policy_count", 0)),
                "Health": health.upper(),
                "Findings": finding_summary or "All 4 layers verified",
            }
        )
        vpn_tones.append("danger" if health == "critical" else ("warn" if health == "warning" else "allow"))
    vpn_html = _table_html(
        ["Tunnel", "Remote Peer", "Tunnel Intf / Zones", "Routes", "Policies", "Health", "Findings"],
        vpn_rows,
        vpn_tones,
        empty_msg="No IPSec site-to-site tunnels configured.",
    )

    audit_findings = quick_audit.get("findings") or []
    audit_rows = [
        {
            "Severity": f.get("severity", "-"),
            "Category": f.get("category", "-"),
            "Count": str(f.get("count", 0)),
            "Details": f.get("details", "-"),
        }
        for f in audit_findings
    ]
    audit_tones = [
        "danger" if f.get("severity") == "High" else ("warn" if f.get("severity") == "Medium" else "info")
        for f in audit_findings
    ]
    audit_html = _table_html(
        ["Severity", "Category", "Count", "Details"],
        audit_rows,
        audit_tones,
        empty_msg="No quick security audit findings.",
    )

    hyg_issues = hygiene.get("hygiene_issues") or []
    hyg_rows = [
        {
            "Finding": r.get("finding", "-"),
            "Target": r.get("target", "-"),
            "Details": r.get("details", "-"),
            "Severity": r.get("severity", "-"),
        }
        for r in hyg_issues
    ]
    hyg_tones = ["danger" if r.get("tone") == "danger" else "warn" for r in hyg_issues]
    hyg_html = _table_html(
        ["Finding", "Target", "Details", "Severity"],
        hyg_rows,
        hyg_tones,
        empty_msg="No rule or schedule hygiene issues detected.",
    )

    unused_objects = hygiene.get("unused_objects") or []
    unused_rows = [
        {
            "Category": obj.get("category", "-"),
            "Name": obj.get("name", "-"),
            "Scope": obj.get("scope", "-"),
            "Details": obj.get("value", "-"),
        }
        for obj in unused_objects[:100]
    ]
    unused_html = _table_html(
        ["Category", "Name", "Scope", "Details"],
        unused_rows,
        empty_msg="No unreferenced address, service, or NAT objects detected.",
    )

    badges = "".join(
        [
            _badge_html(f"Audit: {audit_high} High / {audit_med} Med", "deny" if audit_high else ("warn" if audit_med else "allow")),
            _badge_html(
                f"Exposure: {len(exposure_findings)} ({exp_crit} Crit)" if exposure_findings else "Exposure: Clean",
                "deny" if exp_crit else ("warn" if exposure_findings else "allow"),
            ),
            _badge_html(
                f"Certs: {cert_bad} Flagged / {len(certificates)}" if certificates else "Certs: 0",
                "warn" if cert_bad else "info",
            ),
            _badge_html(
                f"VPNs: {vpn_err} Critical / {len(vpn_inspections)}" if vpn_inspections else "VPNs: 0",
                "deny" if vpn_err else "allow",
            ),
            _badge_html(f"Unused Objects: {hyg_counts.get('unused', 0)}", "warn" if hyg_counts.get("unused") else "allow"),
        ]
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_e(hostname)} — Firewall Security Audit Report</title>
  <style>
    :root {{ --ink:#0f172a; --muted:#475569; --border:#cbd5e1; --bg:#f8fafc; --card:#ffffff; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; padding:28px; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; color:var(--ink); background:var(--bg); line-height:1.45; }}
    .wrap {{ max-width: 1080px; margin: 0 auto; }}
    .topbar {{ display:flex; justify-content:space-between; align-items:flex-start; gap:16px; background:var(--card); border:1px solid var(--border); border-radius:10px; padding:20px 24px; margin-bottom:18px; }}
    .eyebrow {{ font-size:11px; text-transform:uppercase; letter-spacing:0.08em; color:#2563eb; font-weight:700; }}
    h1 {{ margin:4px 0 6px; font-size:22px; }}
    .sub {{ color:var(--muted); font-size:13px; }}
    .print-hint {{ font-size:12px; color:var(--muted); border:1px solid var(--border); border-radius:7px; padding:7px 12px; background:#f8fafc; white-space:nowrap; }}
    .badges {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }}
    .badge {{ display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:600; }}
    .b-allow {{ background:#dcfce7; color:#166534; }}
    .b-warn {{ background:#fef3c7; color:#92400e; }}
    .b-deny {{ background:#fee2e2; color:#991b1b; }}
    .b-info {{ background:#dbeafe; color:#1e40af; }}
    .b-muted {{ background:#e2e8f0; color:#334155; }}
    .section {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:18px 20px; margin-bottom:16px; page-break-inside:avoid; }}
    h2 {{ margin:0 0 12px; font-size:16px; border-bottom:1px solid #e2e8f0; padding-bottom:6px; }}
    h3 {{ margin:14px 0 8px; font-size:14px; color:var(--ink); }}
    .kv-grid {{ display:grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap:10px; }}
    .kv-box {{ background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:10px 12px; }}
    .kv-lbl {{ font-size:11.5px; color:var(--muted); margin-bottom:2px; }}
    .kv-val {{ font-size:14px; font-weight:600; word-break:break-word; }}
    table {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
    th, td {{ text-align:left; padding:7px 9px; border-bottom:1px solid #e2e8f0; vertical-align:top; word-break:break-word; }}
    th {{ background:#f1f5f9; font-weight:600; color:#334155; }}
    .tr-danger td {{ background:#fef2f2; }}
    .tr-warn td {{ background:#fffbeb; }}
    .tr-allow td {{ background:#f0fdf4; }}
    .tr-info td {{ background:#eff6ff; }}
    .muted {{ color:var(--muted); font-size:13px; margin:4px 0; }}
    @media print {{
      body {{ background:#fff; padding:0; }}
      .print-hint {{ display:none; }}
      .section, .topbar {{ border-color:#cbd5e1; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div>
        <div class="eyebrow">Firewall Migration Tool · Security Audit Report</div>
        <h1>{_e(hostname)} ({_e(vendor_label)})</h1>
        <div class="sub">Source: {_e(filename)} · Generated: {_e(timestamp)}</div>
        <div class="badges">{badges}</div>
      </div>
      <div class="print-hint">Use Browser Print (Ctrl+P) → Save as PDF</div>
    </div>

    <div class="section">
      <h2>1. Device &amp; Configuration Overview</h2>
      {_kv_grid_html(overview_items)}
    </div>

    <div class="section">
      <h2>2. Connectivity &amp; Storage Posture</h2>
      {posture_html}
    </div>

    <div class="section">
      <h2>3. Hardware &amp; Firmware Lifecycle</h2>
      {lc_table}
    </div>

    <div class="section">
      <h2>4. Public Management &amp; VIP Exposure ({len(exposure_findings)})</h2>
      {exp_html}
    </div>

    <div class="section">
      <h2>5. Certificate Expiry Summary ({len(certificates)} total · {cert_bad} flagged)</h2>
      {cert_html}
    </div>

    <div class="section">
      <h2>6. IPSec Site-to-Site VPN Health ({len(vpn_inspections)} tunnels)</h2>
      {vpn_html}
    </div>

    <div class="section">
      <h2>7. Quick Security Audit ({audit_high} High · {audit_med} Med · {int(quick_audit.get('info_count', 0))} Info)</h2>
      {audit_html}
    </div>

    <div class="section">
      <h2>8. Rule Hygiene &amp; Unused Objects ({len(hyg_issues)} rule findings · {hyg_counts.get('unused', 0)} unused objects)</h2>
      {hyg_html}
      <h3>Unused Objects{f' (first 100 of {len(unused_objects)})' if len(unused_objects) > 100 else ''}</h3>
      {unused_html}
    </div>
  </div>
</body>
</html>"""
    return html_doc.encode("utf-8")
