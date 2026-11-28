"""FortiGate SSL-VPN -> Dial-up IPSec (IKEv2) Migration Assistant.

Read-only analyzer built over typed ``FGConfig`` and ``FortiGateSourceMetadata``.
Audits existing SSL-VPN settings, portals, certificates, user groups, and
``ssl.*`` policies to produce readiness checks, GUI/Wizard quick-reference
parameters, draft Phase 1 / Phase 2 / Policy CLI, and cutover checklists.
"""

from __future__ import annotations

from typing import Any

from .model.policy import FGPolicy
from .model.source import FGConfig

_UTM_PROFILE_ATTRS: tuple[tuple[str, str, bool], ...] = (
    ("utm_status", "utm-status", False),
    ("profile_protocol_options", "profile-protocol-options", True),
    ("ssl_ssh_profile", "ssl-ssh-profile", True),
    ("av_profile", "av-profile", True),
    ("webfilter_profile", "webfilter-profile", True),
    ("dnsfilter_profile", "dnsfilter-profile", True),
    ("ips_sensor", "ips-sensor", True),
    ("application_list", "application-list", True),
    ("file_filter_profile", "file-filter-profile", True),
    ("emailfilter_profile", "emailfilter-profile", True),
    ("waf_profile", "waf-profile", True),
    ("profile_group", "profile-group", True),
)


def _norm_vdom(vdom: str | None) -> str:
    cleaned = (vdom or "root").strip()
    return cleaned or "root"


def _is_ssl_interface(name: str) -> bool:
    return name.strip().lower().startswith("ssl.")


def _policy_has_ssl_src(policy: FGPolicy) -> bool:
    return any(_is_ssl_interface(intf) for intf in (policy.srcintf or ()))


def _quote_cli_value(value: str) -> str:
    safe = value.replace('"', '\\"')
    return f'"{safe}"'


def _quote_list(items: list[str] | tuple[str, ...] | None) -> str:
    if not items:
        return ""
    return " ".join(_quote_cli_value(x) for x in items if x and x != "-")


def _append_unique(target: list[str], items: list[str] | tuple[str, ...] | None) -> None:
    if not items:
        return
    for item in items:
        val = str(item).strip()
        if val and val != "-" and val not in target:
            target.append(val)


def _ordered_vdoms(config: FGConfig) -> list[str]:
    seen: list[str] = []
    for item in config.ssl_vpn_settings:
        v = _norm_vdom(item.vdom)
        if v not in seen:
            seen.append(v)
    for portal in config.ssl_vpn_portals:
        v = _norm_vdom(portal.vdom)
        if v not in seen:
            seen.append(v)
    for pol in config.policies:
        if _policy_has_ssl_src(pol):
            v = _norm_vdom(pol.vdom)
            if v not in seen:
                seen.append(v)
    if "root" in seen:
        others = sorted(v for v in seen if v != "root")
        return ["root", *others]
    return sorted(seen)


def _policy_profile_lines(pol: FGPolicy) -> tuple[list[str], list[str]]:
    cli_lines: list[str] = []
    labels: list[str] = []
    for attr, cli_key, quoted in _UTM_PROFILE_ATTRS:
        raw = getattr(pol, attr, None)
        if raw is None:
            continue
        val = str(raw).strip()
        if not val:
            continue
        rendered = _quote_cli_value(val) if quoted else val
        cli_lines.append(f"set {cli_key} {rendered}")
        if attr != "utm_status":
            labels.append(f"{cli_key}: {val}")
    return cli_lines, labels


def _format_policy_row(pol: FGPolicy, profile_labels: list[str]) -> dict[str, Any]:
    pid = str(pol.policy_id) if pol.policy_id is not None else "-"
    name = (pol.name or "").strip() or (f"Policy {pid}" if pid != "-" else "-")
    status = (pol.status or "enable").strip().capitalize()
    action = (pol.action or "accept").strip().upper()
    nat = (pol.nat or "disable").strip().capitalize()
    return {
        "id": pid,
        "name": name,
        "status": status,
        "srcintf": ", ".join(pol.srcintf or ()) or "-",
        "dstintf": ", ".join(pol.dstintf or ()) or "-",
        "srcaddr": ", ".join(pol.srcaddr or ()) or "-",
        "dstaddr": ", ".join(pol.dstaddr or ()) or "-",
        "service": ", ".join(pol.service or ()) or "-",
        "action": action,
        "nat": nat,
        "schedule": (pol.schedule or "always").strip() or "always",
        "groups": ", ".join(pol.groups or ()) or "-",
        "users": ", ".join(pol.users or ()) or "-",
        "profiles": ", ".join(profile_labels) if profile_labels else "-",
    }


def analyze_fortigate_ssl_to_ipsec(
    config: FGConfig,
    *,
    metadata: Any | None = None,
    vdom: str | None = None,
) -> dict[str, Any]:
    """Audit FortiGate SSL-VPN configuration and produce a Dial-up IPSec migration draft."""
    model = (getattr(metadata, "hardware_model", None) or "").strip() or "FortiGate"
    firmware = (getattr(metadata, "fortios_version", None) or "").strip() or "Unknown"

    vdoms = _ordered_vdoms(config)
    if not vdoms:
        return {
            "has_ssl_vpn": False,
            "vdom": None,
            "vdoms": [],
            "model": model,
            "firmware": firmware,
        }

    requested_vdom = _norm_vdom(vdom) if vdom else None
    active_vdom = requested_vdom if (requested_vdom and requested_vdom in vdoms) else vdoms[0]

    vdom_settings = [s for s in config.ssl_vpn_settings if _norm_vdom(s.vdom) == active_vdom]
    vdom_portals = [p for p in config.ssl_vpn_portals if _norm_vdom(p.vdom) == active_vdom]
    ssl_policies = [
        p for p in config.policies
        if _norm_vdom(p.vdom) == active_vdom and _policy_has_ssl_src(p)
    ]
    vdom_user_bookmarks = [
        b for b in config.ssl_vpn_user_bookmarks if _norm_vdom(b.vdom) == active_vdom
    ]
    vdom_group_bookmarks = [
        b for b in config.ssl_vpn_user_group_bookmarks if _norm_vdom(b.vdom) == active_vdom
    ]

    local_certs = {
        c.name
        for c in config.certificates
        if c.store == "local" and (c.vdom is None or _norm_vdom(c.vdom) == active_vdom)
    }
    saml_servers = {
        s.name for s in config.saml_servers if _norm_vdom(s.vdom) == active_vdom
    }
    user_groups = [ug for ug in config.user_groups if _norm_vdom(ug.vdom) == active_vdom]
    ldap_servers = [ls for ls in config.ldap_servers if _norm_vdom(ls.vdom) == active_vdom]
    radius_servers = [rs for rs in config.radius_servers if _norm_vdom(rs.vdom) == active_vdom]

    settings = vdom_settings[0] if vdom_settings else None

    group_members_map: dict[str, list[str]] = {}
    for ug in user_groups:
        members: list[str] = []
        _append_unique(members, ug.members)
        for match in ug.matches:
            if match.server_name:
                _append_unique(members, [match.server_name])
        group_members_map[ug.name] = members

    servercert = (settings.servercert if settings and settings.servercert else "Fortinet_Factory").strip()
    if not servercert:
        servercert = "Fortinet_Factory"
    is_factory_cert = servercert.lower() in {"fortinet_factory", "fortinet_factory2", "-", ""}
    cert_exists_locally = servercert in local_certs

    require_client_cert = False
    if settings is not None:
        if str(settings.raw_extra.get("reqclientcert", "")).strip().lower() == "enable":
            require_client_cert = True
        elif any(
            str(rule.client_cert or "").strip().lower() == "enable"
            for rule in settings.authentication_rules
        ):
            require_client_cert = True

    referenced_groups: list[str] = []
    if settings is not None:
        for rule in settings.authentication_rules:
            for grp in rule.groups:
                if grp and grp != "All Other Users/Groups" and grp not in referenced_groups:
                    referenced_groups.append(grp)
    for pol in ssl_policies:
        _append_unique(referenced_groups, pol.groups)

    detected_saml: list[str] = []
    for grp in referenced_groups:
        for member in group_members_map.get(grp, ()):
            if member in saml_servers and member not in detected_saml:
                detected_saml.append(member)
    if not detected_saml and saml_servers:
        detected_saml = sorted(saml_servers)

    if detected_saml:
        auth_mode = "saml"
    elif require_client_cert:
        auth_mode = "cert"
    else:
        auth_mode = "eap"

    listen_interfaces = [
        intf.strip()
        for intf in (settings.source_interface if settings else ())
        if intf and intf.strip() and intf.strip() != "(default)"
    ]
    wan_intf = listen_interfaces[0] if listen_interfaces else "wan1"

    ip_pools: list[str] = []
    if settings is not None:
        _append_unique(ip_pools, settings.tunnel_ip_pools)
    for portal in vdom_portals:
        _append_unique(ip_pools, portal.ip_pools)
    primary_pool = ip_pools[0] if ip_pools else "SSLVPN_TUNNEL_ADDR1"

    split_addrs: list[str] = []
    for portal in vdom_portals:
        _append_unique(split_addrs, portal.split_tunneling_routing_address)

    dns1 = (settings.dns_server1 or "-").strip() if settings and settings.dns_server1 else "-"
    dns2 = (settings.dns_server2 or "-").strip() if settings and settings.dns_server2 else "-"

    warnings: list[str] = []
    infos: list[str] = []

    if settings is not None and str(settings.status or "enable").strip().lower() == "disable":
        infos.append(
            "SSL-VPN status is currently disabled in settings; verify if legacy portals/policies are just leftover config."
        )

    if is_factory_cert:
        warnings.append(
            f"SSL-VPN uses '{servercert}' (self-signed). For IPSec IKEv2 EAP/SAML/Signature, install a CA-signed server certificate matching your VPN FQDN."
        )
    elif not cert_exists_locally and local_certs:
        warnings.append(
            f"Configured servercert '{servercert}' was not found in 'config vpn certificate local'; verify it exists before referencing it in IPSec."
        )

    web_portals = [
        p.name
        for p in vdom_portals
        if str(p.web_mode or "").strip().lower() == "enable"
        or bool(p.raw_extra.get("bookmark-group"))
    ]
    has_standalone_bookmarks = bool(vdom_user_bookmarks or vdom_group_bookmarks)
    if web_portals:
        warnings.append(
            f"Web-Mode / Bookmarks enabled on portal(s): {', '.join(web_portals)}. Dial-up IPSec has no clientless web portal — plan ZTNA / reverse proxy or full tunnel client access."
        )
    elif has_standalone_bookmarks:
        warnings.append(
            "SSL-VPN user/group bookmarks are configured. Dial-up IPSec has no clientless web portal — plan ZTNA / reverse proxy or full tunnel client access."
        )

    host_check_portals = [
        f"{p.name} ({p.host_check})"
        for p in vdom_portals
        if str(p.host_check or "none").strip().lower() not in {"none", "-", "disable", ""}
    ]
    if host_check_portals:
        warnings.append(
            f"Host-Check is configured on {', '.join(host_check_portals)}. SSL-VPN host-check does not transfer directly to IPSec — migrate posture checks to FortiClient EMS / ZTNA tags."
        )

    if not ssl_policies:
        warnings.append(
            "No firewall policies found with an ssl.* source interface; verify VDOM or policy bindings before cutover."
        )

    if require_client_cert:
        infos.append(
            "Client certificate verification (reqclientcert / client-cert) is enabled — draft includes 'config user peer' + 'authmethod signature'."
        )
    if len(vdom_portals) > 1:
        infos.append(
            f"Multiple SSL portals detected ({len(vdom_portals)}). Either consolidate onto one Dial-up IPSec tunnel with policy-level group matching, or create separate Dial-up tunnels with distinct Peer IDs."
        )
    if auth_mode == "saml":
        infos.append(
            f"SAML server(s) detected ({', '.join(detected_saml)}): requires FortiOS 7.2.4+ / 7.4+ and 'set ike-saml-server' bound on underlay interface '{wan_intf}'."
        )
    elif ldap_servers or radius_servers:
        infos.append(
            f"Detected external auth ({len(ldap_servers)} LDAP, {len(radius_servers)} RADIUS): mapped to IKEv2 + EAP in Phase 1."
        )
    infos.append(
        "IPSec uses UDP 500 & UDP 4500 (NAT-T) by default; ensure upstream ISP/firewalls permit them, or enable IPSec over TCP 443 ('set transport tcp' in FortiOS 7.4.2+) for restrictive networks."
    )

    tunnel_name = "RA-IPSec-IKEv2"
    p2_name = "RA-IPSec-P2"
    primary_group = referenced_groups[0] if referenced_groups else "SSL_VPN_USERS"
    cert_to_use = "<UPLOAD_CA_SIGNED_CERT>" if is_factory_cert else servercert

    auth_label = {
        "saml": f"IKEv2 + SAML ({', '.join(detected_saml)})",
        "cert": "IKEv2 + Signature (Client & Server Certificates)",
        "eap": "IKEv2 + EAP (PSK + User Group / LDAP / RADIUS)",
    }[auth_mode]

    gui_rows = [
        {
            "parameter": "Tunnel Name",
            "recommended_value": tunnel_name,
            "notes": "Custom Remote Access (Dial-up)",
        },
        {
            "parameter": "Incoming Interface",
            "recommended_value": wan_intf,
            "notes": f"All SSL listen intfs: {', '.join(listen_interfaces) or 'default'}",
        },
        {
            "parameter": "IKE Version",
            "recommended_value": "IKEv2",
            "notes": "Required for modern EAP / SAML",
        },
        {
            "parameter": "Authentication",
            "recommended_value": auth_label,
            "notes": f"Groups: {', '.join(referenced_groups) or 'None detected'}",
        },
        {
            "parameter": "Server Certificate",
            "recommended_value": cert_to_use,
            "notes": "Must match VPN FQDN (SAN) & be trusted by client OS",
        },
        {
            "parameter": "Phase 1 Proposal",
            "recommended_value": "AES256GCM-PRFSHA256 / AES256-SHA256",
            "notes": "DH Group 19, 20, 14",
        },
        {
            "parameter": "Phase 2 Proposal",
            "recommended_value": "AES256GCM / AES256-SHA256",
            "notes": "Enable PFS (DH Group 19, 20, 14)",
        },
        {
            "parameter": "Mode Config IP Pool",
            "recommended_value": primary_pool,
            "notes": f"All pools: {', '.join(ip_pools) or primary_pool}",
        },
        {
            "parameter": "DNS Server(s)",
            "recommended_value": ", ".join(d for d in (dns1, dns2) if d != "-") or "Use System DNS",
            "notes": "Pushed via Mode Config",
        },
        {
            "parameter": "Split Tunneling",
            "recommended_value": ", ".join(split_addrs) if split_addrs else "Disabled (Full Tunnel) or Policy-based",
            "notes": "Set via ipv4-split-include on Phase 1",
        },
    ]

    cli_lines: list[str] = [
        "# ======================================================================",
        "# DRAFT FortiGate Dial-up IPSec (IKEv2) Migration CLI",
        f"# VDOM: {active_vdom} — Generated offline from backup config — REVIEW & REPLACE <PLACEHOLDERS>",
        "# ======================================================================",
        "",
    ]

    if auth_mode == "saml":
        saml_name = detected_saml[0]
        cli_lines.extend(
            [
                "# 1. Bind SAML server on the WAN underlay interface (FortiOS 7.2.4+ / 7.4+)",
                "config system interface",
                f"    edit {_quote_cli_value(wan_intf)}",
                f"        set ike-saml-server {_quote_cli_value(saml_name)}",
                "    next",
                "end",
                "",
            ]
        )

    if require_client_cert:
        cli_lines.extend(
            [
                "# 1b. PKI Peer definition for client certificate validation",
                "config user peer",
                '    edit "IPSEC_CLIENT_PKI"',
                '        set ca "<REPLACE_WITH_CA_CERT_NAME>"',
                "    next",
                "end",
                "",
            ]
        )

    cli_lines.extend(
        [
            "# 2. Phase 1 Dial-up IPSec Interface (IKEv2 + Mode Config)",
            "config vpn ipsec phase1-interface",
            f"    edit {_quote_cli_value(tunnel_name)}",
            "        set type dynamic",
            f"        set interface {_quote_cli_value(wan_intf)}",
            "        set ike-version 2",
            "        set peertype any",
            "        set net-device disable",
            "        set mode-cfg enable",
            "        set proposal aes256gcm-prfsha256 aes256-sha256",
            "        set dhgrp 19 20 14",
            "        set dpd on-idle",
            "        set dpd-retrycount 3",
            "        set dpd-retryinterval 10",
            "        set assign-ip-from name",
            f"        set ipv4-name {_quote_cli_value(primary_pool)}",
        ]
    )

    if dns1 != "-":
        cli_lines.append("        set dns-mode manual")
        cli_lines.append(f"        set ipv4-dns-server1 {dns1}")
        if dns2 != "-":
            cli_lines.append(f"        set ipv4-dns-server2 {dns2}")
    else:
        cli_lines.append("        set dns-mode auto")

    if split_addrs:
        cli_lines.append(f"        set ipv4-split-include {_quote_list(split_addrs)}")

    if auth_mode == "cert":
        cli_lines.extend(
            [
                "        set authmethod signature",
                f"        set certificate {_quote_cli_value(cert_to_use)}",
                '        set peer "IPSEC_CLIENT_PKI"',
            ]
        )
    elif auth_mode == "saml":
        cli_lines.extend(
            [
                "        set eap enable",
                "        set eap-identity send-request",
                f"        set authusrgrp {_quote_cli_value(primary_group)}",
                "        set psksecret <REPLACE_WITH_STRONG_PSK>",
                f'        # Optional cert auth if replacing PSK: set authmethod signature / set certificate "{cert_to_use}"',
            ]
        )
    else:
        cli_lines.extend(
            [
                "        set eap enable",
                "        set eap-identity send-request",
                f"        set authusrgrp {_quote_cli_value(primary_group)}",
                "        set psksecret <REPLACE_WITH_STRONG_PSK>",
            ]
        )

    cli_lines.extend(["    next", "end", ""])

    cli_lines.extend(
        [
            "# 3. Phase 2 Selector",
            "config vpn ipsec phase2-interface",
            f"    edit {_quote_cli_value(p2_name)}",
            f"        set phase1name {_quote_cli_value(tunnel_name)}",
            "        set proposal aes256gcm aes256-sha256",
            "        set pfs enable",
            "        set dhgrp 19 20 14",
            "        set src-subnet 0.0.0.0 0.0.0.0",
            "        set dst-subnet 0.0.0.0 0.0.0.0",
            "        set keepalive enable",
            "    next",
            "end",
            "",
        ]
    )

    policy_rows: list[dict[str, Any]] = []
    if ssl_policies:
        cli_lines.extend(
            [
                "# 4. Cloned Firewall Policies (ssl.root -> Dial-up IPSec Tunnel)",
                "# Uses 'edit 0' so existing SSL-VPN policies remain untouched during parallel cutover.",
                "config firewall policy",
            ]
        )
        for pol in ssl_policies:
            prof_cli, prof_labels = _policy_profile_lines(pol)
            policy_rows.append(_format_policy_row(pol, prof_labels))

            pid = str(pol.policy_id) if pol.policy_id is not None else "0"
            pname = (pol.name or "").strip()
            new_name = f"IPSec-{pname}" if pname and pname != "-" else f"IPSec-From-Policy-{pid}"
            action = str(pol.action or "accept").strip().lower()
            if action not in {"accept", "deny"}:
                action = "accept"
            nat_val = "enable" if str(pol.nat or "").strip().lower() == "enable" else "disable"
            schedule = (pol.schedule or "always").strip() or "always"

            cli_lines.append("    edit 0")
            cli_lines.append(f"        set name {_quote_cli_value(new_name)}")
            cli_lines.append(f"        set srcintf {_quote_cli_value(tunnel_name)}")
            if pol.dstintf:
                cli_lines.append(f"        set dstintf {_quote_list(pol.dstintf)}")
            cli_lines.append(f"        set action {action}")
            cli_lines.append(f'        set srcaddr {_quote_list(pol.srcaddr) or "\"all\""}')
            cli_lines.append(f'        set dstaddr {_quote_list(pol.dstaddr) or "\"all\""}')
            cli_lines.append(f'        set service {_quote_list(pol.service) or "\"ALL\""}')
            cli_lines.append(f"        set schedule {_quote_cli_value(schedule)}")
            cli_lines.append(f"        set nat {nat_val}")
            if pol.groups:
                cli_lines.append(f"        set groups {_quote_list(pol.groups)}")
            if pol.users:
                cli_lines.append(f"        set users {_quote_list(pol.users)}")
            for pline in prof_cli:
                cli_lines.append(f"        {pline}")
            cli_lines.append("    next")
        cli_lines.append("end")

    forticlient_rows = [
        {"setting": "VPN Type", "value": "IPsec VPN (IKEv2)"},
        {"setting": "Remote Gateway", "value": f"VPN FQDN on {wan_intf} (matches cert SAN)"},
        {"setting": "Authentication Method", "value": auth_label},
        {"setting": "IKEv2 Proposals", "value": "Phase 1: AES256-GCM / SHA256 (DH 19/20/14) · Phase 2: AES256-GCM / PFS"},
        {"setting": "Transport Fallback", "value": "UDP 500/4500 (or TCP 443 if FortiOS 7.4.2+ transport tcp enabled)"},
    ]

    cutover_rows = [
        {
            "step": "1",
            "phase": "Pre-Check",
            "action": "Install CA-signed server cert matching VPN FQDN (do not reuse Fortinet_Factory).",
        },
        {
            "step": "2",
            "phase": "Build Parallel",
            "action": f"Apply Phase 1 ({tunnel_name}), Phase 2 ({p2_name}), and cloned policies alongside SSL-VPN.",
        },
        {
            "step": "3",
            "phase": "Pilot Test",
            "action": "Test with 1-2 pilot FortiClient users: verify Mode Config IP, DNS, split routes, and policy logs.",
        },
        {
            "step": "4",
            "phase": "Rollout",
            "action": "Deploy updated FortiClient IPsec profile via EMS / MDM to all remote users.",
        },
        {
            "step": "5",
            "phase": "Decommission",
            "action": "Confirm 0 active SSL-VPN sessions, set vpn ssl settings status disable, and remove ssl.root policies.",
        },
    ]

    return {
        "has_ssl_vpn": True,
        "vdom": active_vdom,
        "vdoms": vdoms,
        "model": model,
        "firmware": firmware,
        "servercert": servercert,
        "is_factory_cert": is_factory_cert,
        "require_client_cert": require_client_cert,
        "auth_mode": auth_mode,
        "auth_label": auth_label,
        "wan_intf": wan_intf,
        "listen_interfaces": listen_interfaces,
        "primary_pool": primary_pool,
        "ip_pools": ip_pools,
        "portals_count": len(vdom_portals),
        "ssl_policies_count": len(policy_rows),
        "referenced_groups": referenced_groups,
        "warnings": warnings,
        "infos": infos,
        "ssl_policies": policy_rows,
        "gui_rows": gui_rows,
        "cli_draft": "\n".join(cli_lines),
        "forticlient_rows": forticlient_rows,
        "cutover_rows": cutover_rows,
    }
