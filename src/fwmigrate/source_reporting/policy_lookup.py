"""Read-only 5-tuple Policy Match Simulator for FortiGate and Palo Alto configs."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from re import compile as re_compile, split as re_split
from typing import Any

from fwmigrate.source_reporting.ip_match import parse_ipv4_range
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.palo_alto.model.source import PANOSConfig
from fwmigrate.vendors.palo_alto.source_model import PANScope, pan_scope_identity

# Built-in FortiGate well-known service definitions:
# SERVICE_NAME -> list of (protocol, port_start, port_end) where 0..65535 means any port.
_WELL_KNOWN_SERVICES: dict[str, list[tuple[str, int, int]]] = {
    "ALL": [("ALL", 0, 65535)],
    "ANY": [("ALL", 0, 65535)],
    "ALL_TCP": [("TCP", 1, 65535)],
    "TCP": [("TCP", 1, 65535)],
    "ALL_UDP": [("UDP", 1, 65535)],
    "UDP": [("UDP", 1, 65535)],
    "ALL_ICMP": [("ICMP", 0, 65535)],
    "ICMP": [("ICMP", 0, 65535)],
    "PING": [("ICMP", 0, 65535)],
    "HTTP": [("TCP", 80, 80)],
    "HTTPS": [("TCP", 443, 443)],
    "SSH": [("TCP", 22, 22)],
    "TELNET": [("TCP", 23, 23)],
    "DNS": [("TCP", 53, 53), ("UDP", 53, 53)],
    "RDP": [("TCP", 3389, 3389)],
    "SMTP": [("TCP", 25, 25)],
    "SMTPS": [("TCP", 465, 465)],
    "SUBMISSION": [("TCP", 587, 587)],
    "FTP": [("TCP", 21, 21)],
    "NTP": [("UDP", 123, 123)],
    "SNMP": [("UDP", 161, 161), ("UDP", 162, 162)],
    "SYSLOG": [("UDP", 514, 514)],
    "SMB": [("TCP", 445, 445)],
    "LDAP": [("TCP", 389, 389)],
    "LDAPS": [("TCP", 636, 636)],
    "DHCP": [("UDP", 67, 68)],
    "RADIUS": [("UDP", 1812, 1813)],
    "IKE": [("UDP", 500, 500), ("UDP", 4500, 4500)],
}

# PAN-OS built-in service aliases.
_PAN_BUILTIN_SERVICES: dict[str, list[tuple[str, int, int]]] = {
    "SERVICE-HTTP": [("TCP", 80, 80)],
    "SERVICE-HTTPS": [("TCP", 443, 443)],
}

_PROTO_PORT_RE = re_compile(r"^(TCP|UDP|SCTP)/(\d+)(?:-(\d+))?$")
_RULEBASE_ORDER = {"pre": 0, "local": 1, "post": 2}


def _strip_port(val: str | None) -> str:
    s = str(val or "").strip()
    if ":" in s and not s.startswith("["):
        return s.split(":", 1)[0].strip()
    return s


def _parse_query_ip(query: str) -> IPv4Address | IPv6Address | None:
    try:
        return ip_address(_strip_port(query))
    except ValueError:
        return None


def _ip_matches_literal(query: str, candidate: str | None) -> bool:
    """Match an IP query (or name query) against an IPv4/IPv6 CIDR, netmask, or range."""
    q_clean = _strip_port(query)
    c_clean = str(candidate or "").strip()
    if not c_clean:
        return False
    if q_clean.lower() == c_clean.lower():
        return True

    q_ip = _parse_query_ip(q_clean)
    if q_ip is None:
        return False

    if q_ip.version == 4:
        bounds = parse_ipv4_range(c_clean)
        if bounds is not None:
            q_int = int(q_ip)
            return bounds[0] <= q_int <= bounds[1]
        return False

    try:
        net = ip_network(c_clean, strict=False)
        return net.version == 6 and q_ip in net
    except ValueError:
        if "-" in c_clean:
            left, right = c_clean.split("-", 1)
            try:
                lo = IPv6Address(left.strip())
                hi = IPv6Address(right.strip())
                return int(min(lo, hi)) <= int(q_ip) <= int(max(lo, hi))
            except ValueError:
                return False
    return False


def _parse_port_specs(spec_str: str | None, proto: str, *, sep_regex: str = r"[\s,]+") -> list[tuple[str, int, int]]:
    """Parse FortiGate space-separated or PAN-OS comma-separated port specs into (proto, lo, hi)."""
    out: list[tuple[str, int, int]] = []
    if not spec_str:
        return out
    for token in re_split(sep_regex, spec_str.strip()):
        dst_part = token.split(":", 1)[0].strip()
        if not dst_part:
            continue
        if "-" in dst_part:
            parts = dst_part.split("-", 1)
            try:
                lo, hi = int(parts[0]), int(parts[1])
                out.append((proto, min(lo, hi), max(lo, hi)))
            except ValueError:
                continue
        else:
            try:
                p = int(dst_part)
                out.append((proto, p, p))
            except ValueError:
                continue
    return out


def _expand_service_specs(
    svc_name: str,
    svc_specs: dict[str, list[tuple[str, int, int]]],
    svc_groups: dict[str, list[str]],
    visited: set[str],
) -> list[tuple[str, int, int]]:
    key = svc_name.strip().upper()
    if not key or key in visited:
        return []
    visited.add(key)
    if key in svc_groups:
        out: list[tuple[str, int, int]] = []
        for member in svc_groups[key]:
            out.extend(_expand_service_specs(member, svc_specs, svc_groups, visited))
        return out
    return list(svc_specs.get(key, []))


def _collect_group_names(grp_name: str, groups: dict[str, list[str]], visited: set[str]) -> set[str]:
    key = grp_name.upper()
    if key in visited:
        return set()
    visited.add(key)
    names: set[str] = {key}
    for member in groups.get(key, []):
        mu = member.upper()
        names.add(mu)
        if mu in groups:
            names.update(_collect_group_names(mu, groups, visited))
    return names


def _parse_query_specs(
    query: str,
    svc_specs: dict[str, list[tuple[str, int, int]]],
    svc_groups: dict[str, list[str]],
) -> tuple[str, list[tuple[str, int, int]]]:
    q = query.strip().upper()
    if q in ("", "ANY", "ALL", "IP"):
        return q, [("ALL", 0, 65535)]

    m = _PROTO_PORT_RE.match(q)
    if m:
        proto = m.group(1)
        lo = int(m.group(2))
        hi = int(m.group(3)) if m.group(3) else lo
        return q, [(proto, min(lo, hi), max(lo, hi))]

    if q.isdigit():
        p = int(q)
        return q, [("TCP", p, p), ("UDP", p, p)]

    if q in svc_specs:
        return q, svc_specs[q]
    if q in svc_groups:
        return q, _expand_service_specs(q, svc_specs, svc_groups, set())
    return q, []


def _specs_overlap(pol_specs: list[tuple[str, int, int]], q_specs: list[tuple[str, int, int]]) -> bool:
    for p_proto, p_lo, p_hi in pol_specs:
        if p_proto == "ALL":
            return True
        for q_proto, q_lo, q_hi in q_specs:
            if q_proto == "ALL":
                return True
            if p_proto == q_proto and max(p_lo, q_lo) <= min(p_hi, q_hi):
                return True
    return False


def _service_tokens_match(
    pol_tokens: list[str],
    proto_query: str,
    svc_specs: dict[str, list[tuple[str, int, int]]],
    svc_groups: dict[str, list[str]],
    *,
    allow_app_default: bool = False,
) -> bool:
    q_upper, q_specs = _parse_query_specs(proto_query, svc_specs, svc_groups)
    if q_upper in ("", "ANY", "ALL", "IP"):
        return True

    for token in pol_tokens:
        tok_upper = token.strip().upper()
        if not tok_upper:
            continue
        if tok_upper in ("ALL", "ANY", q_upper):
            return True
        if allow_app_default and tok_upper == "APPLICATION-DEFAULT":
            return True
        if tok_upper in svc_groups:
            members = _collect_group_names(tok_upper, svc_groups, set())
            if q_upper in members or "ALL" in members or "ANY" in members:
                return True
        pol_specs = _expand_service_specs(tok_upper, svc_specs, svc_groups, set())
        if pol_specs and q_specs and _specs_overlap(pol_specs, q_specs):
            return True
        if not q_specs and q_upper in tok_upper:
            return True
    return False


# ---------------------------------------------------------------------------
# FortiGate Policy Match Simulator
# ---------------------------------------------------------------------------


def _fg_vdom_matches(item_vdom: str | None, target_vdom: str | None) -> bool:
    if not target_vdom or target_vdom.lower() == "all":
        return True
    return (item_vdom or "root").lower() == target_vdom.lower()


def _fg_build_indexes(config: FGConfig, vdom: str | None):
    addr_by_name: dict[str, list[Any]] = {}
    for addr in config.addresses:
        if _fg_vdom_matches(addr.vdom, vdom):
            addr_by_name.setdefault(addr.name, []).append(addr)

    iface_subnets: dict[str, list[str]] = {}
    for iface in config.interfaces:
        if _fg_vdom_matches(iface.vdom, vdom) and iface.ip:
            iface_subnets.setdefault(iface.name, []).append(iface.ip)

    groups: dict[str, Any] = {}
    for grp in config.address_groups:
        if _fg_vdom_matches(grp.vdom, vdom):
            groups[grp.name] = grp

    vips: dict[str, Any] = {}
    for vip in config.vips:
        if _fg_vdom_matches(vip.vdom, vdom):
            vips[vip.name] = vip

    vip_groups: dict[str, list[str]] = {}
    for vg in config.vip_groups:
        if _fg_vdom_matches(vg.vdom, vdom):
            vip_groups[vg.name] = list(vg.members or [])

    svc_specs: dict[str, list[tuple[str, int, int]]] = {k: list(v) for k, v in _WELL_KNOWN_SERVICES.items()}
    for svc in config.services:
        if not _fg_vdom_matches(svc.vdom, vdom):
            continue
        specs: list[tuple[str, int, int]] = []
        specs.extend(_parse_port_specs(svc.tcp_portrange, "TCP", sep_regex=r"\s+"))
        specs.extend(_parse_port_specs(svc.udp_portrange, "UDP", sep_regex=r"\s+"))
        specs.extend(_parse_port_specs(svc.sctp_portrange, "SCTP", sep_regex=r"\s+"))
        proto = (svc.protocol or "").upper()
        if not specs:
            if "ICMP" in proto:
                specs.append(("ICMP", 0, 65535))
            elif proto in ("ALL", "IP"):
                specs.append(("ALL", 0, 65535))
        if specs:
            svc_specs[svc.name.upper()] = specs

    svc_groups: dict[str, list[str]] = {}
    for sg in config.service_groups:
        if _fg_vdom_matches(sg.vdom, vdom):
            svc_groups[sg.name.upper()] = [m for m in (sg.members or []) if m]

    return addr_by_name, iface_subnets, groups, vips, vip_groups, svc_specs, svc_groups


def _fg_addr_matches(
    query: str,
    obj_name: str,
    addr_by_name: dict[str, list[Any]],
    iface_subnets: dict[str, list[str]],
    groups: dict[str, Any],
    vips: dict[str, Any] | None,
    vip_groups: dict[str, list[str]] | None,
    visited: set[str] | None = None,
) -> bool:
    name = (obj_name or "").strip()
    low = name.lower()
    if low in ("all", "any", ""):
        return True
    q_clean = query.strip()
    if q_clean.lower() == low:
        return True

    seen = visited if visited is not None else set()
    if name in seen:
        return False
    seen.add(name)

    if vip_groups and name in vip_groups:
        for member in vip_groups[name]:
            if _fg_addr_matches(q_clean, member, addr_by_name, iface_subnets, groups, vips, vip_groups, seen):
                return True

    if vips and name in vips:
        vip = vips[name]
        if vip.extip and _ip_matches_literal(q_clean, vip.extip):
            return True
        for m_ip in vip.mappedip or []:
            if _ip_matches_literal(q_clean, m_ip):
                return True

    if name in groups:
        grp = groups[name]
        if (grp.exclude or "").lower() == "enable":
            for ex in grp.exclude_members or []:
                if _fg_addr_matches(q_clean, ex, addr_by_name, iface_subnets, groups, vips, vip_groups, set(seen)):
                    return False
        for member in grp.members or []:
            if _fg_addr_matches(q_clean, member, addr_by_name, iface_subnets, groups, vips, vip_groups, seen):
                return True

    for addr in addr_by_name.get(name, []):
        if addr.subnet and _ip_matches_literal(q_clean, addr.subnet):
            return True
        if addr.ip6 and _ip_matches_literal(q_clean, addr.ip6):
            return True
        if addr.start_ip and addr.end_ip and _ip_matches_literal(q_clean, f"{addr.start_ip}-{addr.end_ip}"):
            return True
        if addr.fqdn and q_clean.lower() == addr.fqdn.strip().lower():
            return True
        if (addr.type or "").lower() == "interface-subnet" and addr.associated_interface:
            for ip_net in iface_subnets.get(addr.associated_interface, []):
                if _ip_matches_literal(q_clean, ip_net):
                    return True

    return _ip_matches_literal(q_clean, name)


def _fg_policy_record(pol: Any) -> dict[str, Any]:
    return {
        "id": str(pol.policy_id) if pol.policy_id is not None else "-",
        "name": pol.name or f"Policy #{pol.policy_id or '-'}",
        "vdom": pol.vdom or "root",
        "src_interface": ", ".join(pol.srcintf or []) or "any",
        "dst_interface": ", ".join(pol.dstintf or []) or "any",
        "source": ", ".join(pol.srcaddr or pol.srcaddr6 or []) or "all",
        "destination": ", ".join(pol.dstaddr or pol.dstaddr6 or []) or "all",
        "service": ", ".join(pol.service or []) or "ALL",
        "action": (pol.action or "deny").upper(),
        "nat": pol.nat or "disable",
        "schedule": pol.schedule or "always",
        "comments": pol.comments or "",
    }


def evaluate_fortigate_policy_lookup(
    config: FGConfig,
    *,
    vdom: str | None = None,
    src_iface: str = "any",
    dst_iface: str = "any",
    src_addr: str = "",
    dst_addr: str = "",
    protocol: str = "any",
) -> dict[str, Any]:
    """Evaluate FortiGate firewall policies top-to-bottom for a 5-tuple query."""
    addr_by_name, iface_subnets, groups, vips, vip_groups, svc_specs, svc_groups = _fg_build_indexes(config, vdom)

    src_i_q = (src_iface or "any").strip().lower()
    dst_i_q = (dst_iface or "any").strip().lower()
    src_q = (src_addr or "").strip()
    dst_q = (dst_addr or "").strip()
    proto_q = (protocol or "any").strip()

    matches: list[dict[str, Any]] = []
    for pol in config.policies:
        if not _fg_vdom_matches(pol.vdom, vdom):
            continue
        if (pol.status or "enable").lower() == "disable":
            continue

        pol_src_intfs = [x.strip().lower() for x in (pol.srcintf or ["any"])]
        if src_i_q not in ("", "any") and "any" not in pol_src_intfs and src_i_q not in pol_src_intfs:
            continue

        pol_dst_intfs = [x.strip().lower() for x in (pol.dstintf or ["any"])]
        if dst_i_q not in ("", "any") and "any" not in pol_dst_intfs and dst_i_q not in pol_dst_intfs:
            continue

        if src_q and src_q.lower() not in ("any", "all"):
            src_names = pol.srcaddr or pol.srcaddr6 or ["all"]
            src_hit = any(
                _fg_addr_matches(src_q, n, addr_by_name, iface_subnets, groups, None, None)
                for n in src_names
            )
            if (pol.srcaddr_negate or "").lower() == "enable":
                src_hit = not src_hit
            if not src_hit:
                continue

        if dst_q and dst_q.lower() not in ("any", "all"):
            dst_names = pol.dstaddr or pol.dstaddr6 or ["all"]
            dst_hit = any(
                _fg_addr_matches(dst_q, n, addr_by_name, iface_subnets, groups, vips, vip_groups)
                for n in dst_names
            )
            if (pol.dstaddr_negate or "").lower() == "enable":
                dst_hit = not dst_hit
            if not dst_hit:
                continue

        svc_hit = _service_tokens_match(pol.service or ["ALL"], proto_q, svc_specs, svc_groups)
        if (pol.service_negate or "").lower() == "enable" and proto_q.lower() not in ("", "any", "all", "ip"):
            svc_hit = not svc_hit
        if not svc_hit:
            continue

        matches.append(_fg_policy_record(pol))

    if not matches:
        return {
            "vendor": "fortigate",
            "matched": False,
            "action": "DENY",
            "reason": "No enabled FortiGate policy matched all criteria (Implicit DENY).",
            "match": None,
            "shadowed": [],
        }

    first = matches[0]
    return {
        "vendor": "fortigate",
        "matched": True,
        "action": first["action"],
        "reason": f"Matched Policy #{first['id']} ({first['name']}) — {first['action']}.",
        "match": first,
        "shadowed": matches[1:],
    }


# ---------------------------------------------------------------------------
# Palo Alto Policy Match Simulator
# ---------------------------------------------------------------------------


def _scope_label(scope: PANScope | None) -> str:
    if scope is None:
        return "shared"
    return scope.vsys or scope.device_group or scope.name or pan_scope_identity(scope)


def _pan_scope_matches(item_scope: PANScope | None, target_scope: str | None) -> bool:
    if not target_scope or target_scope.lower() == "all":
        return True
    if item_scope is None or item_scope.kind == "shared":
        return True
    target_low = target_scope.strip().lower()
    candidates = {
        (item_scope.name or "").lower(),
        (item_scope.vsys or "").lower(),
        (item_scope.device_group or "").lower(),
        pan_scope_identity(item_scope).lower(),
    }
    return target_low in candidates


def _pan_build_indexes(config: PANOSConfig, scope: str | None):
    addr_map: dict[str, list[Any]] = {}
    for addr in config.addresses:
        if addr.name and _pan_scope_matches(addr.scope, scope):
            addr_map.setdefault(addr.name, []).append(addr)

    group_map: dict[str, list[str]] = {}
    for grp in config.address_groups:
        if grp.name and _pan_scope_matches(grp.scope, scope):
            group_map[grp.name] = [m for m in (grp.static_members or []) if m]

    svc_specs: dict[str, list[tuple[str, int, int]]] = {k: list(v) for k, v in _PAN_BUILTIN_SERVICES.items()}
    for svc in config.services:
        if not svc.name or not _pan_scope_matches(svc.scope, scope):
            continue
        specs: list[tuple[str, int, int]] = []
        if svc.tcp and svc.tcp.port:
            specs.extend(_parse_port_specs(svc.tcp.port, "TCP", sep_regex=r"[\s,]+"))
        if svc.udp and svc.udp.port:
            specs.extend(_parse_port_specs(svc.udp.port, "UDP", sep_regex=r"[\s,]+"))
        if svc.sctp and svc.sctp.port:
            specs.extend(_parse_port_specs(svc.sctp.port, "SCTP", sep_regex=r"[\s,]+"))
        if specs:
            svc_specs[svc.name.upper()] = specs

    svc_groups: dict[str, list[str]] = {}
    for sg in config.service_groups:
        if sg.name and _pan_scope_matches(sg.scope, scope):
            svc_groups[sg.name.upper()] = [m for m in (sg.members or []) if m]

    return addr_map, group_map, svc_specs, svc_groups


def _pan_addr_matches(
    query: str,
    members: list[str] | None,
    addr_map: dict[str, list[Any]],
    group_map: dict[str, list[str]],
    visited: set[str] | None = None,
) -> bool:
    q_clean = (query or "").strip()
    if not q_clean or q_clean.lower() in ("any", "all"):
        return True
    if not members:
        return True

    for member in members:
        name = (member or "").strip()
        if not name or name.lower() == "any":
            return True
        if q_clean.lower() == name.lower():
            return True
        seen = visited if visited is not None else set()
        if name in seen:
            continue
        next_seen = seen | {name}
        if name in group_map:
            if _pan_addr_matches(q_clean, group_map[name], addr_map, group_map, next_seen):
                return True
        for obj in addr_map.get(name, []):
            if obj.ip_netmask and _ip_matches_literal(q_clean, obj.ip_netmask):
                return True
            if obj.ip_range and _ip_matches_literal(q_clean, obj.ip_range):
                return True
            if obj.fqdn and q_clean.lower() in obj.fqdn.strip().lower():
                return True
        if _ip_matches_literal(q_clean, name):
            return True
    return False


def _format_pan_nat_summary(rule: Any) -> tuple[str, str]:
    src_t = "None"
    if rule.source_translation is not None:
        st = rule.source_translation
        if getattr(st, "translated_addresses", None):
            src_t = f"{st.translation_type or 'src'}: {', '.join(st.translated_addresses)}"
        elif getattr(st, "translated_address", None):
            src_t = f"{st.translation_type or 'static'}: {st.translated_address}"
        elif getattr(st, "interface", None):
            src_t = f"{st.translation_type or 'interface'}: {st.interface}"
        else:
            src_t = st.translation_type or "Configured"

    dst_t = "None"
    if rule.destination_translation is not None:
        dt = rule.destination_translation
        dst_t = f"{dt.translated_address or '-'}{f':{dt.translated_port}' if dt.translated_port else ''}"
    elif rule.dynamic_destination_translation is not None:
        ddt = rule.dynamic_destination_translation
        addrs = ", ".join(ddt.translated_addresses or []) or "-"
        dst_t = f"{addrs}{f':{ddt.translated_port}' if ddt.translated_port else ''}"
    return src_t, dst_t


def evaluate_paloalto_policy_lookup(
    config: PANOSConfig,
    *,
    scope: str | None = None,
    policy_type: str = "security",
    src_zone: str = "any",
    dst_zone: str = "any",
    src_addr: str = "",
    dst_addr: str = "",
    src_user: str = "any",
    dst_port: str = "",
    protocol: str = "any",
) -> dict[str, Any]:
    """Evaluate Palo Alto security or NAT rules top-to-bottom for a 5-tuple query."""
    ptype = (policy_type or "security").strip().lower()
    if ptype not in ("security", "nat"):
        raise ValueError("policy_type must be 'security' or 'nat'")

    addr_map, group_map, svc_specs, svc_groups = _pan_build_indexes(config, scope)
    sz_q = (src_zone or "any").strip().lower()
    dz_q = (dst_zone or "any").strip().lower()
    src_q = (src_addr or "").strip()
    dst_q = (dst_addr or "").strip()
    user_q = (src_user or "any").strip().lower()

    proto_clean = (protocol or "any").strip().lower()
    port_clean = (dst_port or "").strip()
    if proto_clean in ("icmp", "any") and not port_clean:
        svc_query = proto_clean
    elif port_clean and proto_clean not in ("any", ""):
        svc_query = f"{proto_clean}/{port_clean}"
    elif port_clean:
        svc_query = port_clean
    else:
        svc_query = proto_clean

    raw_rules = list(config.security_rules if ptype == "security" else config.nat_rules)
    ordered_rules = sorted(
        raw_rules,
        key=lambda r: (
            _RULEBASE_ORDER.get(r.rulebase_position or "local", 1),
            r.source_order if r.source_order is not None else 0,
        ),
    )

    matches: list[dict[str, Any]] = []
    for idx, rule in enumerate(ordered_rules, start=1):
        if not _pan_scope_matches(rule.scope, scope):
            continue
        if (rule.disabled or "no").lower() == "yes":
            continue

        from_z = [z.strip().lower() for z in (rule.from_zones or ["any"])]
        to_z = [z.strip().lower() for z in (rule.to_zones or ["any"])]
        if sz_q not in ("", "any") and "any" not in from_z and sz_q not in from_z:
            continue
        if dz_q not in ("", "any") and "any" not in to_z and dz_q not in to_z:
            continue

        if src_q and src_q.lower() not in ("any", "all"):
            src_hit = _pan_addr_matches(src_q, rule.source, addr_map, group_map)
            if ptype == "security" and (rule.negate_source or "no").lower() == "yes":
                src_hit = not src_hit
            if not src_hit:
                continue

        if dst_q and dst_q.lower() not in ("any", "all"):
            dst_hit = _pan_addr_matches(dst_q, rule.destination, addr_map, group_map)
            if ptype == "security" and (rule.negate_destination or "no").lower() == "yes":
                dst_hit = not dst_hit
            if not dst_hit:
                continue

        if ptype == "security":
            users = [u.strip().lower() for u in (rule.source_user or ["any"])]
            if user_q not in ("", "any") and "any" not in users and user_q not in users:
                continue
            rule_svcs = rule.service or ["any"]
        else:
            rule_svcs = [rule.service] if rule.service else ["any"]

        if not _service_tokens_match(rule_svcs, svc_query, svc_specs, svc_groups, allow_app_default=True):
            continue

        if ptype == "security":
            action_val = (rule.action or "allow").upper()
            record: dict[str, Any] = {
                "index": idx,
                "name": rule.name or f"Rule #{idx}",
                "scope": _scope_label(rule.scope),
                "rulebase_position": rule.rulebase_position or "local",
                "src_zone": ", ".join(rule.from_zones or []) or "any",
                "dst_zone": ", ".join(rule.to_zones or []) or "any",
                "source": ", ".join(rule.source or []) or "any",
                "destination": ", ".join(rule.destination or []) or "any",
                "application": ", ".join(rule.application or []) or "any",
                "service": ", ".join(rule_svcs) or "any",
                "action": action_val,
            }
        else:
            src_t, dst_t = _format_pan_nat_summary(rule)
            record = {
                "index": idx,
                "name": rule.name or f"NAT #{idx}",
                "scope": _scope_label(rule.scope),
                "rulebase_position": rule.rulebase_position or "local",
                "src_zone": ", ".join(rule.from_zones or []) or "any",
                "dst_zone": ", ".join(rule.to_zones or []) or "any",
                "source": ", ".join(rule.source or []) or "any",
                "destination": ", ".join(rule.destination or []) or "any",
                "service": rule.service or "any",
                "src_translation": src_t,
                "dst_translation": dst_t,
                "action": "NAT",
            }
        matches.append(record)

    if matches:
        first = matches[0]
        return {
            "vendor": "palo_alto",
            "policy_type": ptype,
            "matched": True,
            "action": first["action"],
            "reason": f"Matched {ptype.upper()} rule '{first['name']}' (index {first['index']}).",
            "match": first,
            "shadowed": matches[1:],
        }

    if ptype == "security" and sz_q not in ("", "any") and sz_q == dz_q:
        default_intra = next(
            (r for r in config.default_security_rules if (r.name or "").lower() == "intrazone-default" and _pan_scope_matches(r.scope, scope)),
            None,
        )
        intra_action = (default_intra.action if default_intra and default_intra.action else "allow").upper()
        return {
            "vendor": "palo_alto",
            "policy_type": ptype,
            "matched": False,
            "action": intra_action,
            "reason": f"No explicit rule matched; same-zone traffic hits intrazone-default ({intra_action}).",
            "match": None,
            "shadowed": [],
        }

    return {
        "vendor": "palo_alto",
        "policy_type": ptype,
        "matched": False,
        "action": "DENY",
        "reason": f"No {ptype.upper()} rule matched all criteria (Implicit Deny / interzone-default).",
        "match": None,
        "shadowed": [],
    }
