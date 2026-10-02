from __future__ import annotations

import re

from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult


def _without_no(lower: str) -> str:
    return lower[3:].lstrip() if lower.startswith("no ") else lower


def _path(line: str, parent: str | None = None) -> str:
    lower = line.lower().strip()
    effective = _without_no(lower)
    if parent == "object network" and effective.startswith("nat "):
        return "nat object"
    patterns = (
        (r"^hostname\b", "system hostname"),
        (r"^interface\b", "interface"),
        (r"^object network-service\b", "object network-service"),
        (r"^object network\b", "object network"),
        (r"^object service\b", "object service"),
        (r"^object-group network-service\b", "object-group network-service"),
        (r"^object-group network\b", "object-group network"),
        (r"^object-group service\b", "object-group service"),
        (r"^object-group protocol\b", "object-group protocol"),
        (r"^object-group icmp-type\b", "object-group icmp-type"),
        (r"^object-group user\b", "object-group user"),
        (r"^object-group security\b", "object-group security"),
        (r"^access-list\b", "access-list"),
        (r"^access-group\b", "access-group"),
        (r"^nat\b", "nat manual"),
        (r"^ipv6 route\b", "ipv6 route"),
        (r"^route\b", "route"),
        (r"^route-map\b", "route-map"),
        (r"^router\s+\S+", "dynamic-routing"),
        (r"^sla\s+monitor\s+\d+\b", "sla-monitor"),
        (r"^policy-route\b", "policy-route"),
        (r"^time-range\b", "time-range"),
        (r"^crypto ikev1 policy\b", "crypto ikev1 policy"),
        (r"^crypto ikev2 policy\b", "crypto ikev2 policy"),
        (r"^crypto ikev1\b", "crypto ikev1"),
        (r"^crypto ikev2\b", "crypto ikev2"),
        (r"^crypto ipsec\b", "crypto ipsec"),
        (r"^crypto map\b", "crypto map"),
        (r"^crypto dynamic-map\b", "crypto map"),
        (r"^crypto ca trustpoint\b", "certificate/trustpoint"),
        (r"^crypto ca certificate\b", "certificate/trustpoint"),
        (r"^certificate\b", "certificate/trustpoint"),
        (r"^ip local pool\b", "vpn address pool"),
        (r"^webvpn\b", "webvpn"),
        (r"^vpn-addr-assign\b", "vpn-addr-assign"),
        (r"^privilege\b", "privilege"),
        (r"^tunnel-group\b", "tunnel-group"),
        (r"^group-policy\b", "group-policy"),
        (r"^username\b", "username"),
        (r"^aaa-server\b", "aaa-server"),
        (r"^aaa\b", "aaa"),
        (r"^class-map type inspect\b", "class-map type inspect"),
        (r"^class-map\b", "class-map"),
        (r"^policy-map type inspect\b", "policy-map type inspect"),
        (r"^policy-map\b", "policy-map"),
        (r"^tcp-map\b", "tcp-map"),
        (r"^conn\b", "conn"),
        (r"^timeout\b", "timeout"),
        (r"^threat-detection\b", "threat-detection"),
        (r"^service-policy\b", "service-policy"),
        (r"^context\b", "context"),
        (r"^admin-context\b", "admin-context"),
        (r"^allocate-interface\b", "allocate-interface"),
        (r"^config-url\b", "config-url"),
        (r"^resource-class\b", "resource-class"),
        (r"^changeto\s+(?:context|system|admin)\b", "context"),
        (r"^failover\b", "failover"),
        (r"^monitor-interface\b", "failover"),
        (r"^management-access\b", "management-access"),
        (r"^same-security-traffic\b", "same-security-traffic"),
        (r"^sysopt\s+connection\s+permit-vpn$", "sysopt connection permit-vpn"),
        (r"^clock\s+(?:timezone|summer-time)\b", "timezone"),
        (r"^domain-name\b", "domain-name"),
        (r"^dns-group\b", "dns"),
        (r"^(?:ssh|http|telnet|snmp-server|logging|dns|dhcpd|dhcprelay|ntp|enable|flow-export)\b", "management-or-network-service"),
    )
    for pattern, path in patterns:
        if re.match(pattern, effective):
            if path == "management-or-network-service":
                command = effective.split()[0]
                return "snmp" if command == "snmp-server" else command
            return path
    return "other"


def _build_source_contexts(lines: list[str]) -> dict[int, str | None]:
    """Track explicit ASA execution-space markers without deriving semantics."""
    admin_name: str | None = None
    for raw in lines:
        if raw[:1].isspace():
            continue
        line = raw.strip()
        match = re.fullmatch(r"admin-context\s+(\S+)", line, re.I)
        if match:
            admin_name = match.group(1)
        elif re.fullmatch(r"no\s+admin-context(?:\s+\S+)?", line, re.I):
            admin_name = None

    ownership: dict[int, str | None] = {}
    active: str | None = None
    for index, raw in enumerate(lines):
        number = index + 1
        line = raw.strip()
        ownership[number] = active
        if not line or line.startswith(("!", ":")) or raw[:1].isspace():
            continue
        switch = re.fullmatch(r"changeto\s+context\s+(\S+)", line, re.I)
        if switch:
            active = switch.group(1)
            ownership[number] = active
            continue
        if re.fullmatch(r"changeto\s+system", line, re.I):
            active = None
            ownership[number] = None
            continue
        if re.fullmatch(r"changeto\s+admin", line, re.I):
            active = admin_name
            ownership[number] = active
            continue
        context = re.fullmatch(r"context\s+(\S+)", line, re.I)
        if context:
            next_index = index + 1
            while next_index < len(lines) and not lines[next_index].strip():
                next_index += 1
            has_definition_children = (
                next_index < len(lines)
                and not lines[next_index].strip().startswith(("!", ":"))
                and bool(lines[next_index][:1].isspace())
            )
            active = None if has_definition_children else context.group(1)
            ownership[number] = active
    return ownership


def scan_cisco_asa_sections(text: str) -> list[SourceSectionResult]:
    """Account for every non-comment ASA command and hierarchical block."""
    lines = text.splitlines()
    contexts = _build_source_contexts(lines)
    sections: list[SourceSectionResult] = []
    current: SourceSectionResult | None = None
    current_path: str | None = None
    block_paths = {
        "interface", "object network", "object network-service", "object service",
        "object-group network", "object-group network-service", "object-group service",
        "object-group protocol", "object-group icmp-type", "object-group user",
        "object-group security", "time-range", "class-map", "class-map type inspect",
        "policy-map", "policy-map type inspect", "route-map", "tunnel-group",
        "group-policy", "aaa-server", "tcp-map", "dns", "context", "failover",
        "crypto map", "crypto ikev1 policy", "crypto ikev2 policy", "crypto ipsec", "webvpn",
        "certificate/trustpoint", "vpn address pool", "dynamic-routing", "sla-monitor",
    }
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith(("!", ":")):
            if current is not None:
                current.line_end = number - 1
                current = None
                current_path = None
            continue
        indented = bool(raw[:1].isspace())
        if indented and current is not None and current_path in block_paths:
            current.line_end = number
            current.object_count_source = (current.object_count_source or 0) + 1
            continue
        if current is not None:
            current.line_end = number - 1
        current_path = _path(line)
        current = SourceSectionResult(
            path=current_path, source_context=contexts.get(number),
            line_start=number, line_end=number,
            object_count_source=1, status=ExtractionStatus.UNSUPPORTED,
        )
        sections.append(current)
        if current_path not in block_paths:
            current = None
            current_path = None
    return sections

