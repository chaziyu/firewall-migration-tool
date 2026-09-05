from __future__ import annotations

import re

from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult


def _path(line: str, parent: str | None = None) -> str:
    lower = line.lower()
    if parent == "object network" and lower.startswith("nat "):
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
        (r"^policy-route\b", "policy-route"),
        (r"^time-range\b", "time-range"),
        (r"^crypto ikev1 policy\b", "crypto ikev1 policy"),
        (r"^crypto ikev2 policy\b", "crypto ikev2 policy"),
        (r"^crypto ikev1\b", "crypto ikev1"),
        (r"^crypto ikev2\b", "crypto ikev2"),
        (r"^crypto ipsec\b", "crypto ipsec"),
        (r"^crypto map\b", "crypto map"),
        (r"^crypto dynamic-map\b", "crypto map"),
        (r"^ip local pool\b", "vpn address pool"),
        (r"^tunnel-group\b", "tunnel-group"),
        (r"^group-policy\b", "group-policy"),
        (r"^username\b", "username"),
        (r"^aaa-server\b", "aaa-server"),
        (r"^aaa\b", "aaa"),
        (r"^class-map\b", "class-map"),
        (r"^policy-map\b", "policy-map"),
        (r"^service-policy\b", "service-policy"),
        (r"^context\b", "context"),
        (r"^admin-context\b", "admin-context"),
        (r"^allocate-interface\b", "allocate-interface"),
        (r"^config-url\b", "config-url"),
        (r"^failover\b", "failover"),
        (r"^monitor-interface\b", "failover"),
        (r"^management-access\b", "management-access"),
        (r"^same-security-traffic\b", "same-security-traffic"),
        (r"^(?:ssh|http|snmp|logging|dns|dhcpd|dhcprelay|enable|threat-detection|flow-export|monitor-interface)\b", lower.split()[0]),
        (r"^(?:certificate|crypto ca)\b", "certificate/trustpoint"),
    )
    for pattern, path in patterns:
        if re.match(pattern, lower):
            return path
    return "other"


def scan_cisco_asa_sections(text: str) -> list[SourceSectionResult]:
    """Account for each non-comment ASA command and structural object block."""
    sections: list[SourceSectionResult] = []
    current: SourceSectionResult | None = None
    current_path: str | None = None
    block_paths = {
        "interface", "object network", "object network-service", "object service",
        "object-group network", "object-group network-service", "object-group service",
        "object-group protocol", "object-group icmp-type", "object-group user",
        "object-group security", "time-range", "class-map", "policy-map", "route-map",
        "tunnel-group", "group-policy", "aaa-server", "dns", "context",
        "failover", "crypto map", "crypto ikev1 policy", "crypto ikev2 policy",
        "crypto ipsec",
        "vpn address pool",
    }
    for number, raw in enumerate(text.splitlines(), 1):
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
            path=current_path, line_start=number, line_end=number,
            object_count_source=1, status=ExtractionStatus.UNSUPPORTED,
        )
        sections.append(current)
        if current_path not in block_paths:
            current = None
            current_path = None
    return sections
