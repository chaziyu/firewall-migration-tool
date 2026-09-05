from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult


NORMALIZED = {"system hostname"}
PARTIAL = {
    "interface", "object network", "object service", "object-group network",
    "object-group service", "access-list", "access-group", "nat object",
    "nat manual", "route",
    "ipv6 route", "route-map", "policy-route", "time-range", "object network-service",
    "object-group network-service", "object-group protocol", "object-group icmp-type",
    "object-group user", "object-group security",
}
EXTRACT_ONLY = {
    "class-map", "policy-map", "service-policy", "failover", "aaa", "username",
    "management-access", "same-security-traffic", "ssh", "http", "snmp", "logging",
    "dns", "dhcp", "enable", "threat-detection", "flow-export", "certificate/trustpoint",
}


def classify_cisco_asa_coverage(sections: list[SourceSectionResult]) -> None:
    for section in sections:
        if section.path in NORMALIZED:
            section.status = ExtractionStatus.NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
        elif section.path in PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("Portable semantics are normalized where proven; source-only details remain for review.")
        elif section.path in EXTRACT_ONLY:
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "Cisco ASA source inventory"
        else:
            section.status = ExtractionStatus.UNSUPPORTED
            section.notes.append("No safe canonical Cisco ASA mapping is implemented.")
