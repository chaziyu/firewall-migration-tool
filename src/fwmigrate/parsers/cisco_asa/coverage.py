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
    "access-group",
}
MPF_PARTIAL = {"class-map", "policy-map", "service-policy", "tcp-map"}
CONNECTION_CONTROL_PARTIAL = {"conn", "timeout", "threat-detection"}
DHCP_DNS_PARTIAL = {"dhcpd", "dhcprelay", "dns"}
SYSTEM_MANAGEMENT_PARTIAL = {"domain-name", "timezone", "management-access", "same-security-traffic", "ssh", "http", "telnet", "snmp", "logging", "ntp", "enable", "failover"}
EXTRACT_ONLY = {
    "crypto ipsec", "crypto map", "tunnel-group", "group-policy",
    "aaa-server",
    "failover", "aaa", "username",
    "management-access", "same-security-traffic", "ssh", "http", "snmp", "logging",
    "dns", "dhcpd", "dhcprelay", "enable", "threat-detection", "flow-export", "certificate/trustpoint",
}
AAA_PARTIAL = {"aaa-server", "aaa", "username"}


def classify_cisco_asa_coverage(sections: list[SourceSectionResult]) -> None:
    for section in sections:
        if section.path in NORMALIZED:
            section.status = ExtractionStatus.NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
        elif section.path in PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("Portable semantics are normalized where proven; source-only details remain for review.")
        elif section.path in MPF_PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("MPF class, policy and attachment semantics are structured where verified; unsupported inspection/action parameters remain source-preserved.")
        elif section.path in CONNECTION_CONTROL_PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("Connection-control and DoS semantics are structured where verified; unsupported variants remain source-preserved.")
        elif section.path in DHCP_DNS_PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("DHCP and DNS semantics are structured where verified; platform-specific options and unresolved interface/group dependencies remain source-preserved.")
        elif section.path in {"crypto ikev1 policy", "crypto ikev2 policy", "crypto ipsec", "crypto map", "tunnel-group", "group-policy"}:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("VPN semantics are structured where syntax is verified; unresolved references remain for review.")
        elif section.path in AAA_PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("AAA semantics are structured where verified; credentials are redacted and protocol-specific unsupported fields remain source-preserved.")
        elif section.path in SYSTEM_MANAGEMENT_PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("System and management-plane semantics are structured where verified; credentials and community values are redacted and platform-specific options remain source-preserved.")
        elif section.path in EXTRACT_ONLY:
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "Cisco ASA source inventory"
        else:
            section.status = ExtractionStatus.UNSUPPORTED
            section.notes.append("No safe canonical Cisco ASA mapping is implemented.")
