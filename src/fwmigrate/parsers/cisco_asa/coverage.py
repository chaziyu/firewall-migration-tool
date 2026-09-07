from __future__ import annotations

from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult


NORMALIZED = {"system hostname"}
PARTIAL = {
    "interface", "object network", "object service", "object-group network",
    "object-group service", "access-list", "access-group", "nat object",
    "nat manual", "route", "ipv6 route", "route-map", "policy-route", "time-range",
    "object network-service", "object-group network-service", "object-group protocol",
    "object-group icmp-type", "object-group user", "object-group security",
}
MPF_PARTIAL = {"class-map", "policy-map", "service-policy", "tcp-map"}
TYPED_INSPECTION_PARTIAL = {"class-map type inspect", "policy-map type inspect"}
CONNECTION_CONTROL_PARTIAL = {"conn", "timeout", "threat-detection"}
DHCP_DNS_PARTIAL = {"dhcpd", "dhcprelay", "dns"}
SYSTEM_MANAGEMENT_PARTIAL = {
    "domain-name", "timezone", "management-access", "same-security-traffic",
    "ssh", "http", "telnet", "snmp", "logging", "ntp", "enable", "failover",
}
CONTEXT_PARTIAL = {"context", "admin-context", "allocate-interface", "config-url", "resource-class"}
EXTRACT_ONLY = {
    "flow-export", "certificate/trustpoint", "dynamic-routing", "sla-monitor",
}
VPN_PARTIAL = {
    "crypto ikev1 policy", "crypto ikev2 policy", "crypto ipsec", "crypto map",
    "tunnel-group", "group-policy",
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
        elif section.path in TYPED_INSPECTION_PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("Typed inspection header and nested application hierarchy are preserved; target support is evaluated separately from ASA extraction.")
        elif section.path in CONNECTION_CONTROL_PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("Connection-control and threat-detection semantics are structured only for verified ASA command families; unverified variants remain source-preserved.")
        elif section.path in DHCP_DNS_PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("DHCP and DNS semantics are structured where verified; interface/group ownership and source order are retained.")
        elif section.path in VPN_PARTIAL:
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
            section.notes.append("System and management-plane semantics are structured where verified; credentials/community values are not exposed.")
        elif section.path in CONTEXT_PARTIAL:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.parser_handler = "CiscoASAParser.parse_raw"
            section.notes.append("System-space context definitions and per-context ownership are kept separate; unresolved allocations remain reviewable.")
        elif section.path in EXTRACT_ONLY:
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "Cisco ASA source inventory"
            if section.path == "certificate/trustpoint":
                section.notes.append("Trustpoint metadata is structured for inventory/reference validation; certificate/key material is not emitted.")
        else:
            section.status = ExtractionStatus.UNSUPPORTED
            section.notes.append("No safe canonical Cisco ASA mapping is implemented.")
