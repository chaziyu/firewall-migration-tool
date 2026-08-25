"""Central FortiGate source-section extraction coverage registry."""

from __future__ import annotations

from typing import Callable, Optional

from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.fortigate.model import FGConfig


TYPED_SECTIONS = {
    "system interface",
    "system zone",
    "system dhcp server",
    "system dhcp server ip-range",
    "system dhcp server reserved-address",
    "firewall address",
    "firewall address6",
    "firewall multicast-address",
    "firewall multicast-address6",
    "firewall addrgrp",
    "firewall wildcard-fqdn custom",
    "firewall service category",
    "firewall service custom",
    "firewall service group",
    "firewall schedule recurring",
    "firewall policy",
    "firewall ippool",
    "firewall vip",
    "firewall vip realservers",
    "firewall vipgrp",
    "firewall internet-service-name",
    "vpn ipsec phase1-interface",
    "vpn ipsec phase2-interface",
    "vpn certificate remote",
    "vpn certificate local",
    "router static",
    "system session-helper",
    "system session-ttl",
    "system session-ttl port",
    "endpoint-control fctems",
    "system sdwan",
    "system sdwan zone",
    "system sdwan members",
}

TYPED_EXTRACT_ONLY_SECTIONS = {
    "firewall service category",
    "vpn certificate remote",
    "vpn certificate local",
    "system session-helper",
    "system session-ttl",
    "system session-ttl port",
}

EXTRACT_ONLY_SECTIONS = {
    "ips sensor",
    "firewall shaper traffic-shaper",
    "firewall proxy-address",
    "web-proxy global",
    "application custom",
    "application list",
    "antivirus profile",
    "webfilter profile",
    "dnsfilter profile",
    "file-filter profile",
    "emailfilter profile",
    "dlp profile",
    "firewall ssl-ssh-profile",
    "user ldap",
    "user saml",
    "user fsso",
    "user local",
    "user group",
    "vpn ssl web portal",
    "vpn ssl settings",
    "firewall DoS-policy",
    "firewall sniffer",
    "router ospf",
    "router ospf6",
    "router bgp",
    "router isis",
}

IGNORED_PREFIXES = {
    "system replacemsg ",
    "switch-controller ",
    "wireless-controller ",
}


def _address_filter(path: str) -> Callable[[object], bool]:
    expected_ipv6 = path.endswith("address6")
    expected_multicast = "multicast-" in path
    return lambda item: (
        bool(getattr(item, "is_ipv6", False)) == expected_ipv6
        and bool(getattr(item, "is_multicast", False)) == expected_multicast
    )


_COLLECTIONS: dict[str, tuple[str, str]] = {
    "system interface": ("interfaces", "interfaces"),
    "system zone": ("system_zones", "zones"),
    "system dhcp server": ("dhcp_servers", "dhcp_servers"),
    "system dhcp server ip-range": ("dhcp_servers", "dhcp_servers"),
    "system dhcp server reserved-address": ("dhcp_servers", "dhcp_servers"),
    "firewall address": ("addresses", "addresses"),
    "firewall address6": ("addresses", "addresses"),
    "firewall multicast-address": ("addresses", "addresses"),
    "firewall multicast-address6": ("addresses", "addresses"),
    "firewall addrgrp": ("address_groups", "address_groups"),
    "firewall wildcard-fqdn custom": ("wildcard_fqdns", "addresses"),
    "firewall service category": ("service_categories", "service_categories"),
    "firewall service custom": ("services", "services"),
    "firewall service group": ("service_groups", "service_groups"),
    "firewall schedule recurring": ("schedules", "schedules"),
    "firewall policy": ("policies", "policies"),
    "firewall ippool": ("ip_pools", "ip_pools"),
    "firewall vip": ("vips", "virtual_ips"),
    "firewall vip realservers": ("vips", "virtual_ips"),
    "firewall vipgrp": ("vip_groups", "nat_rules"),
    "vpn ipsec phase1-interface": ("phase1_interfaces", "vpn_tunnels"),
    "vpn ipsec phase2-interface": ("phase2_interfaces", "_not_countable"),
    "vpn certificate remote": ("certificates", "certificates"),
    "vpn certificate local": ("certificates", "certificates"),
    "router static": ("static_routes", "routes"),
    "system session-helper": ("session_helpers", "session_helpers"),
    "system session-ttl port": ("session_ttl_overrides", "session_ttl_overrides"),
    "endpoint-control fctems": ("fctems_connectors", "ztna_providers"),
    "firewall internet-service-name": ("internet_services", "internet_services"),
    "system sdwan zone": ("sdwan", "_not_countable"),
    "system sdwan members": ("sdwan", "_not_countable"),
}


def _count_collection(
    model: object,
    attribute: str,
    path: str,
) -> Optional[int]:
    collection = getattr(model, attribute, None)
    if collection is None:
        return None
    if path == "system sdwan zone":
        return len(collection.zones)
    if path == "system sdwan members":
        return len(collection.members)
    if path.startswith("firewall ") and "address" in path and attribute == "addresses":
        predicate = _address_filter(path)
        return sum(1 for item in collection if predicate(item))
    if path.startswith("vpn certificate "):
        certificate_type = path.rsplit(" ", 1)[-1]
        return sum(
            1 for item in collection
            if getattr(item, "certificate_type", None) == certificate_type
        )
    if path == "firewall vip realservers":
        child_attribute = "realservers" if isinstance(model, FGConfig) else "real_servers"
        return sum(len(getattr(item, child_attribute)) for item in collection)
    if path == "system dhcp server ip-range":
        return sum(len(item.ip_ranges) for item in collection)
    if path == "system dhcp server reserved-address":
        child_attribute = "reserved_addresses" if isinstance(model, FGConfig) else "reservations"
        return sum(len(getattr(item, child_attribute)) for item in collection)
    return len(collection)


def classify_section_coverage(
    source_sections: list[SourceSectionResult],
    fg_config: FGConfig,
    ir_config: IRConfig,
) -> None:
    """Correlate source discovery, typed parsing, and canonical normalization."""
    for section in source_sections:
        path = section.path
        if path in EXTRACT_ONLY_SECTIONS:
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "source inventory"
            section.notes.append(
                "Section is retained as source inventory and is not canonical migration IR."
            )
            continue

        if any(path.startswith(prefix) for prefix in IGNORED_PREFIXES):
            section.status = ExtractionStatus.IGNORED_BY_POLICY
            section.notes.append("Section is deliberately excluded by the coverage policy.")
            continue

        if path not in TYPED_SECTIONS:
            section.status = ExtractionStatus.UNSUPPORTED
            section.notes.append("No typed FortiGate extraction handler is registered.")
            continue

        section.parser_handler = "FortiGateParser.build_model"
        mapping = _COLLECTIONS.get(path)
        if mapping is None:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.notes.append(
                "Typed parsing exists, but an exact section-level normalization count is not reliable."
            )
            continue

        fg_attribute, ir_attribute = mapping
        section.object_count_parsed = _count_collection(fg_config, fg_attribute, path)
        section.object_count_normalized = _count_collection(ir_config, ir_attribute, path)

        if path in TYPED_EXTRACT_ONLY_SECTIONS:
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.notes.append(
                "Typed source inventory is retained, but this section is not portable migration intent."
            )
            continue

        source_count = section.object_count_source
        parsed_count = section.object_count_parsed
        normalized_count = section.object_count_normalized
        if (
            source_count is not None
            and parsed_count == source_count
            and normalized_count == source_count
        ):
            section.status = ExtractionStatus.NORMALIZED
        else:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.notes.append(
                "Source, parsed, and normalized counts do not prove complete one-to-one normalization."
            )
