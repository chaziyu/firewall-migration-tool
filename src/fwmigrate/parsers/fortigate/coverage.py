"""Central FortiGate source-section extraction coverage registry."""

from __future__ import annotations

from typing import Callable, Optional

from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.fortigate.model import FGConfig
from fwmigrate.parsers.fortigate.source_tree import (
    STRUCTURED_OPERATIONAL_SECTIONS,
    STRUCTURED_ROUTING_SECTIONS,
    STRUCTURED_SECURITY_SECTIONS,
)


SYSTEM_BEHAVIOUR_PREFIXES = (
    "system ha",
    "system physical-switch",
    "system ike",
    "system settings",
    "firewall ssh setting",
)

MANAGEMENT_LOGGING_PREFIXES = (
    "log",
    "system snmp",
    "system fortiguard",
    "system ntp",
    "system email-server",
)

MISC_OPERATIONAL_PREFIXES = (
    "system auto-install",
    "system autoupdate",
    "system federated-upgrade",
    "system ftm-push",
    "system object-tagging",
    "system custom-language",
    "system replacemsg-image",
    "system quarantine",
    "system search-engine",
    "system threat-weight",
)

def is_interface_nested_source_path(
    path: str,
) -> bool:
    return (
        path.startswith(
            "system interface "
        )
        and path
        != "system interface secondaryip"
    )

def _matches_source_prefix(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == prefix or path.startswith(f"{prefix} ") for prefix in prefixes)


def fortigate_source_category(path: str) -> str:
    """Classify source-only FortiGate configuration without inferring semantics."""
    if _matches_source_prefix(path, tuple(STRUCTURED_OPERATIONAL_SECTIONS)):
        return "Automation"
    if _matches_source_prefix(path, MANAGEMENT_LOGGING_PREFIXES):
        return "Management / Logging"
    if _matches_source_prefix(path, SYSTEM_BEHAVIOUR_PREFIXES):
        return "System Behaviour"
    return "Other Operational"


def is_operational_source_path(path: str) -> bool:
    return (
        _matches_source_prefix(path, tuple(STRUCTURED_OPERATIONAL_SECTIONS))
        or _matches_source_prefix(path, SYSTEM_BEHAVIOUR_PREFIXES)
        or _matches_source_prefix(path, MANAGEMENT_LOGGING_PREFIXES)
        or _matches_source_prefix(path, MISC_OPERATIONAL_PREFIXES)
    )


TYPED_SECTIONS = {
    "system global",
    "system dns",
    "system interface",
    "system interface secondaryip",
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
    "firewall schedule onetime",
    "firewall shaper traffic-shaper",
    "firewall proxy-address",
    "web-proxy global",
    "firewall policy",
    "firewall ippool",
    "firewall ippool6",
    "firewall vip",
    "firewall vip realservers",
    "firewall vip6",
    "firewall vip6 realservers",
    "firewall vipgrp",
    "firewall vipgrp6",
    "firewall internet-service-name",
    "firewall internet-service-definition",
    "firewall internet-service-definition entry",
    "firewall internet-service-definition entry port-range",
    "vpn ipsec phase1-interface",
    "vpn ipsec phase2-interface",
    "vpn certificate remote",
    "vpn certificate local",
    "vpn certificate ca",
    "firewall ssh local-key",
    "firewall ssh local-ca",
    "router static",
    "system session-helper",
    "system session-ttl",
    "system session-ttl port",
    "endpoint-control fctems",
    "system sdwan",
    "system sdwan zone",
    "system sdwan members",
    "system sdwan health-check",
    "system sdwan health-check sla",
    "system sdwan service",
    "user ldap",
    "user fsso",
    "user adgrp",
    "user saml",
    "user local",
    "user group",
    "user group match",
    "system admin",
    "system accprofile",
    "user fortitoken",
    "vpn ssl web portal",
    "vpn ssl web portal host-check-software",
    "vpn ssl settings",
    "vpn ssl settings authentication-rule",
    "firewall DoS-policy",
    "firewall DoS-policy anomaly",
    "firewall sniffer",
    "authentication scheme",
    "authentication rule",
    "ips sensor",
    "ips sensor entries",
    "firewall internet-service-definition",
    "firewall internet-service-definition entry",
    "firewall internet-service-definition entry port-range",
}

TYPED_EXTRACT_ONLY_SECTIONS = {
    "firewall service category",
    "firewall internet-service-definition",
    "firewall internet-service-definition entry",
    "firewall internet-service-definition entry port-range",
    "vpn certificate remote",
    "vpn certificate local",
    "vpn certificate ca",
    "firewall ssh local-key",
    "firewall ssh local-ca",
    "system session-helper",
    "system session-ttl",
    "system session-ttl port",
    "firewall proxy-address",
    "web-proxy global",
    "firewall vipgrp",
    "firewall ippool6",
    "firewall vip6",
    "firewall vip6 realservers",
    "firewall vipgrp6",
    "system sdwan",
    "system sdwan zone",
    "system sdwan members",
    "system sdwan health-check",
    "system sdwan health-check sla",
    "system sdwan service",
    "user ldap",
    "user fsso",
    "user adgrp",
    "user saml",
    "user local",
    "user group",
    "user group match",
    "system admin",
    "system accprofile",
    "user fortitoken",
    "vpn ssl web portal",
    "vpn ssl web portal host-check-software",
    "vpn ssl settings",
    "vpn ssl settings authentication-rule",
    "firewall DoS-policy",
    "firewall DoS-policy anomaly",
    "firewall sniffer",
    "authentication scheme",
    "authentication rule",
    "ips sensor",
    "ips sensor entries",
}

TYPED_PARTIAL_SECTIONS = {
    "firewall shaper traffic-shaper",
    "vpn ipsec phase1-interface",
    "vpn ipsec phase2-interface",
}

MANUAL_REVIEW_EXTRACT_ONLY_SECTIONS = {
    "firewall vipgrp",
    "firewall ippool6",
    "firewall vip6",
    "firewall vip6 realservers",
    "firewall vipgrp6",
    "firewall proxy-address",
    "web-proxy global",
    "user ldap",
    "user fsso",
    "user adgrp",
    "user saml",
    "user local",
    "user group",
    "system admin",
    "system accprofile",
    "user fortitoken",
    "vpn ssl web portal",
    "vpn ssl settings",
    "firewall DoS-policy",
    "firewall sniffer",
    "authentication scheme",
    "authentication rule",
    "firewall ssh local-key",
    "firewall ssh local-ca",
}


def extract_only_requires_manual_review(path: str) -> bool:
    return (
        path in MANUAL_REVIEW_EXTRACT_ONLY_SECTIONS
        or is_operational_source_path(path)
        or path.startswith("system sdwan")
        or any(path == parent or path.startswith(f"{parent} ") for parent in STRUCTURED_ROUTING_SECTIONS)
        or any(path == parent or path.startswith(f"{parent} ") for parent in STRUCTURED_SECURITY_SECTIONS)
    )

EXTRACT_ONLY_SECTIONS = {
    "application custom",
    "application list",
    "antivirus profile",
    "webfilter profile",
    "dnsfilter profile",
    "file-filter profile",
    "emailfilter profile",
    "dlp profile",
    "firewall ssl-ssh-profile",
}

IGNORED_PREFIXES = {
    "system replacemsg": "FortiGate replacement-message configuration is outside current firewall migration scope.",
    "switch-controller": "FortiSwitch configuration is outside firewall migration scope.",
    "wireless-controller": "FortiAP/wireless-controller configuration is outside firewall migration scope.",
}


def _address_filter(path: str) -> Callable[[object], bool]:
    expected_ipv6 = path.endswith("address6")
    expected_multicast = "multicast-" in path
    return lambda item: (
        bool(getattr(item, "is_ipv6", False)) == expected_ipv6
        and bool(getattr(item, "is_multicast", False)) == expected_multicast
    )


_COLLECTIONS: dict[str, tuple[str, str]] = {
    "system global": ("system_global", "system_settings"),
    "system dns": ("dns", "dns_settings"),
    "system interface": ("interfaces", "interfaces"),
    "system interface secondaryip": ("interfaces", "interfaces"),
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
    "firewall schedule onetime": ("schedules", "schedules"),
    "firewall shaper traffic-shaper": ("traffic_shapers", "traffic_shapers"),
    "firewall proxy-address": ("proxy_addresses", "proxy_addresses"),
    "web-proxy global": ("web_proxy_global", "web_proxy_settings"),
    "firewall policy": ("policies", "policies"),
    "firewall ippool": ("ip_pools", "ip_pools"),
    "firewall ippool6": ("ip_pools6", "ip_pools"),
    "firewall vip": ("vips", "virtual_ips"),
    "firewall vip realservers": ("vips", "virtual_ips"),
    "firewall vip6": ("vips6", "virtual_ips"),
    "firewall vip6 realservers": ("vips6", "virtual_ips"),
    "firewall vipgrp": ("vip_groups", "virtual_ip_groups"),
    "firewall vipgrp6": ("vip_groups6", "virtual_ip_groups"),
    "vpn ipsec phase1-interface": ("phase1_interfaces", "vpn_tunnels"),
    "vpn ipsec phase2-interface": ("phase2_interfaces", "vpn_phase2"),
    "vpn certificate remote": ("certificates", "certificates"),
    "vpn certificate local": ("certificates", "certificates"),
    "vpn certificate ca": ("certificates", "certificates"),
    "firewall ssh local-key": ("ssh_keys", "ssh_keys"),
    "firewall ssh local-ca": ("ssh_keys", "ssh_keys"),
    "router static": ("static_routes", "routes"),
    "system session-helper": ("session_helpers", "session_helpers"),
    "system session-ttl port": ("session_ttl_overrides", "session_ttl_overrides"),
    "endpoint-control fctems": ("fctems_connectors", "ztna_providers"),
    "firewall internet-service-name": ("internet_services", "internet_services"),
    "firewall internet-service-definition": (
        "internet_service_definitions", "internet_service_definitions"
    ),
    "firewall internet-service-definition entry": (
        "internet_service_definitions", "internet_service_definitions"
    ),
    "firewall internet-service-definition entry port-range": (
        "internet_service_definitions", "internet_service_definitions"
    ),
    "system sdwan zone": ("sdwan", "sdwan"),
    "system sdwan members": ("sdwan", "sdwan"),
    "system sdwan": ("sdwan", "sdwan"),
    "system sdwan health-check": ("sdwan", "sdwan"),
    "system sdwan health-check sla": ("sdwan", "sdwan"),
    "system sdwan service": ("sdwan", "sdwan"),
    "user ldap": ("user_ldap_servers", "user_ldap_servers"),
    "user fsso": ("fsso_servers", "fsso_providers"),
    "user adgrp": ("ad_groups", "fsso_ad_groups"),
    "user saml": ("user_saml_servers", "user_saml_servers"),
    "user local": ("local_users", "local_users"),
    "user group": ("user_groups", "user_groups"),
    "user group match": ("user_groups", "user_groups"),
    "system admin": ("administrators", "administrators"),
    "system accprofile": ("admin_profiles", "admin_profiles"),
    "user fortitoken": ("fortitokens", "fortitokens"),
    "vpn ssl web portal": ("ssl_vpn_portals", "ssl_vpn_portals"),
    "vpn ssl web portal host-check-software": ("ssl_vpn_portals", "ssl_vpn_portals"),
    "vpn ssl settings": ("ssl_vpn_settings", "ssl_vpn_settings"),
    "vpn ssl settings authentication-rule": ("ssl_vpn_settings", "ssl_vpn_settings"),
    "firewall DoS-policy": ("dos_policies", "dos_policies"),
    "firewall DoS-policy anomaly": ("dos_policies", "dos_policies"),
    "firewall sniffer": ("firewall_sniffers", "firewall_sniffers"),
    "authentication scheme": ("authentication_schemes", "authentication_schemes"),
    "authentication rule": ("authentication_rules", "authentication_rules"),
    "ips sensor": ("ips_sensors", "ips_sensors"),
    "ips sensor entries": ("ips_sensors", "ips_sensors"),
}


def _count_collection(
    model: object,
    attribute: str,
    path: str,
) -> Optional[int]:
    collection = getattr(model, attribute, None)
    if collection is None:
        return None
    if not isinstance(model, FGConfig):
        if path in {"firewall ippool", "firewall ippool6"}:
            family = "ipv6" if path.endswith("6") else "ipv4"
            return sum(item.address_family == family for item in collection)
        if path in {"firewall vip", "firewall vip6"}:
            family = "ipv6" if path.endswith("6") else "ipv4"
            return sum(item.address_family == family for item in collection)
        if path in {"firewall vipgrp", "firewall vipgrp6"}:
            family = "ipv6" if path.endswith("6") else "ipv4"
            return sum(item.address_family == family for item in collection)
    if path in {"system global", "system dns"}:
        return 1
    if path == "ips sensor":
        return len(collection)
    if path == "ips sensor entries":
        return sum(len(sensor.entries) for sensor in collection)
    if path == "firewall internet-service-definition entry":
        return sum(len(definition.entries) for definition in collection)
    if path == "firewall internet-service-definition entry port-range":
        return sum(
            len(entry.port_ranges)
            for definition in collection
            for entry in definition.entries
        )
    if path == "web-proxy global":
        return 1
    if path == "system sdwan":
        return 1
    if path == "system sdwan health-check":
        return len(collection.health_checks)
    if path == "system sdwan health-check sla":
        return sum(len(item.sla) for item in collection.health_checks)
    if path == "system sdwan service":
        child = "services" if isinstance(model, FGConfig) else "rules"
        return len(getattr(collection, child))
    if path == "user group match":
        child = "match" if isinstance(model, FGConfig) else "matches"
        return sum(len(getattr(item, child)) for item in collection)
    if path == "vpn ssl settings":
        return 1
    if path == "vpn ssl settings authentication-rule":
        return len(collection.authentication_rules)
    if path == "vpn ssl web portal host-check-software":
        child = "host_checks"
        return sum(len(getattr(item, child)) for item in collection)
    if path == "firewall DoS-policy anomaly":
        return sum(len(item.anomalies) for item in collection)
    if path in {
        "firewall schedule recurring",
        "firewall schedule onetime",
    }:
        schedule_type = path.rsplit(" ", 1)[-1]
        return sum(
            1 for item in collection
            if getattr(item, "schedule_type", getattr(item, "type", None)) == schedule_type
        )
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
    if path.startswith("firewall ssh "):
        key_type = path.rsplit(" ", 1)[-1]
        return sum(
            1 for item in collection
            if getattr(item, "key_type", None) == key_type
        )
    if path in {"firewall vip realservers", "firewall vip6 realservers"}:
        child_attribute = "realservers" if isinstance(model, FGConfig) else "real_servers"
        family = "ipv6" if path.startswith("firewall vip6") else "ipv4"
        return sum(
            len(getattr(item, child_attribute))
            for item in collection
            if isinstance(model, FGConfig)
            or getattr(item, "address_family", "ipv4") == family
        )
    if path == "system dhcp server ip-range":
        return sum(len(item.ip_ranges) for item in collection)
    if path == "system dhcp server reserved-address":
        child_attribute = "reserved_addresses" if isinstance(model, FGConfig) else "reservations"
        return sum(len(getattr(item, child_attribute)) for item in collection)
    if path == "system interface secondaryip":
        return sum(len(intf.secondary_ips) for intf in collection)
    return len(collection)


def classify_section_coverage(
    source_sections: list[SourceSectionResult],
    fg_config: FGConfig,
    ir_config: IRConfig,
) -> None:
    """Correlate source discovery, typed parsing, and canonical normalization."""
    for section in source_sections:
        path = section.path
        structured_sections = (
            STRUCTURED_SECURITY_SECTIONS
            | STRUCTURED_ROUTING_SECTIONS
            | STRUCTURED_OPERATIONAL_SECTIONS
        )
        if path in structured_sections or any(
            path.startswith(f"{parent} ") for parent in structured_sections
        ):
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "FortiGateParser.parse_source_node"
            section.notes.append(
                "Recursive source command structure is retained for inventory and manual review."
            )
            continue
        if is_operational_source_path(path):
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "source inventory"
            section.notes.append(
                "Sanitized operational configuration is retained as source-only inventory."
            )
            continue
        if path in EXTRACT_ONLY_SECTIONS:
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "source inventory"
            section.notes.append(
                "Section is retained as source inventory and is not canonical migration IR."
            )
            continue

        ignored_reason = next(
            (
                reason
                for prefix, reason in IGNORED_PREFIXES.items()
                if path == prefix or path.startswith(f"{prefix} ")
            ),
            None,
        )
        if ignored_reason:
            section.status = ExtractionStatus.IGNORED_BY_POLICY
            section.notes.append(ignored_reason)
            continue

        if is_interface_nested_source_path(
            path
        ):
            section.status = (
                ExtractionStatus.EXTRACT_ONLY
            )
            section.parser_handler = (
                "FortiGateParser.parse_source_node"
            )
            section.notes.append(
                "Nested interface configuration is "
                "retained recursively under its parent "
                "interface as sanitized extraction-only "
                "source data."
            )
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

        if path in TYPED_PARTIAL_SECTIONS:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            if path == "vpn ipsec phase1-interface":
                section.notes.append(
                    "Typed Phase 1 source values are retained, but source-specific "
                    "IKE semantics require target-specific migration review."
                )
            elif path == "vpn ipsec phase2-interface":
                section.notes.append(
                    "Typed Phase 2 source values are retained, but the complete "
                    "cross-vendor IPsec model is not yet implemented."
                )
            else:
                section.notes.append(
                    "Typed source values are retained, but exact target QoS behavior is vendor-specific."
                )
            continue

        source_count = section.object_count_source
        parsed_count = section.object_count_parsed
        normalized_count = section.object_count_normalized

        if path == "router static":
            partial_routes = [
                route
                for route in ir_config.routes
                if (
                    route.requires_manual_review
                    or route.parse_error is not None
                    or route.migration_status != "NORMALIZED"
                )
            ]
            if partial_routes:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                parse_error_count = sum(
                    route.parse_error is not None
                    for route in partial_routes
                )
                if parse_error_count:
                    section.notes.append(
                        f"{parse_error_count} static route(s) contained invalid "
                        "destination/netmask syntax and require manual review."
                    )
                section.notes.append(
                    "One or more static routes contain unmodeled or invalid "
                    "source semantics."
                )
                continue

        if path in {
            "firewall address",
            "firewall address6",
            "firewall multicast-address",
            "firewall multicast-address6",
        }:
            address_matches = _address_filter(path)
            parse_error_count = sum(
                address.parse_error is not None and address_matches(address)
                for address in ir_config.addresses
            )
            if parse_error_count:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                section.notes.append(
                    f"{parse_error_count} address object(s) contained invalid "
                    "network syntax and require manual review."
                )
                continue

        if path == "system interface":
            parse_error_count = sum(
                bool(interface.parse_errors)
                for interface in ir_config.interfaces
            )

            nested_config_count = sum(
                len(
                    interface.nested_source_configs
                )
                for interface in ir_config.interfaces
            )

            if parse_error_count:
                section.status = (
                    ExtractionStatus.PARTIALLY_NORMALIZED
                )
                section.notes.append(
                    f"{parse_error_count} interface(s) "
                    "contained invalid IP syntax and "
                    "require manual review."
                )

            if nested_config_count:
                section.status = (
                    ExtractionStatus.PARTIALLY_NORMALIZED
                )
                section.notes.append(
                    f"{nested_config_count} nested "
                    "interface configuration block(s) "
                    "were retained as extraction-only "
                    "source data and are not yet "
                    "normalized into portable IR."
                )

            if (
                parse_error_count
                or nested_config_count
            ):
                continue

        if path == "firewall ippool":
            partial_pools = [
                pool for pool in ir_config.ip_pools
                if pool.address_family == "ipv4" and pool.requires_manual_review
            ]
            if partial_pools:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                section.notes.append(
                    "One or more IP pools retain advanced NAT semantics requiring manual review."
                )
                continue

        if path in {"firewall vip", "firewall vip realservers"}:
            partial_vips = [
                vip for vip in ir_config.virtual_ips
                if vip.address_family == "ipv4" and vip.requires_manual_review
            ]
            if partial_vips:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                section.notes.append(
                    "One or more VIPs retain advanced translation or real-server semantics requiring manual review."
                )
                continue

        if path == "system interface secondaryip":
            partial_items = [
                sec
                for interface in ir_config.interfaces
                for sec in interface.secondary_ips
                if sec.parse_error is not None or sec.requires_manual_review
            ]
            if partial_items:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                parse_errors = sum(1 for s in partial_items if s.parse_error is not None)
                if parse_errors:
                    section.notes.append(
                        f"{parse_errors} secondary interface IP(s) contained missing "
                        "or invalid IP/netmask values and require manual review."
                    )
                if any(s.source_attributes for s in partial_items):
                    section.notes.append(
                        "One or more secondary interface IPs contain unmodeled source settings."
                    )
                section.notes.append(
                    "One or more secondary interface IPs require manual review."
                )
                continue

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
