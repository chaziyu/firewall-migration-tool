"""Central FortiGate source-section extraction coverage registry."""

from __future__ import annotations

from typing import Any, Callable, Optional

from fwmigrate.extraction.models import ExtractionStatus, SourceSectionResult
from fwmigrate.ir.core import IRConfig
from fwmigrate.parsers.fortigate.model import FGConfig
from fwmigrate.parsers.fortigate.source_tree import (
    STRUCTURED_OPERATIONAL_SECTIONS,
    STRUCTURED_IDENTITY_SECTIONS,
    STRUCTURED_ROUTING_DEPENDENCY_SECTIONS,
    STRUCTURED_ROUTING_SECTIONS,
    STRUCTURED_SECURITY_SECTIONS,
)


SYSTEM_BEHAVIOUR_PREFIXES = (
    "system ha",
    "system physical-switch",
    "system ike",
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
    if _matches_source_prefix(path, tuple(STRUCTURED_ROUTING_DEPENDENCY_SECTIONS)):
        return "Routing Dependency"
    if _matches_source_prefix(path, tuple(STRUCTURED_IDENTITY_SECTIONS)):
        return "Identity / Authentication"
    if _matches_source_prefix(path, MANAGEMENT_LOGGING_PREFIXES):
        return "Management / Logging"
    if path == "system settings" or _matches_source_prefix(path, SYSTEM_BEHAVIOUR_PREFIXES):
        return "System Behaviour"
    return "Other Operational"


def is_operational_source_path(path: str) -> bool:
    return (
        _matches_source_prefix(path, tuple(STRUCTURED_OPERATIONAL_SECTIONS))
        or _matches_source_prefix(path, tuple(STRUCTURED_IDENTITY_SECTIONS))
        or _matches_source_prefix(path, SYSTEM_BEHAVIOUR_PREFIXES)
        or _matches_source_prefix(path, MANAGEMENT_LOGGING_PREFIXES)
        or _matches_source_prefix(path, MISC_OPERATIONAL_PREFIXES)
    )


TYPED_SECTIONS = {
    "vdom",
    "system settings",
    "system global",
    "system dns",
    "system interface",
    "system interface secondaryip",
    "system zone",
    "system zone tagging",
    "system dhcp server",
    "system dhcp server ip-range",
    "system dhcp server exclude-range",
    "system dhcp server reserved-address",
    "system dhcp server options",
    "firewall address",
    "firewall address list",
    "firewall address tagging",
    "firewall address6",
    "firewall address6 tagging",
    "firewall multicast-address",
    "firewall multicast-address tagging",
    "firewall multicast-address6",
    "firewall multicast-address6 tagging",
    "firewall addrgrp",
    "firewall addrgrp tagging",
    "firewall addrgrp6",
    "firewall addrgrp6 tagging",
    "firewall wildcard-fqdn custom",
    "firewall service category",
    "firewall service custom",
    "firewall service group",
    "firewall schedule recurring",
    "firewall schedule onetime",
    "firewall schedule group",
    "firewall shaper traffic-shaper",
    "firewall proxy-address",
    "web-proxy global",
    "firewall policy",
    "firewall security-policy",
    "router policy",
    "router policy6",
    "system dhcp6 server",
    "firewall local-in-policy",
    "firewall local-in-policy6",
    "firewall proxy-policy",
    "firewall proxy-addrgrp",
    "firewall shaping-policy",
    "firewall shaper per-ip-shaper",
    "firewall shaping-profile",
    "vpn ipsec phase1",
    "vpn ipsec phase2",
    "vpn ipsec phase2-interface",
    "vpn ipsec manualkey",
    "firewall wildcard-fqdn group",
    "firewall multicast-policy",
    "firewall multicast-policy6",
    "firewall ttl-policy",
    "firewall ldb-monitor",
    "firewall ssl-server",
    "firewall traffic-class",
    "firewall internet-service-custom",
    "firewall internet-service-custom-group",
    "firewall ippool",
    "firewall vip",
    "firewall vip realservers",
    "firewall vipgrp",
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
    "router static6",
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
    "system sdwan service sla",
    "system sdwan duplication",
    "system sdwan neighbor",
    "user ldap",
    "user radius",
    "user tacacs+",
    "user fsso",
    "user fsso-polling",
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
    "vpn ssl web host-check-software",
    "vpn ssl web host-check-software check-item-list",
    "vpn ssl settings",
    "vpn ssl settings authentication-rule",
    "vpn ssl web portal bookmark-group",
    "vpn ssl web portal bookmark-group bookmarks",
    "vpn ssl web portal bookmark-group bookmarks form-data",
    "vpn ssl web portal landing-page",
    "vpn ssl web portal landing-page form-data",
    "vpn ssl web portal mac-addr-check-rule",
    "vpn ssl web portal os-check-list",
    "vpn ssl web portal split-dns",
    "firewall DoS-policy",
    "firewall DoS-policy6",
    "firewall DoS-policy anomaly",
    "firewall sniffer",
    "authentication scheme",
    "authentication rule",
    "user setting",
    "user quarantine",
    "ips sensor",
    "ips sensor entries",
    "ips sensor entries exempt-ip",
    "firewall acl",
    "firewall acl6",
    "firewall interface-policy",
    "firewall interface-policy6",
    "firewall internet-service-definition",
    "firewall internet-service-definition entry",
    "firewall internet-service-definition entry port-range",
    "firewall central-snat-map",
    "firewall ip-translation",
    "firewall ippool6",
    "firewall vip6",
    "firewall vip6 realservers",
    "firewall vipgrp6",
}

TYPED_EXTRACT_ONLY_SECTIONS = {
    "vdom",
    "system settings",
    "firewall schedule group",
    "router policy",
    "router policy6",
    "system dhcp6 server",
    "system dhcp server",
    "system dhcp server ip-range",
    "system dhcp server exclude-range",
    "system dhcp server reserved-address",
    "system dhcp server options",
    "firewall local-in-policy",
    "firewall local-in-policy6",
    "firewall proxy-policy",
    "firewall proxy-addrgrp",
    "firewall shaper per-ip-shaper",
    "firewall shaping-profile",
    "vpn ipsec phase1",
    "vpn ipsec phase2",
    "vpn ipsec manualkey",
    "firewall wildcard-fqdn group",
    "firewall ttl-policy",
    "firewall ldb-monitor",
    "firewall ssl-server",
    "firewall traffic-class",
    "firewall internet-service-custom",
    "firewall internet-service-custom-group",
    "firewall address list",
    "firewall address tagging",
    "firewall address6 tagging",
    "firewall multicast-address tagging",
    "firewall multicast-address6 tagging",
    "firewall addrgrp tagging",
    "firewall addrgrp6 tagging",
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
    "system sdwan",
    "system sdwan zone",
    "system sdwan members",
    "system sdwan health-check",
    "system sdwan health-check sla",
    "system sdwan service",
    "system sdwan service sla",
    "system sdwan duplication",
    "system sdwan neighbor",
    "user ldap",
    "user radius",
    "user tacacs+",
    "user fsso",
    "user fsso-polling",
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
    "vpn ssl web host-check-software",
    "vpn ssl web host-check-software check-item-list",
    "vpn ssl settings",
    "vpn ssl settings authentication-rule",
    "vpn ssl web portal bookmark-group",
    "vpn ssl web portal bookmark-group bookmarks",
    "vpn ssl web portal bookmark-group bookmarks form-data",
    "vpn ssl web portal landing-page",
    "vpn ssl web portal landing-page form-data",
    "vpn ssl web portal mac-addr-check-rule",
    "vpn ssl web portal os-check-list",
    "vpn ssl web portal split-dns",
    "firewall DoS-policy",
    "firewall DoS-policy6",
    "firewall DoS-policy anomaly",
    "firewall sniffer",
    "authentication scheme",
    "authentication rule",
    "user setting",
    "user quarantine",
    "ips sensor",
    "ips sensor entries",
    "ips sensor entries exempt-ip",
    "firewall acl",
    "firewall acl6",
    "firewall interface-policy",
    "firewall interface-policy6",
}

TYPED_PARTIAL_SECTIONS = {
    "firewall shaper traffic-shaper",
    "firewall security-policy",
    "firewall shaping-policy",
    "vpn ipsec phase1",
    "vpn ipsec phase1-interface",
}

MANUAL_REVIEW_EXTRACT_ONLY_SECTIONS = {
    "firewall vipgrp",
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
    "vpn ssl web host-check-software",
    "vpn ssl web host-check-software check-item-list",
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
        path == "system dhcp server"
        or path.startswith("system dhcp server ")
        or path in MANUAL_REVIEW_EXTRACT_ONLY_SECTIONS
        or path == "system settings"
        or is_operational_source_path(path)
        or path.startswith("system sdwan")
        or any(path == parent or path.startswith(f"{parent} ") for parent in STRUCTURED_ROUTING_SECTIONS)
        or any(path == parent or path.startswith(f"{parent} ") for parent in STRUCTURED_ROUTING_DEPENDENCY_SECTIONS)
        or any(path == parent or path.startswith(f"{parent} ") for parent in STRUCTURED_IDENTITY_SECTIONS)
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
    "system settings": ("execution_contexts", "execution_contexts"),
    "system global": ("system_global", "system_settings"),
    "system dns": ("dns", "dns_settings"),
    "system interface": ("interfaces", "interfaces"),
    "system interface secondaryip": ("interfaces", "interfaces"),
    "system zone": ("system_zones", "zones"),
    "system dhcp server": ("dhcp_servers", "dhcp_servers"),
    "system dhcp server ip-range": ("dhcp_servers", "dhcp_servers"),
    "system dhcp server exclude-range": ("dhcp_servers", "dhcp_servers"),
    "system dhcp server reserved-address": ("dhcp_servers", "dhcp_servers"),
    "system dhcp server options": ("dhcp_servers", "dhcp_servers"),
    "firewall address": ("addresses", "addresses"),
    "firewall address list": ("addresses", "addresses"),
    "firewall address tagging": ("addresses", "addresses"),
    "firewall address6": ("addresses", "addresses"),
    "firewall address6 tagging": ("addresses", "addresses"),
    "firewall multicast-address": ("addresses", "addresses"),
    "firewall multicast-address tagging": ("addresses", "addresses"),
    "firewall multicast-address6": ("addresses", "addresses"),
    "firewall multicast-address6 tagging": ("addresses", "addresses"),
    "firewall addrgrp": ("address_groups", "address_groups"),
    "firewall addrgrp6": ("address_groups", "address_groups"),
    "firewall addrgrp tagging": ("address_groups", "address_groups"),
    "firewall addrgrp6 tagging": ("address_groups", "address_groups"),
    "firewall wildcard-fqdn custom": ("wildcard_fqdns", "addresses"),
    "firewall service category": ("service_categories", "service_categories"),
    "firewall service custom": ("services", "services"),
    "firewall service group": ("service_groups", "service_groups"),
    "firewall schedule recurring": ("schedules", "schedules"),
    "firewall schedule onetime": ("schedules", "schedules"),
    "firewall schedule group": ("schedule_groups", "schedule_groups"),
    "firewall shaper traffic-shaper": ("traffic_shapers", "traffic_shapers"),
    "firewall proxy-address": ("proxy_addresses", "proxy_addresses"),
    "web-proxy global": ("web_proxy_global", "web_proxy_settings"),
    "firewall policy": ("policies", "policies"),
    "firewall central-snat-map": ("central_snat_rules", "nat_rules"),
    "firewall ip-translation": ("ip_translations", "nat_rules"),
    "firewall multicast-policy": ("multicast_policies", "nat_rules"),
    "firewall multicast-policy6": ("multicast_policies6", "nat_rules"),
    "firewall security-policy": ("security_policies", "security_policies"),
    "router policy": ("policy_routes", "policy_routes"),
    "router policy6": ("policy_routes", "policy_routes"),
    "vpn ipsec phase2": ("phase2_policies", "vpn_phase2"),
    "system dhcp6 server": ("dhcp6_servers", "dhcp6_servers"),
    "firewall local-in-policy": ("local_in_policies", "local_in_policies"),
    "firewall local-in-policy6": ("local_in_policies", "local_in_policies"),
    "firewall proxy-policy": ("proxy_policies", "proxy_policies"),
    "firewall shaping-policy": ("shaping_policies", "shaping_policies"),
    "firewall internet-service-custom": ("custom_internet_services", "custom_internet_services"),
    "firewall internet-service-custom-group": ("custom_internet_service_groups", "custom_internet_service_groups"),
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
    "router static6": ("static_routes", "routes"),
    "system session-helper": ("session_helpers", "session_helpers"),
    "system session-ttl": ("session_ttl_settings", "session_ttl_settings"),
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
    "system sdwan service sla": ("sdwan", "sdwan"),
    "system sdwan duplication": ("sdwan", "sdwan"),
    "system sdwan neighbor": ("sdwan", "sdwan"),
    "user ldap": ("user_ldap_servers", "user_ldap_servers"),
    "user radius": ("radius_servers", "user_radius_servers"),
    "user tacacs+": ("tacacs_servers", "user_tacacs_servers"),
    "user fsso": ("fsso_servers", "fsso_providers"),
    "user fsso-polling": ("fsso_polling", "fsso_polling"),
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
    "vpn ssl web host-check-software": (
        "ssl_vpn_host_check_software", "ssl_vpn_host_checks"
    ),
    "vpn ssl web host-check-software check-item-list": (
        "ssl_vpn_host_check_software", "ssl_vpn_host_checks"
    ),
    "vpn ssl settings": ("ssl_vpn_settings", "ssl_vpn_settings"),
    "vpn ssl settings authentication-rule": ("ssl_vpn_settings", "ssl_vpn_settings"),
    "vpn ssl web portal bookmark-group": ("ssl_vpn_portals", "ssl_vpn_portals"),
    "vpn ssl web portal bookmark-group bookmarks": ("ssl_vpn_portals", "ssl_vpn_portals"),
    "vpn ssl web portal bookmark-group bookmarks form-data": ("ssl_vpn_portals", "ssl_vpn_portals"),
    "vpn ssl web portal landing-page": ("ssl_vpn_portals", "ssl_vpn_portals"),
    "vpn ssl web portal landing-page form-data": ("ssl_vpn_portals", "ssl_vpn_portals"),
    "vpn ssl web portal mac-addr-check-rule": ("ssl_vpn_portals", "ssl_vpn_portals"),
    "vpn ssl web portal os-check-list": ("ssl_vpn_portals", "ssl_vpn_portals"),
    "vpn ssl web portal split-dns": ("ssl_vpn_portals", "ssl_vpn_portals"),
    "firewall DoS-policy": ("dos_policies", "dos_policies"),
    "firewall DoS-policy6": ("dos_policies", "dos_policies"),
    "firewall DoS-policy anomaly": ("dos_policies", "dos_policies"),
    "firewall sniffer": ("firewall_sniffers", "firewall_sniffers"),
    "authentication scheme": ("authentication_schemes", "authentication_schemes"),
    "authentication rule": ("authentication_rules", "authentication_rules"),
    "user setting": (
        "user_authentication_settings", "user_authentication_settings"
    ),
    "user quarantine": ("user_quarantine", "user_quarantine_settings"),
    "ips sensor": ("ips_sensors", "ips_sensors"),
    "ips sensor entries": ("ips_sensors", "ips_sensors"),
    "ips sensor entries exempt-ip": ("ips_sensors", "ips_sensors"),
    "firewall acl": ("source_only_rules", "source_only_rules"),
    "firewall acl6": ("source_only_rules", "source_only_rules"),
    "firewall interface-policy": ("source_only_rules", "source_only_rules"),
    "firewall interface-policy6": ("source_only_rules", "source_only_rules"),
}

PROFILE_SUPPORT_LEVELS = {
    "firewall profile-group": "TYPED_EXTRACT_ONLY",
}

SEMANTIC_SUPPORT_LEVELS = {
    "system dhcp server": "TYPED_EXTRACT_ONLY",
    "firewall local-in-policy": "TYPED_EXTRACT_ONLY",
    "firewall local-in-policy6": "TYPED_EXTRACT_ONLY",
    "router policy": "TYPED_EXTRACT_ONLY",
    "router policy6": "TYPED_EXTRACT_ONLY",
    "vpn ipsec phase2": "TYPED_EXTRACT_ONLY",
    "vpn ipsec phase2-interface": "TYPED_EXTRACT_ONLY",
    "user local": "TYPED_EXTRACT_ONLY",
    "user group": "TYPED_EXTRACT_ONLY",
    "user group match": "TYPED_EXTRACT_ONLY",
    "user radius": "TYPED_EXTRACT_ONLY",
    "user tacacs+": "TYPED_EXTRACT_ONLY",
    "ips sensor": "TYPED_EXTRACT_ONLY",
    "ips sensor entries": "TYPED_EXTRACT_ONLY",
    "ips sensor entries exempt-ip": "TYPED_EXTRACT_ONLY",
    **{path: "STRUCTURED_EXTRACT_ONLY" for path in STRUCTURED_SECURITY_SECTIONS},
    "firewall profile-group": "TYPED_EXTRACT_ONLY",
}


def fortigate_semantic_support_level(path: str) -> str:
    matches = [
        level for prefix, level in SEMANTIC_SUPPORT_LEVELS.items()
        if path == prefix or path.startswith(f"{prefix} ")
    ]
    if matches:
        return matches[-1]
    return "NORMALIZED" if path in TYPED_SECTIONS else "UNSUPPORTED"

ADDRESS_OBJECT_SOURCE_SECTIONS = {
    "firewall address",
    "firewall address6",
    "firewall multicast-address",
    "firewall multicast-address6",
}
ADDRESS_GROUP_SOURCE_SECTIONS = {"firewall addrgrp", "firewall addrgrp6"}

SOURCE_ONLY_FAMILY_BY_SECTION = {
    "firewall acl": "acl-ipv4",
    "firewall acl6": "acl-ipv6",
    "firewall interface-policy": "interface-policy-ipv4",
    "firewall interface-policy6": "interface-policy-ipv6",
}

COSMETIC_SOURCE_SETTINGS = {
    "color",
    "comment",
    "comments",
    # Schedule visibility affects presentation/inventory, not the recurring
    # or one-time match window represented by the portable schedule model.
    "visibility",
}


def _semantic_unknown_keys(
    fg_config: FGConfig,
    path: str,
    source_context: Optional[str],
) -> list[str]:
    """Return meaningful source settings not represented by the typed model.

    This is deliberately separate from object counts.  A scalar section with
    one parsed object can still be only partially normalized when important
    FortiOS behavior remains in ``extra_settings``.
    """

    mapping = _COLLECTIONS.get(path)
    if mapping is None:
        return []
    collection = getattr(fg_config, mapping[0], None)
    if collection is None:
        return []
    items = collection if isinstance(collection, list) else [collection]
    keys: set[str] = set()
    for item in items:
        item_context = getattr(item, "source_context", None)
        if source_context is not None and item_context not in {None, source_context}:
            continue
        extras = getattr(item, "extra_settings", {}) or {}
        keys.update(
            str(key) for key in extras
            if str(key).replace("-", "_").lower() not in COSMETIC_SOURCE_SETTINGS
        )
        if path == "system dns":
            # These fields are intentionally explicit in the vendor model,
            # but remain outside portable IRDNSSettings semantics.
            keys.update(
                field.replace("-", "_")
                for field in (
                    "protocol", "server_select_method", "domain",
                    "interface_select_method", "interface", "source_ip",
                    "source_ip6", "ssl_certificate", "timeout", "retry",
                )
                if getattr(item, field, None) is not None
            )
    return sorted(keys)


def _count_ir_source_section(ir_config: IRConfig, path: str) -> int:
    if path in ADDRESS_OBJECT_SOURCE_SECTIONS:
        return sum(item.source_section == path for item in ir_config.addresses) + sum(
            item.source_section == path for item in ir_config.address_groups
        )
    if path == "firewall wildcard-fqdn custom":
        return sum(item.source_section == path for item in ir_config.addresses)
    if path in ADDRESS_GROUP_SOURCE_SECTIONS:
        return sum(item.source_section == path for item in ir_config.address_groups)
    if path == "firewall address list":
        return sum(
            len(item.source_list_entries)
            for item in ir_config.addresses
            if item.source_section == "firewall address"
        )
    if path in {
        "firewall address tagging",
        "firewall address6 tagging",
        "firewall multicast-address tagging",
        "firewall multicast-address6 tagging",
    }:
        parent_path = path.rsplit(" ", 1)[0]
        return sum(
            len(item.source_tagging_entries)
            for item in ir_config.addresses
            if item.source_section == parent_path
        )
    if path in {"firewall addrgrp tagging", "firewall addrgrp6 tagging"}:
        parent_path = path.rsplit(" ", 1)[0]
        return sum(
            len(item.source_tagging_entries)
            for item in ir_config.address_groups
            if item.source_section == parent_path
        )
    raise KeyError(path)


def _count_collection(
    model: object,
    attribute: str,
    path: str,
) -> Optional[int]:
    collection = getattr(model, attribute, None)
    if collection is None:
        return None
    if path in {"router policy", "router policy6"}:
        family = "policy-route-ipv6" if path == "router policy6" else "policy-route-ipv4"
        return sum(
            1 for item in collection
            if getattr(item, "family", None) == family
        )
    if isinstance(model, IRConfig):
        try:
            return _count_ir_source_section(model, path)
        except KeyError:
            pass
    if isinstance(model, FGConfig) and path == "firewall address list":
        return sum(
            len(item.address_list)
            for item in model.addresses
            if not item.is_ipv6 and not item.is_multicast
        )
    if isinstance(model, FGConfig) and path in {
        "firewall address tagging",
        "firewall address6 tagging",
        "firewall multicast-address tagging",
        "firewall multicast-address6 tagging",
    }:
        expected_ipv6 = "address6" in path
        expected_multicast = "multicast-address" in path
        return sum(
            len(item.tagging)
            for item in model.addresses
            if item.is_ipv6 == expected_ipv6
            and item.is_multicast == expected_multicast
        )
    if path in {"firewall addrgrp", "firewall addrgrp6"}:
        expected_ipv6 = path.endswith("6")
        if isinstance(model, FGConfig):
            return sum(bool(item.is_ipv6) == expected_ipv6 for item in collection)
        return sum(item.source_section == path for item in collection)
    if path in {"firewall addrgrp tagging", "firewall addrgrp6 tagging"}:
        expected_ipv6 = "addrgrp6" in path
        if isinstance(model, FGConfig):
            return sum(len(item.tagging) for item in collection if bool(item.is_ipv6) == expected_ipv6)
        return sum(len(item.source_tagging_entries) for item in collection if item.address_family == ("ipv6" if expected_ipv6 else "ipv4"))
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
    if path in {"system global", "system dns", "system session-ttl", "system settings"}:
        return 1
    if path == "ips sensor":
        return len(collection)
    if path == "ips sensor entries":
        return sum(len(sensor.entries) for sensor in collection)
    if path == "ips sensor entries exempt-ip":
        return sum(len(entry.exempt_ips) for sensor in collection for entry in sensor.entries)
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
    if path == "system sdwan service sla":
        child = "services" if isinstance(model, FGConfig) else "rules"
        return sum(len(item.sla) for item in getattr(collection, child))
    if path == "system sdwan duplication":
        return len(collection.duplication_rules)
    if path == "system sdwan neighbor":
        return len(collection.neighbors)
    if path == "user group match":
        child = "match" if isinstance(model, FGConfig) else "matches"
        return sum(len(getattr(item, child)) for item in collection)
    if path == "vpn ssl settings":
        return 1
    if path in {"user setting", "user quarantine"}:
        return 1
    if path == "vpn ssl settings authentication-rule":
        return len(collection.authentication_rules)
    if path == "vpn ssl web portal host-check-software":
        child = "host_checks"
        return sum(len(getattr(item, child)) for item in collection)
    if path == "vpn ssl web portal bookmark-group":
        return sum(len(item.bookmark_groups) for item in collection)
    if path == "vpn ssl web portal bookmark-group bookmarks":
        return sum(len(group.bookmarks) for item in collection for group in item.bookmark_groups)
    if path == "vpn ssl web portal bookmark-group bookmarks form-data":
        return sum(len(bookmark.form_data) for item in collection for group in item.bookmark_groups for bookmark in group.bookmarks)
    if path == "vpn ssl web portal landing-page":
        return sum(len(item.landing_pages) for item in collection)
    if path == "vpn ssl web portal landing-page form-data":
        return sum(len(page.form_data) for item in collection for page in item.landing_pages)
    if path == "vpn ssl web portal mac-addr-check-rule":
        return sum(len(item.mac_address_check_rules) for item in collection)
    if path == "vpn ssl web portal os-check-list":
        return sum(len(item.os_check_list) for item in collection)
    if path == "vpn ssl web portal split-dns":
        return sum(len(item.split_dns) for item in collection)
    if path == "vpn ssl web host-check-software check-item-list":
        return sum(len(item.check_items) for item in collection)
    if path == "firewall DoS-policy anomaly":
        return sum(len(item.anomalies) for item in collection)
    if path in {"firewall DoS-policy", "firewall DoS-policy6"}:
        family = "ipv6" if path.endswith("6") else "ipv4"
        return sum(
            1 for item in collection
            if getattr(item, "address_family", "ipv4") == family
        )
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
    if path in {"router static", "router static6"}:
        family = "ipv6" if path == "router static6" else "ipv4"
        return sum(item.address_family == family for item in collection)
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
    if path == "system dhcp server exclude-range":
        return sum(len(item.exclude_ranges) for item in collection)
    if path == "system dhcp server reserved-address":
        child_attribute = "reserved_addresses" if isinstance(model, FGConfig) else "reservations"
        return sum(len(getattr(item, child_attribute)) for item in collection)
    if path == "system dhcp server options":
        return sum(len(item.options) for item in collection)
    if path == "system interface secondaryip":
        if isinstance(model, FGConfig):
            return sum(len(intf.secondary_ips) for intf in collection)
        # Retained inactive/ambiguous entries are source preservation, not
        # active canonical normalization, so they must not inflate this count.
        return sum(len(intf.secondary_ips) for intf in collection)
    if path in SOURCE_ONLY_FAMILY_BY_SECTION:
        family = SOURCE_ONLY_FAMILY_BY_SECTION[path]
        return sum(
            1 for item in collection
            if getattr(item, "family", None) == family
        )
    return len(collection)


def classify_section_coverage(
    source_sections: list[SourceSectionResult],
    fg_config: FGConfig,
    ir_config: IRConfig,
) -> None:
    """Correlate source discovery, typed parsing, and canonical normalization."""
    for section in source_sections:
        path = section.path
        if path == "vdom":
            section.status = ExtractionStatus.VENDOR_EXTENSION
            section.parser_handler = "FortiGateParser._parse_vdom_contents"
            section.notes.append("VDOM wrapper normalized into source_context provenance.")
            continue
        if path in {
            "vpn ssl settings", "user setting", "user quarantine", "system settings", "system session-ttl",
        } and section.object_count_source == 0:
            section.object_count_source = 1
        structured_sections = (
            STRUCTURED_SECURITY_SECTIONS
            | STRUCTURED_ROUTING_SECTIONS
            | STRUCTURED_ROUTING_DEPENDENCY_SECTIONS
            | STRUCTURED_IDENTITY_SECTIONS
            | STRUCTURED_OPERATIONAL_SECTIONS
        )
        if path not in {"user radius", "user tacacs+"} and (path in structured_sections or any(
            path.startswith(f"{parent} ") for parent in structured_sections
        )):
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "FortiGateParser.parse_source_node"
            section.notes.append(
                "Recursive source command structure is retained for inventory and manual review."
            )
            profile_path = next(
                (parent for parent in PROFILE_SUPPORT_LEVELS if path == parent or path.startswith(f"{parent} ")),
                None,
            )
            section.notes.append(
                f"Support level: {PROFILE_SUPPORT_LEVELS.get(profile_path, 'STRUCTURED_EXTRACT_ONLY')}."
            )
            continue
        if path not in {"user radius", "user tacacs+"} and is_operational_source_path(path):
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

        if path.startswith("system sdwan ") and path not in TYPED_SECTIONS:
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.parser_handler = "source inventory"
            section.notes.append(
                "Unmodeled SD-WAN child configuration is retained as source-only inventory."
            )
            continue

        if path not in TYPED_SECTIONS:
            if path.startswith(("firewall ", "router ", "vpn ", "user ", "endpoint-control ", "system ")):
                section.status = ExtractionStatus.EXTRACT_ONLY_UNKNOWN
                section.parser_handler = "source inventory"
                section.notes.append(
                    "Unrecognized migration-relevant FortiOS section preserved as sanitized source-only inventory; no semantic interpretation was applied."
                )
            else:
                section.status = ExtractionStatus.UNSUPPORTED
                section.notes.append("No typed FortiGate extraction handler is registered.")
            continue

        if path in {
            "system settings", "system global", "system dns", "system session-ttl",
            "vpn ssl settings", "user setting", "user quarantine", "web-proxy global",
        }:
            section.parser_handler = "FortiGateParser.apply_global_set"
        else:
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
        semantic_unknowns = _semantic_unknown_keys(
            fg_config,
            path,
            section.source_context,
        )
        section.semantic_unknowns = semantic_unknowns

        if path in TYPED_EXTRACT_ONLY_SECTIONS:
            section.status = ExtractionStatus.EXTRACT_ONLY
            section.notes.append(
                "Typed source inventory is retained, but this section is not portable migration intent."
            )
            section.notes.append(
                f"Semantic support level: {fortigate_semantic_support_level(path)}."
            )
            if path == "user local":
                section.notes.append(
                    "Password content is intentionally secret and is not exported; password presence and safe metadata remain visible."
                )
            elif path in {"user radius", "user tacacs+"}:
                section.notes.append(
                    "Unmodeled vendor settings remain sanitized in Additional Settings."
                )
            if semantic_unknowns:
                section.notes.append(
                    "Additional source settings are retained outside the typed model: "
                    + ", ".join(semantic_unknowns)
                )
            continue

        if path == "firewall policy":
            policies = [
                policy for policy in ir_config.policies
                if section.source_context is None
                or policy.source_context == section.source_context
            ]
            partial_policies = [
                policy for policy in policies
                if policy.requires_manual_review
                or policy.migration_status != "NORMALIZED"
                or policy.review_reasons
            ]
            if partial_policies:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                section.notes.append(
                    f"{len(partial_policies)} policy object(s) retain semantic or reference review findings."
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

        if path == "firewall service category":
            section.status = (
                ExtractionStatus.NORMALIZED
                if section.object_count_normalized == section.object_count_parsed
                else ExtractionStatus.PARTIALLY_NORMALIZED
            )
            section.notes.append("Service category source items are normalized into IRServiceCategory.")
            continue

        if semantic_unknowns:
            section.status = ExtractionStatus.PARTIALLY_NORMALIZED
            section.notes.append(
                "Object counts are complete, but semantic source settings remain outside canonical IR: "
                + ", ".join(semantic_unknowns)
            )
            if path in {"router static", "router static6"}:
                section.notes.append(
                    "One or more static routes contain unmodeled or invalid source semantics."
                )
            continue

        if path == "system interface":
            partial_interfaces = [
                interface for interface in ir_config.interfaces
                if interface.requires_manual_review
                or interface.migration_status != "NORMALIZED"
                or interface.review_reasons
            ]
            if partial_interfaces:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                section.notes.append(
                    f"{len(partial_interfaces)} interface object(s) retain topology or semantic review findings."
                )
                continue

        if path == "firewall service custom":
            partial_services = [
                item for item in ir_config.services
                if item.requires_manual_review
                or item.migration_status != "NORMALIZED"
            ]
            if partial_services:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                section.notes.append(
                    f"{len(partial_services)} service object(s) retain "
                    "source-specific or manually reviewed semantics."
                )
                continue

        if path == "firewall service group":
            partial_groups = [
                item for item in ir_config.service_groups
                if item.requires_manual_review
                or item.migration_status != "NORMALIZED"
            ]
            if partial_groups:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                section.notes.append(
                    f"{len(partial_groups)} service group(s) retain "
                    "source-specific or manually reviewed semantics."
                )
                continue

        if path in {"router static", "router static6"}:
            family = "ipv6" if path == "router static6" else "ipv4"
            partial_routes = [
                route
                for route in ir_config.routes
                if (
                    route.address_family == family
                    and (
                        route.requires_manual_review
                        or route.parse_error is not None
                        or route.migration_status != "NORMALIZED"
                        or route.review_reasons
                    )
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

        if path in ADDRESS_OBJECT_SOURCE_SECTIONS:
            partial_addresses = [
                item for item in ir_config.addresses
                if item.source_section == path
                and (
                    item.requires_manual_review
                    or item.parse_error is not None
                    or item.migration_status != "NORMALIZED"
                )
            ]
            partial_derived_groups = [
                item for item in ir_config.address_groups
                if item.source_section == path
                and (
                    item.requires_manual_review
                    or item.migration_status != "NORMALIZED"
                )
            ]
            partial_count = len(partial_addresses) + len(partial_derived_groups)
            if partial_count:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                section.notes.append(
                    f"{partial_count} address object(s) retain source-specific, "
                    "missing, or manually reviewed semantics."
                )
                continue

        if path == "system interface":
            interfaces = [
                interface
                for interface in ir_config.interfaces
                if section.source_context is None
                or interface.source_context == section.source_context
            ]
            parse_error_count = sum(
                bool(interface.parse_errors)
                for interface in interfaces
            )

            review_interface_count = sum(
                interface.requires_manual_review
                or interface.migration_status != "NORMALIZED"
                or bool(interface.review_reasons)
                for interface in interfaces
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

            if review_interface_count:
                section.status = (
                    ExtractionStatus.PARTIALLY_NORMALIZED
                )
                section.notes.append(
                    f"{review_interface_count} interface(s) require manual "
                    "review for topology or other retained interface semantics."
                )

            if (
                parse_error_count
                or review_interface_count
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
                for sec in (
                    list(interface.secondary_ips)
                    + list(interface.inactive_secondary_ips)
                )
                if sec.parse_error is not None or sec.requires_manual_review
            ]
            inactive_items = [
                sec
                for interface in ir_config.interfaces
                for sec in interface.inactive_secondary_ips
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
                if inactive_items:
                    section.notes.append(
                        "Configured secondary interface IPs are retained as inactive or "
                        "ambiguous source data and are not exposed as active addresses."
                    )
                section.notes.append(
                    "One or more secondary interface IPs require manual review."
                )
                continue
            if inactive_items:
                section.status = ExtractionStatus.PARTIALLY_NORMALIZED
                section.notes.append(
                    "Configured secondary interface IPs are retained as inactive or "
                    "ambiguous source data and are not exposed as active addresses."
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
