"""Declarative FortiGate source-parser section metadata."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable, Iterable, Mapping

@dataclass(frozen=True)
class SectionSpec:
    source_path: str
    model: type[Any] | None = None
    destination_collection: str | None = None
    list_fields: frozenset[str] = field(default_factory=frozenset)
    integer_fields: frozenset[str] = field(default_factory=frozenset)
    integer_list_fields: frozenset[str] = field(default_factory=frozenset)
    scalar_fields: frozenset[str] = field(default_factory=frozenset)
    explicit_fields: frozenset[str] = field(default_factory=frozenset)
    secret_fields: frozenset[str] = field(default_factory=frozenset)
    source_only_fields: frozenset[str] = field(default_factory=frozenset)
    normalizer: Callable[..., Any] | None = None
    custom_builder: Callable[..., Any] | None = None


SECTION_LIST_FIELDS = {
    "system zone": {"interface"},
    "system zone tagging": {"tags"},
    "user ldap": {"search_type"},
    "router policy": {
        "dst",
        "dstaddr",
        "input_device",
        "internet_service_custom",
        "src",
        "srcaddr",
    },
    "router policy6": {
        "dst",
        "dstaddr",
        "input_device",
        "internet_service_custom",
        "src",
        "srcaddr",
    },
    "router static": {"sdwan_zone"},
    "router static6": {"sdwan_zone"},
    "firewall addrgrp": {"member", "exclude_member"},
    "firewall addrgrp6": {"member", "exclude_member"},
    "firewall address tagging": {"tags"},
    "firewall address6 tagging": {"tags"},
    "firewall multicast-address tagging": {"tags"},
    "firewall multicast-address6 tagging": {"tags"},
    "firewall addrgrp tagging": {"tags"},
    "firewall addrgrp6 tagging": {"tags"},
    "firewall vip": {
        "extaddr", "mappedip", "monitor", "service",
        "src_filter", "srcintf_filter",
    },
    "firewall vip realservers": {"monitor"},
    "firewall vipgrp": {"member"},
    "firewall vip6": {"mappedip", "monitor", "src_filter"},
    "firewall vip6 realservers": {"monitor"},
    "firewall vipgrp6": {"member"},
    "firewall policy": {
        "custom_log_fields",
        "pcp_poolname",
        "srcintf",
        "dstintf",
        "srcaddr",
        "dstaddr",
        "service",
        "groups",
        "users",
        "poolname",
        "srcaddr6",
        "dstaddr6",
        "poolname6",
        "fsso_groups",
        "internet_service_custom",
        "internet_service_custom_group",
        "internet_service_group",
        "internet_service_name",
        "internet_service_src_custom",
        "internet_service_src_custom_group",
        "internet_service_src_group",
        "internet_service_src_name",
        "internet_service6_custom",
        "internet_service6_custom_group",
        "internet_service6_group",
        "internet_service6_name",
        "internet_service6_src_custom",
        "internet_service6_src_custom_group",
        "internet_service6_src_group",
        "internet_service6_src_name",
        "network_service_dynamic",
        "network_service_src_dynamic",
        "ntlm_enabled_browsers",
        "rtp_addr",
        "sgt",
        "src_vendor_mac",
        "ztna_ems_tag",
        "ztna_ems_tag_secondary",
        "ztna_geo_tag",
        "app_group",
        "url_category",
    },
    "firewall security-policy": {
        "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6",
        "service", "application", "app_category", "app_group", "groups",
        "fsso_groups", "users", "url_category", "internet_service_custom",
        "internet_service_custom_group", "internet_service_group",
        "internet_service_name", "internet_service_src_custom",
        "internet_service_src_custom_group", "internet_service_src_group",
        "internet_service_src_name", "internet_service6_custom",
        "internet_service6_custom_group", "internet_service6_group",
        "internet_service6_name", "internet_service6_src_custom",
        "internet_service6_src_custom_group", "internet_service6_src_group",
        "internet_service6_src_name",
    },
    "firewall central-snat-map": {
        "srcintf", "dstintf", "orig_addr", "orig_addr6", "dst_addr",
        "dst_addr6", "nat_ippool", "nat_ippool6",
    },
    "firewall schedule group": {"member"},
    "firewall service group": {"member"},
    "system dns": {"protocol", "domain", "server_hostname"},
    # These settings accept multiple CLI values on a system interface.  Keep
    # this section-specific because the same keys may be scalar in other
    # FortiOS sections, and because source preservation must not depend only
    # on the broad global list-field set below.
    "system interface": {
        "member",
        "fail_alert_interfaces",
        "fail_detect_option",
        "dns_server_protocol",
        "security_groups",
        "dhcp_relay_ip",
    },
    "system interface secondaryip": {
        "detectprotocol",
    },
    "vpn ipsec phase1-interface": {
        "proposal",
        "certificate",
        "backup_gateway",
        "signature_hash_alg",
        "exchange_ip_addr4",
        "exchange_ip_addr6",
        "ipv4_split_include",
        "ipv4_split_exclude",
        "ipv6_split_include",
        "ipv6_split_exclude",
        "split_include_service",
        "dhgrp",
    },
    "vpn ipsec phase1": {
        "proposal",
        "certificate",
        "backup_gateway",
        "signature_hash_alg",
        "exchange_ip_addr4",
        "exchange_ip_addr6",
        "ipv4_split_include",
        "ipv4_split_exclude",
        "ipv6_split_include",
        "ipv6_split_exclude",
        "split_include_service",
        "dhgrp",
    },
    "vpn ipsec phase2-interface": {
        "proposal",
        "src_name",
        "dst_name",
        "src_name6",
        "dst_name6",
        "dhgrp",
    },
    "vpn ipsec phase2": {
        "proposal",
        "src_name",
        "dst_name",
        "src_name6",
        "dst_name6",
        "dhgrp",
    },
    "ips sensor entries": {
        "rule",
        "severity",
        "protocol",
        "application",
        "cve",
        "os",
        "vuln_type",
    },
    "system sdwan health-check": {"members", "server"},
    "system sdwan health-check sla": {"link_cost_factor"},
    "system sdwan service": {
        "service",
        "src",
        "src6",
        "dst",
        "dst6",
        "groups",
        "health_check",
        "input_device",
        "input_zone",
        "priority_zone",
        "internet_service_name",
        "internet_service_app_ctrl_group",
        "internet_service_custom",
        "internet_service_custom_group",
        "internet_service_group",
        "users",
    },
    "system sdwan duplication": {
        "srcaddr",
        "dstaddr",
        "srcaddr6",
        "dstaddr6",
        "srcintf",
        "dstintf",
        "service",
    },
    "vpn ssl web portal": {
        "ip_pools",
        "ipv6_pools",
        "allow_user_access",
        "split_tunneling_routing_address",
        "ipv6_split_tunneling_routing_address",
    },
    "vpn ssl web portal mac-addr-check-rule": {"mac_addr_list"},
    "vpn ssl settings": {
        "banned_cipher",
        "ciphersuite",
        "client_sigalgs",
        "source_interface",
        "source_address",
        "source_address6",
        "tunnel_ip_pools",
        "tunnel_ipv6_pools",
    },
    "vpn ssl settings authentication-rule": {
        "groups",
        "users",
        "source_address",
        "source_address6",
        "source_interface",
    },
    "firewall DoS-policy": {"srcaddr", "dstaddr", "service"},
    "firewall DoS-policy6": {"srcaddr", "dstaddr", "service"},
    "user group": {"member"},
    "user quarantine": {"firewall_groups"},
}

# Numeric CLI fields are declared here so normal edit evaluation does not
# depend on the section-specific model builder remembering to coerce them.
SECTION_INTEGER_FIELDS = {
    "system interface": {
        "bfd_desired_min_tx", "bfd_detect_mult", "bfd_required_min_rx",
        "bandwidth_measure_time", "snmp_index", "weight", "mtu", "tcp_mss",
        "estimated_upstream_bandwidth", "estimated_downstream_bandwidth",
        "link_up_delay", "link_down_delay", "distance", "priority",
        "ha_priority", "dhcp_renew_time", "lacp_select_timeout", "bandwidth",
        "cli_conn6_status", "ip6_default_life", "ip6_delegated_prefix_iaid",
        "ip6_hop_limit", "ip6_link_mtu", "ip6_max_interval", "ip6_min_interval",
        "ip6_reachable_time", "ip6_retrans_time", "vlanid", "vrf", "min_links",
        "ping_serv_status",
    },
    "system interface secondaryip": {"id", "ha_priority", "ping_serv_status"},
    "firewall address": {"cache_ttl", "route_tag", "color"},
    "firewall address6": {"cache_ttl", "route_tag", "color"},
    "firewall addrgrp": {"color"},
    "firewall addrgrp6": {"color"},
    "firewall service custom": {
        "protocol_number", "icmptype", "icmpcode", "color",
        "tcp_halfclose_timer", "tcp_halfopen_timer", "tcp_rst_timer",
        "tcp_timewait_timer", "udp_idle_timer",
    },
    "firewall service group": {"color"},
    "firewall schedule recurring": {"color", "expiration_days"},
    "firewall schedule onetime": {"color", "expiration_days"},
    "firewall schedule group": {"color"},
    "vpn ipsec phase1-interface": {
        "default_gw_priority", "distance", "priority", "aggregate_weight",
    },
    "vpn ipsec phase1": {"default_gw_priority", "distance", "priority"},
    "vpn ipsec phase2-interface": {"protocol", "src_port", "dst_port"},
    "vpn ipsec phase2": {"protocol", "src_port", "dst_port"},
    "firewall ippool": {
        "startport", "endport", "block_size", "num_blocks_per_user",
        "pba_timeout", "pba_interim_log", "port_per_user", "client_prefix_length",
        "tcp_session_quota", "udp_session_quota", "icmp_session_quota",
        "cgn_block_size", "cgn_client_ipv6shift", "cgn_port_start", "cgn_port_end",
        "utilization_alarm_clear", "utilization_alarm_raise",
    },
    "firewall vip": {
        "id", "gratuitous_arp_interval", "max_embryonic_connections", "color",
    },
    "firewall vip6": {
        "id", "max_embryonic_connections", "color",
    },
    "firewall vipgrp": {"color"},
    "firewall vipgrp6": {"color"},
    "firewall vip realservers": {
        "id", "port", "weight", "holddown_interval", "max_connections",
    },
    "firewall vip6 realservers": {
        "id", "port", "weight", "holddown_interval", "max_connections",
    },
    "firewall policy": {
        "id", "tcp_mss_sender", "tcp_mss_receiver", "session_ttl",
        "vlan_cos_fwd", "vlan_cos_rev", "reputation_minimum",
        "reputation_minimum6",
    },
    "firewall central-snat-map": {"id", "protocol"},
    "firewall ip-translation": {"id"},
    "router static": {
        "id", "distance", "priority", "weight", "vrf", "tag",
        "internet_service", "devindex",
    },
    "router static6": {
        "id", "distance", "priority", "weight", "vrf", "tag",
        "internet_service", "devindex",
    },
}

SECTION_INTEGER_LIST_FIELDS = {
    "firewall policy": {"application", "app_category"},
}


SECTION_REGISTRY: dict[str, SectionSpec] = {}


def register_section(spec: SectionSpec) -> None:
    categories = {
        "list_fields": spec.list_fields,
        "integer_fields": spec.integer_fields,
        "integer_list_fields": spec.integer_list_fields,
        "scalar_fields": spec.scalar_fields,
    }
    for left, right in (
        ("list_fields", "scalar_fields"),
        ("integer_fields", "scalar_fields"),
        ("integer_list_fields", "list_fields"),
        ("integer_list_fields", "scalar_fields"),
        ("integer_fields", "integer_list_fields"),
    ):
        overlap = categories[left] & categories[right]
        if overlap:
            raise ValueError(
                f"{spec.source_path}: field(s) {sorted(overlap)} overlap between "
                f"{left} and {right}"
            )
    SECTION_REGISTRY[spec.source_path] = spec


def register_sections(
    paths: Iterable[str],
    *,
    models: Mapping[str, type[Any]] | None = None,
    destination_collections: Mapping[str, str] | None = None,
    list_fields: Mapping[str, Iterable[str]] | None = None,
    integer_fields: Mapping[str, Iterable[str]] | None = None,
    integer_list_fields: Mapping[str, Iterable[str]] | None = None,
    scalar_fields: Mapping[str, Iterable[str]] | None = None,
    explicit_fields: Mapping[str, Iterable[str]] | None = None,
    secret_fields: Mapping[str, Iterable[str]] | None = None,
    source_only_fields: Mapping[str, Iterable[str]] | None = None,
) -> None:
    """Register the parser's immutable section specifications."""

    models = models or {}
    destination_collections = destination_collections or {}
    mappings = [
        list_fields or {}, integer_fields or {}, integer_list_fields or {},
        scalar_fields or {}, explicit_fields or {}, secret_fields or {},
    ]
    for path in paths:
        register_section(SectionSpec(
            source_path=path,
            model=models.get(path),
            destination_collection=destination_collections.get(path),
            list_fields=frozenset(mappings[0].get(path, ())),
            integer_fields=frozenset(mappings[1].get(path, ())),
            integer_list_fields=frozenset(mappings[2].get(path, ())),
            scalar_fields=frozenset(mappings[3].get(path, ())),
            explicit_fields=frozenset(mappings[4].get(path, ())),
            secret_fields=frozenset(mappings[5].get(path, ())),
            source_only_fields=frozenset((source_only_fields or {}).get(path, ())),
        ))


_BUILTINS_INITIALIZED = False


def initialize_builtin_sections() -> None:
    """Build the built-in registry once after the parser module is loaded."""
    global _BUILTINS_INITIALIZED
    if _BUILTINS_INITIALIZED:
        return

    from fwmigrate.parsers.fortigate import parser as parser_module

    models = {
        "system interface": parser_module.FGInterface,
        "system zone": parser_module.FGSystemZone,
        "firewall wildcard-fqdn custom": parser_module.FGWildcardFQDN,
        "firewall address": parser_module.FGAddress,
        "firewall address6": parser_module.FGAddress,
        "firewall addrgrp": parser_module.FGAddressGroup,
        "firewall addrgrp6": parser_module.FGAddressGroup,
        "firewall service custom": parser_module.FGService,
        "firewall service group": parser_module.FGServiceGroup,
        "firewall schedule recurring": parser_module.FGSchedule,
        "firewall schedule onetime": parser_module.FGSchedule,
        "firewall schedule group": parser_module.FGScheduleGroup,
        "firewall ippool": parser_module.FGIPPool,
        "firewall ippool6": parser_module.FGIPPool6,
        "firewall ippool_grp": parser_module.FGIPPoolGroup,
        "user adgrp": parser_module.FGADGroup,
        "user local": parser_module.FGLocalUser,
        "user group": parser_module.FGUserGroup,
        "user saml": parser_module.FGUserSAML,
        "system fsso-polling": parser_module.FGSystemFSSOPolling,
        "firewall vip": parser_module.FGVIP,
        "firewall vip6": parser_module.FGVIP6,
        "firewall vipgrp": parser_module.FGVIPGroup,
        "firewall vipgrp6": parser_module.FGVIPGroup6,
        "firewall vip realservers": parser_module.FGVIPRealServer,
        "firewall vip6 realservers": parser_module.FGVIPRealServer,
        "system interface secondaryip": parser_module.FGInterfaceSecondaryIP,
        "firewall policy": parser_module.FGPolicy,
        "firewall security-policy": parser_module.FGSecurityPolicy,
        "firewall central-snat-map": parser_module.FGCentralSNATRule,
        "router static": parser_module.FGStaticRoute,
        "router static6": parser_module.FGStaticRoute,
        "router policy": parser_module.FGPolicyRoute,
        "router policy6": parser_module.FGPolicyRoute,
        "system dns": parser_module.FGDns,
        "vpn ipsec phase1-interface": parser_module.FGPhase1Interface,
        "vpn ipsec phase1": parser_module.FGPhase1Policy,
        "vpn ipsec phase2-interface": parser_module.FGPhase2Interface,
        "vpn ipsec phase2": parser_module.FGPhase2Policy,
    }
    common_list_fields = {
        "allowaccess", "detectprotocol", "dhcp_relay_ip", "member", "day",
        "srcintf", "dstintf", "srcaddr", "dst", "dst6",
        "ip_range", "ip6_range", "groups", "users", "service", "poolname",
        "proposal", "internet_service_name", "exclude_ip", "mappedip", "extaddr",
        "src_filter", "srcintf_filter", "monitor", "ztna_ems_tag",
        "ztna_ems_tag_secondary", "ztna_geo_tag", "capabilities", "fsso_group",
    }
    list_fields = {
        path: set(SECTION_LIST_FIELDS.get(path, ()))
        | (common_list_fields & set(model.model_fields))
        for path, model in models.items()
    }
    list_fields.update({
        path: set(fields)
        for path, fields in SECTION_LIST_FIELDS.items()
        if path not in list_fields
    })
    destination_collections = {
        "system interface": "interfaces",
        "system zone": "system_zones",
        "firewall wildcard-fqdn custom": "wildcard_fqdns",
        "firewall address": "addresses",
        "firewall address6": "addresses",
        "firewall addrgrp": "address_groups",
        "firewall addrgrp6": "address_groups",
        "firewall service custom": "services",
        "firewall service group": "service_groups",
        "firewall schedule recurring": "schedules",
        "firewall schedule onetime": "schedules",
        "firewall schedule group": "schedule_groups",
        "firewall ippool": "ip_pools",
        "firewall ippool6": "ip_pools6",
        "firewall ippool_grp": "ip_pool_groups",
        "user adgrp": "ad_groups",
        "user saml": "user_saml_servers",
        "firewall vip": "vips",
        "firewall vip6": "vips6",
        "firewall vipgrp": "vip_groups",
        "firewall vipgrp6": "vip_groups6",
        "firewall policy": "policies",
        "firewall security-policy": "security_policies",
        "firewall central-snat-map": "central_snat_rules",
        "router static": "static_routes",
        "router static6": "static_routes",
        "router policy": "policy_routes",
        "router policy6": "policy_routes",
        "vpn ipsec phase1-interface": "phase1_interfaces",
        "vpn ipsec phase1": "phase1_policies",
        "vpn ipsec phase2-interface": "phase2_interfaces",
        "vpn ipsec phase2": "phase2_policies",
    }
    integer_fields = {
        path: set(fields) for path, fields in SECTION_INTEGER_FIELDS.items()
    }
    integer_fields.update({
        "router policy": parser_module.FG_POLICY_ROUTE_INT_FIELDS,
        "router policy6": parser_module.FG_POLICY_ROUTE_INT_FIELDS,
        "system sdwan zone": parser_module.FG_SDWAN_ZONE_INT_FIELDS,
        "system sdwan health-check": parser_module.FG_SDWAN_HEALTH_CHECK_INT_FIELDS,
        "system sdwan health-check sla": parser_module.FG_SDWAN_HEALTH_CHECK_SLA_INT_FIELDS,
        "system sdwan service": parser_module.FG_SDWAN_SERVICE_INT_FIELDS,
        "system fsso-polling": {"listening_port"},
    })
    integer_list_fields = {
        path: set(fields) for path, fields in SECTION_INTEGER_LIST_FIELDS.items()
    }
    integer_list_fields.update({
        "router policy": parser_module.FG_POLICY_ROUTE_INT_LIST_FIELDS,
        "router policy6": parser_module.FG_POLICY_ROUTE_INT_LIST_FIELDS,
        "system sdwan service": parser_module.FG_SDWAN_SERVICE_INT_LIST_FIELDS,
    })
    scalar_fields = {
        path: set(model.model_fields)
        - list_fields.get(path, set())
        - integer_fields.get(path, set())
        - integer_list_fields.get(path, set())
        - {"extra_settings", "source_explicit_fields", "source_attributes", "nested_configs"}
        for path, model in models.items()
    }
    secret_fields = {
        path: parser_module.IDENTITY_SECRET_FIELDS
        for path in parser_module.IDENTITY_SECTIONS
    }
    secret_fields.update({
        "vpn ipsec phase1": {
            "psksecret", "psksecret_remote", "authpasswd",
            "group_authentication_secret", "ppk_secret",
        },
        "vpn ipsec phase1-interface": {
            "psksecret", "psksecret_remote", "authpasswd",
            "group_authentication_secret", "ppk_secret",
        },
    })
    paths = (
        set(models)
        | set(list_fields)
        | set(parser_module.SECTION_EXPLICIT_FIELDS)
        | parser_module.CONTEXTUAL_MODEL_SECTIONS
        | parser_module.STRUCTURED_SECURITY_SECTIONS
        | parser_module.STRUCTURED_ROUTING_SECTIONS
        | parser_module.STRUCTURED_ROUTING_DEPENDENCY_SECTIONS
        | parser_module.STRUCTURED_IDENTITY_SECTIONS
        | parser_module.STRUCTURED_OPERATIONAL_SECTIONS
    )
    register_sections(
        paths,
        models=models,
        destination_collections=destination_collections,
        list_fields=list_fields,
        integer_fields=integer_fields,
        integer_list_fields=integer_list_fields,
        scalar_fields=scalar_fields,
        explicit_fields=parser_module.SECTION_EXPLICIT_FIELDS,
        secret_fields=secret_fields,
    )
    _BUILTINS_INITIALIZED = True


def update_section(path: str, **changes: Any) -> SectionSpec:
    spec = replace(get_section_spec(path) or SectionSpec(path), **changes)
    register_section(spec)
    return spec


def get_section_spec(section_path: str) -> SectionSpec | None:
    return SECTION_REGISTRY.get(section_path)


def get_section_parser_capability(
    section_path: str,
    encountered_fields: Iterable[str] = (),
) -> dict[str, Any]:
    spec = get_section_spec(section_path)
    if spec is None:
        return {
            "source_path": section_path,
            "known_section": False,
            "classification": "unknown",
            "unknown_fields": sorted(set(encountered_fields)),
        }
    typed = spec.list_fields | spec.integer_fields | spec.integer_list_fields | spec.scalar_fields
    known = typed | spec.explicit_fields
    return {
        "source_path": section_path,
        "known_section": True,
        "model": spec.model.__name__ if spec.model else None,
        "destination_collection": spec.destination_collection,
        "known_fields": sorted(known),
        "list_fields": sorted(spec.list_fields),
        "integer_fields": sorted(spec.integer_fields),
        "integer_list_fields": sorted(spec.integer_list_fields),
        "scalar_fields": sorted(spec.scalar_fields),
        "custom_handler": bool(spec.custom_builder),
        "source_only_fields": sorted(spec.source_only_fields),
        "classification": (
            "custom handled" if spec.custom_builder
            else "typed" if spec.model
            else "preserved source-only"
        ),
        "unknown_fields": sorted(set(encountered_fields) - known),
    }
