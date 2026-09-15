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
    "system dhcp server": {"tftp_server", "vci_string"},
    "system dhcp server ip-range": {"uci_string", "vci_string"},
    "system dhcp server exclude-range": {"uci_string", "vci_string"},
    "system dhcp server options": {"uci_string", "vci_string", "ip"},
    "system dhcp6 server option": {"ip6"},
    "system dhcp6 server options": {"ip6"},
    "authentication scheme": {"method", "user_database"},
    "authentication rule": {"srcintf", "srcaddr", "srcaddr6", "dstaddr", "dstaddr6", "protocol", "auth_method"},
    "system zone": {"interface"},
    "system zone tagging": {"tags"},
    "user ldap": {"search_type"},
    "firewall local-in-policy": {
        "dstaddr",
        "internet_service_src_custom",
        "internet_service_src_custom_group",
        "internet_service_src_group",
        "internet_service_src_name",
        "intf",
        "service",
        "srcaddr",
    },
    "firewall local-in-policy6": {
        "dstaddr",
        "internet_service6_src_custom",
        "internet_service6_src_custom_group",
        "internet_service6_src_group",
        "internet_service6_src_name",
        "intf",
        "service",
        "srcaddr",
    },
    "router policy": {
        "dst",
        "dstaddr",
        "input_device",
        "internet_service_custom",
        "internet_service_id",
        "src",
        "srcaddr",
    },
    "router policy6": {
        "dst",
        "dstaddr",
        "input_device",
        "internet_service_custom",
        "internet_service_id",
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
        "application",
        "app_category",
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
    "firewall shaping-policy": {
        "srcintf", "dstintf", "srcaddr", "dstaddr", "srcaddr6", "dstaddr6",
        "application", "app_category", "app_group", "url_category", "service",
    },
    "firewall multicast-policy": {
        "srcaddr", "dstaddr",
    },
    "firewall multicast-policy6": {
        "srcaddr", "dstaddr",
    },
    "firewall central-snat-map": {
        "srcintf", "dstintf", "orig_addr", "orig_addr6", "dst_addr",
        "dst_addr6", "nat_ippool", "nat_ippool6",
    },
    "firewall schedule group": {"member"},
    "firewall service group": {"member"},
    "system dns": {"protocol", "domain", "server_hostname"},
    "system admin": {"vdom", "guest_usergroups"},
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
        "priority_members",
        "priority_zone",
        "internet_service_name",
        "internet_service_app_ctrl",
        "internet_service_app_ctrl_category",
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
        "host_check_policy",
        "allow_user_access",
        "split_tunneling_routing_address",
        "ipv6_split_tunneling_routing_address",
    },
    "vpn ssl web portal mac-addr-check-rule": {"mac_addr_list"},
    "vpn ssl web host-check-software check-item-list": {"md5s"},
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
    "authentication rule": {"srcintf", "srcaddr"},
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
    "firewall address6-template": {"subnet_segment_count"},
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
