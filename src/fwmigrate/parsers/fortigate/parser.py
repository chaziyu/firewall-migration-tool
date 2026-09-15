import re
import sys
from typing import Iterator, List, Dict, Any, Optional

from fwmigrate.parsers.fortigate.command_evaluator import (
    evaluate_commands,
    evaluate_section_commands,
)
from fwmigrate.parsers.fortigate.tokenizer import (
    Token,
    TokenType,
    FortiGateTokenizer,
)
from fwmigrate.parsers.fortigate.model import (
    FGConfig,
    FGSystemGlobal,
    FGInterface,
    FGL2TPClientSettings,
    FGInterfaceSecondaryIP,
    FGInterfaceClientOption,
    FGInterfaceDHCPSnoopingServer,
    FGInterfaceTaggingEntry,
    FGInterfaceVRRPProxyARP,
    FGInterfaceVRRP,
    FGInterfaceEgressQueues,
    FGInterfaceIPv6ExtraAddress,
    FGIPv6PrefixAdvertisement,
    FGIPv6DelegatedPrefixAdvertisement,
    FGDHCPv6IAPD,
    FGInterfaceVRRP6,
    FGSystemZone,
    FGSystemZoneTaggingEntry,
    FGAddress,
    FGAddress6Template,
    FGAddressListEntry,
    FGAddressTaggingEntry,
    FGAddressGroup,
    FGAddressGroupTaggingEntry,
    FGWildcardFQDN,
    FGServiceCategory,
    FGPortRange,
    FGService,
    FGServiceGroup,
    FGSchedule,
    FGTrafficShaper,
    FGProxyAddress,
    FGWebProxyGlobal,
    FGIPPool,
    FGIPPool6,
    FGIPPoolGroup,
    FGVIP,
    FGVIPGroup,
    FGVIP6,
    FGVIPGroup6,
    FGVIPRealServer,
    FGPolicy,
    FGMulticastPolicy,
    FGPhase1Interface,
    FGPhase2Interface,
    FGPhase2Policy,
    FGStaticRoute,
    FGSDWan,
    FGDns,
    FGSDWanZone,
    FGSDWanMember,
    FGSDWanSLA,
    FGSDWanHealthCheck,
    FGSDWanService,
    FGSDWanServiceSLA,
    FGSDWanDuplication,
    FGSDWanNeighbor,
    FGInternetService,
    FGInternetServiceAddition,
    FGInternetServiceAdditionEntry,
    FGInternetServiceAdditionPortRange,
    FGInternetServiceAppend,
    FGInternetServiceCustom,
    FGInternetServiceCustomEntry,
    FGInternetServiceCustomGroup,
    FGInternetServiceCustomPortRange,
    FGInternetServiceDefinition,
    FGInternetServiceDefinitionEntry,
    FGInternetServiceDefinitionPortRange,
    FGInternetServiceExtension,
    FGInternetServiceExtensionDisableEntry,
    FGInternetServiceExtensionEntry,
    FGInternetServiceExtensionIPv4Range,
    FGInternetServiceExtensionIPv6Range,
    FGInternetServiceExtensionPortRange,
    FGInternetServiceGroup,
    FGFCTEMS,
    FGSessionHelper,
    FGSessionTTLOverride,
    FGSessionTTLSettings,
    FGExecutionContext,
    FGCentralSNATRule,
    FGIPTranslation,
    FGSourceOnlyRule,
    FGSecurityPolicy,
    FGShapingPolicy,
    FGPhase1Policy,
    FGLocalInPolicy,
    FGPolicyRoute,
    FGScheduleGroup,
    FGDHCPServer,
    FGDHCPIPRange,
    FGDHCPExcludeRange,
    FGDHCPReservation,
    FGDHCPOption,
    FGDHCP6Server,
    FGDHCP6IPRange,
    FGDHCP6PrefixRange,
    FGDHCP6Option,
    FGDnsServer,
    FGDns64,
    FGCertificate,
    FGSSHKey,
    FGIPSSensor,
    FGIPSSensorEntry,
    FGIPSSensorExemptIP,
    FGProfileGroup,
    FGUserLDAP,
    FGFSSOServer,
    FGFSSOEndpoint,
    FGADGroup,
    FGFSSOPolling,
    FGFSSOPollingADGroup,
    FGUserSAML,
    FGLocalUser,
    FGUserGroup,
    FGUserGroupMatch,
    FGUserGroupGuest,
    FGUserAuthenticationSettings,
    FGUserQuarantine,
    FGAdministrator,
    FGAdminProfile,
    FGAdminProfilePermissionBlock,
    FGFortiToken,
    FGSSLVPNPortal,
    FGSSLVPNSettings,
    FGSSLVPNAuthenticationRule,
    FGSSLVPNHostCheckItem,
    FGSSLVPNHostCheckSoftware,
    FGSSLVPNPortalSplitDNS,
    FGSSLVPNPortalBookmarkFormData,
    FGSSLVPNPortalBookmark,
    FGSSLVPNPortalBookmarkGroup,
    FGSSLVPNPortalLandingPageFormData,
    FGSSLVPNPortalLandingPage,
    FGSSLVPNPortalMACAddressRule,
    FGSSLVPNPortalOSCheck,
    FGDoSPolicy,
    FGDoSAnomaly,
    FGFirewallSniffer,
    FGAuthenticationScheme,
    FGAuthenticationRule,
    FGSecurityProfile,
    FGProfileNestedSection,
    FGAntivirusProfile,
    FGAntivirusProtocol,
    FGAntivirusProfileConfig,
    FGWebFilterProfile,
    FGWebFilterCategory,
    FGWebFilterOverride,
    FGWebFilterURLFilter,
    FGDNSFilterProfile,
    FGDNSFilterCategory,
    FGDNSFilterDomainFilter,
    FGDNSFilterBotnet,
    FGDNSFilterAction,
    FGApplicationList,
    FGApplicationEntry,
    FGApplicationFilter,
    FGApplicationOverride,
    FGSSLSSHProfile,
    FGSSLSSHProtocolInspection,
    FGSSLSSHCertificate,
    FGSSLSSHExemption,
    FGNetworkServiceDynamic,
    FGSDNConnector,
    FGUserRADIUS,
    FGUserRADIUSAccountingServer,
    FGUserTACACS,
    FGLinkMonitor,
    FGLinkMonitorServer,
    FGTopologyObject,
    FGVirtualWirePair,
    FGVDOMLink,
    FGAccessProxy,
    FGAccessProxyDestination,
    FGAccessProxyServer,
    FGAccessProxyVirtualHost,
    FGAccessProxyMapping,
    FGAccessProxySSHClientCertExtension,
    FGEMSOverride,
    FGSSLVPNRealm,
    FGSSLVPNBookmark,
    FGManualKeyInterface,
    FGPhase1Common,
    FGIPPool,
    FGIPPool6,
    FGIPv6EHFilter,
    FGVIPGSLBPublicIP,
    FGVIPQUICSettings,
    FGVIPSSLCipherSuite,
)
from fwmigrate.parsers.fortigate.certificates import parse_certificate_metadata
from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes
from fwmigrate.parsers.fortigate.firewall_ip_746 import (
    effective_ipv6_eh_filter_settings,
    validate_ipv6_eh_filter_746,
)
from fwmigrate.parsers.fortigate.dns_multivalue_fix import FGDnsMultiValue746
from fwmigrate.parsers.fortigate.service_parser_extensions import parse_service_port_ranges
from fwmigrate.parsers.fortigate.authentication_scheme_extensions import (
    AUTHENTICATION_METHODS,
    AUTHENTICATION_STRING_LIMITS,
    AUTHENTICATION_SWITCH_FIELDS,
)
from fwmigrate.parsers.fortigate.session_ttl_extensions import (
    SESSION_TTL_OVERRIDE_INT_FIELDS,
    SYSTEM_GLOBAL_SESSION_TIMER_FIELDS,
    FGServiceSessionTimers,
    FGSystemGlobalSessionTimers,
)
from fwmigrate.parsers.fortigate.phase_42_antivirus import (
    FGAntivirusProfile746,
    FGAntivirusProtocol746,
    FGAntivirusProfileConfig746,
)
from fwmigrate.parsers.fortigate.phase_43_webfilter import (
    FGWebFilterProfile746,
    FGWebFilterCategory746,
    FGWebFilterOverride746,
)
from fwmigrate.parsers.fortigate.phase_44_dnsfilter import (
    FGDNSFilterProfile746,
    FGDNSFilterCategory746,
)
from fwmigrate.parsers.fortigate.phase_45_application_control import (
    FGApplicationList746,
    FGApplicationEntry746,
)
from fwmigrate.parsers.fortigate.firewall_vip_746 import FORTIOS_746_VIP_FIELDS
from fwmigrate.parsers.fortigate.phase_46_50_extensions import (
    _build_ips_sensor,
    _refresh_interface_ipv6_from_source,
    _refresh_policy_address_families,
)
from fwmigrate.extraction.models import ExtractionStatus, SourceCommand, SourceInventoryItem
from fwmigrate.parsers.fortigate.source_tree import (
    FGSourceCommand,
    FGSourceNode,
    FGStructuredSourceObject,
    STRUCTURED_IDENTITY_SECTIONS,
    STRUCTURED_ROUTING_SECTIONS,
    STRUCTURED_ROUTING_DEPENDENCY_SECTIONS,
    STRUCTURED_SECURITY_SECTIONS,
    STRUCTURED_OPERATIONAL_SECTIONS,
)
from fwmigrate.parsers.fortigate.section_registry import (
    SECTION_INTEGER_FIELDS,
    SECTION_INTEGER_LIST_FIELDS,
    SECTION_LIST_FIELDS,
    get_section_spec,
    register_sections,
)


SDWAN_EXPLICIT_FIELDS = {
    "system sdwan zone": set(FGSDWanZone.model_fields)
    - {"source_context", "source_explicit_fields", "extra_settings"},
    "system sdwan members": set(FGSDWanMember.model_fields)
    - {"source_explicit_fields", "extra_settings"},
    "system sdwan health-check": set(FGSDWanHealthCheck.model_fields)
    - {"source_explicit_fields", "extra_settings"},
    "system sdwan health-check sla": set(FGSDWanSLA.model_fields)
    - {"source_explicit_fields", "extra_settings"},
    "system sdwan service": set(FGSDWanService.model_fields)
    - {"source_explicit_fields", "extra_settings"},
    "system sdwan service sla": set(FGSDWanServiceSLA.model_fields)
    - {"source_explicit_fields", "extra_settings"},
}


ROUTE_EXPLICIT_FIELDS = {
    "router static": set(FGStaticRoute.model_fields)
    - {"source_explicit_fields", "extra_settings"},
    "router static6": set(FGStaticRoute.model_fields)
    - {"source_explicit_fields", "extra_settings"},
    "router policy": set(FGPolicyRoute.model_fields)
    - {
        "source_context",
        "nested_configs",
        "family",
        "source_order",
        "source_explicit_fields",
        "source_attributes",
        "extra_settings",
    },
    "router policy6": set(FGPolicyRoute.model_fields)
    - {
        "source_context",
        "nested_configs",
        "family",
        "source_order",
        "source_explicit_fields",
        "source_attributes",
        "extra_settings",
    },
}


DHCP_EXPLICIT_FIELDS = {
    "system dhcp server": set(FGDHCPServer.model_fields)
    - {
        "source_context", "source_explicit_fields", "extra_settings",
        "nested_configs", "ip_ranges", "exclude_ranges",
        "reserved_addresses", "options",
    },
    "system dhcp server ip-range": set(FGDHCPIPRange.model_fields)
    - {"source_context", "source_explicit_fields", "extra_settings"},
    "system dhcp server exclude-range": set(FGDHCPExcludeRange.model_fields)
    - {"source_context", "source_explicit_fields", "extra_settings"},
    "system dhcp server reserved-address": set(FGDHCPReservation.model_fields)
    - {"source_context", "source_explicit_fields", "extra_settings"},
    "system dhcp server options": set(FGDHCPOption.model_fields)
    - {"source_context", "source_explicit_fields", "extra_settings"},
}

DHCP6_EXPLICIT_FIELDS = {
    "system dhcp6 server": set(FGDHCP6Server.model_fields)
    - {
        "source_context", "source_explicit_fields", "extra_settings",
        "nested_configs", "ip_ranges", "prefix_ranges", "options",
        "family", "source_order", "settings",
    },
    "system dhcp6 server ip-range": set(FGDHCP6IPRange.model_fields)
    - {"source_context", "source_explicit_fields", "extra_settings"},
    "system dhcp6 server prefix-range": set(FGDHCP6PrefixRange.model_fields)
    - {"source_context", "source_explicit_fields", "extra_settings"},
    "system dhcp6 server option": set(FGDHCP6Option.model_fields)
    - {"source_context", "source_explicit_fields", "extra_settings"},
    "system dhcp6 server options": set(FGDHCP6Option.model_fields)
    - {"source_context", "source_explicit_fields", "extra_settings"},
}

FG_INTERFACE_EXPLICIT_FIELDS = {
    "system interface": {
        "vlanid",
        "interface",
        "vrf",
        "member",
        "lacp_mode",
        "lacp_ha_secondary",
        "system_id_type",
        "system_id",
        "lacp_speed",
        "min_links",
        "min_links_down",
        "algorithm",
        "link_up_delay",
        "link_down_delay",
        "aggregate_type",
        "priority_override",
        "aggregate",
        "redundant_interface",
        "distance",
        "priority",
        "gwdetect",
        "ha_priority",
        "ping_serv",
        "dhcp_renew_time",
        "dhcp_relay_service",
        "dhcp_relay_ip",
        "dhcp_relay_type",
        "dhcp_relay_link_selection",
        "dhcp_relay_interface_select_method",
        "dhcp_relay_interface",
        "dhcp_snooping",
        "dhcp_snooping_option82",
        "dhcp_snooping_trust",
        "vlan_protocol",
        "switch",
        "lacp_select_timeout",
        "bandwidth",
        "fec",
        "flowcontrol",
        "fortilink",
        "fortilink_neighbor_detect",
        "auto_auth_extension",
        "security_mode",
        "security_mac_auth",
        "security_exempt_list",
        "security_redirect_url",
        "management_ip",
        "ip_managed_by_fortiipam",
        "defaultgw",
        "dhcp_client_identifier",
    },
}

FG_INTERFACE_AGGREGATE_INT_FIELDS = {
    "min_links",
    "link_up_delay",
    "link_down_delay",
    "lacp_select_timeout",
}

FG_INTERFACE_AGGREGATE_SCALAR_FIELDS = {
    "lacp_mode",
    "lacp_ha_secondary",
    "system_id_type",
    "system_id",
    "lacp_speed",
    "min_links_down",
    "algorithm",
    "aggregate_type",
    "priority_override",
    "aggregate",
    "redundant_interface",
}

FG_DHCP_SERVER_INT_FIELDS = {
    "conflicted_ip_timeout", "ddns_ttl", "ipsec_lease_hold", "lease_time",
}
FG_DHCP_RANGE_INT_FIELDS = {"lease_time"}
FG_DHCP_OPTION_INT_FIELDS = {"code"}


SECTION_EXPLICIT_FIELDS = {
    **SDWAN_EXPLICIT_FIELDS,
    **ROUTE_EXPLICIT_FIELDS,
    **DHCP_EXPLICIT_FIELDS,
    **DHCP6_EXPLICIT_FIELDS,
    **FG_INTERFACE_EXPLICIT_FIELDS,
    "vpn ipsec phase1-interface": set(FGPhase1Common.model_fields)
    - {"extra_settings", "source_explicit_fields"}
    | {"comments"},
    "vpn ipsec phase1": set(FGPhase1Common.model_fields)
    - {"extra_settings", "source_explicit_fields"}
    | {"comments"},
    "firewall security-policy": set(FGSecurityPolicy.model_fields)
    - {"extra_settings", "source_explicit_fields"},
    "firewall shaping-policy": set(FGShapingPolicy.model_fields)
    - {"extra_settings", "source_explicit_fields"},
    "firewall shaper traffic-shaper": set(FGTrafficShaper.model_fields)
    - {"extra_settings"},
    "system zone": set(FGSystemZone.model_fields)
        - {"source_context", "nested_configs", "source_explicit_fields", "extra_settings"},
    "firewall ippool": set(FGIPPool.model_fields)
        - {"source_context", "nested_configs", "source_explicit_fields", "extra_settings"},
    "firewall ippool6": set(FGIPPool6.model_fields)
        - {"source_context", "nested_configs", "source_explicit_fields", "extra_settings"},
    "firewall ipv6-eh-filter": set(FGIPv6EHFilter.model_fields)
        - {"source_context", "source_explicit_fields", "extra_settings"},
    "firewall vip": set(FGVIP.model_fields)
        - {
            "source_context", "nested_configs", "source_explicit_fields",
            "extra_settings", "realservers", "gslb_public_ips", "quic",
            "ssl_cipher_suites", "ssl_server_cipher_suites",
        },
    "firewall vip6": set(FGVIP6.model_fields)
        - {
            "source_context", "nested_configs", "source_explicit_fields",
            "extra_settings", "realservers", "gslb_public_ips", "quic",
            "ssl_cipher_suites", "ssl_server_cipher_suites",
        },
}



SECTION_LIST_FIELDS.setdefault("firewall schedule recurring", set()).add("day")
for _path in ("vpn ipsec phase1-interface", "vpn ipsec phase1"):
    SECTION_LIST_FIELDS.setdefault(_path, set()).update({"dns_suffix_search", "remote_gw_ztna_tags"})
    SECTION_EXPLICIT_FIELDS.setdefault(_path, set()).update({
        "ip_version", "remote_gw_match", "remote_gw_start_ip",
        "remote_gw_subnet", "remote_gw_country", "remote_gw_ztna_tags",
        "cert_trust_store", "cert_peer_username_strip",
        "cert_peer_username_validation", "acct_verify", "default_gw",
        "default_gw_priority", "distance", "priority", "dns_suffix_search",
    })

FGService = FGServiceSessionTimers
FGSystemGlobal = FGSystemGlobalSessionTimers
FGDns = FGDnsMultiValue746
FGAntivirusProfile = FGAntivirusProfile746
FGAntivirusProtocol = FGAntivirusProtocol746
FGAntivirusProfileConfig = FGAntivirusProfileConfig746
FGWebFilterProfile = FGWebFilterProfile746
FGWebFilterCategory = FGWebFilterCategory746
FGWebFilterOverride = FGWebFilterOverride746
FGDNSFilterProfile = FGDNSFilterProfile746
FGDNSFilterCategory = FGDNSFilterCategory746
FGApplicationList = FGApplicationList746
FGApplicationEntry = FGApplicationEntry746
SECTION_EXPLICIT_FIELDS.setdefault("system interface", set()).add("ping_serv_status")
SECTION_EXPLICIT_FIELDS.setdefault("firewall vip", set()).update(FORTIOS_746_VIP_FIELDS)
SECTION_EXPLICIT_FIELDS["firewall ippool_grp"] = {"member"}
SECTION_LIST_FIELDS.setdefault("firewall ippool_grp", set()).add("member")
SECTION_EXPLICIT_FIELDS["firewall address6-template"] = {
    "ip6", "subnet_segment_count", "fabric_object",
}

FG_POLICY_ROUTE_INT_FIELDS = {
    "protocol",
    "start_port",
    "end_port",
    "start_source_port",
    "end_source_port",
}
FG_POLICY_ROUTE_INT_LIST_FIELDS = {"internet_service_id"}
FG_POLICY_ROUTE_SCALAR_FIELDS = {
    "action",
    "comments",
    "dst_negate",
    "gateway",
    "input_device_negate",
    "output_device",
    "src_negate",
    "status",
    "tos",
    "tos_mask",
}

FG_SDWAN_ZONE_INT_FIELDS = {"minimum_sla_meet_members"}
FG_SDWAN_ZONE_SCALAR_FIELDS = {
    "advpn_health_check", "advpn_select", "service_sla_tie_break",
}
FG_SDWAN_HEALTH_CHECK_INT_FIELDS = {
    "class_id", "failtime", "ha_priority", "interval", "packet_size", "port",
    "probe_count", "probe_timeout", "recoverytime", "sla_fail_log_period",
    "sla_id_redistribute", "sla_pass_log_period", "threshold_alert_jitter",
    "threshold_alert_latency", "threshold_alert_packetloss", "threshold_warning_jitter",
    "threshold_warning_latency", "threshold_warning_packetloss", "vrf",
}
FG_SDWAN_HEALTH_CHECK_SLA_INT_FIELDS = {
    "jitter_threshold", "latency_threshold", "packetloss_threshold",
    "priority_in_sla", "priority_out_sla",
}
FG_SDWAN_SERVICE_INT_LIST_FIELDS = {
    "internet_service_app_ctrl", "internet_service_app_ctrl_category", "priority_members",
}
FG_SDWAN_SERVICE_INT_FIELDS = {
    "bandwidth_weight", "start_port", "end_port", "start_src_port", "end_src_port",
    "hold_down_time", "jitter_weight", "latency_weight", "link_cost_threshold",
    "minimum_sla_meet_members", "packet_loss_weight", "protocol", "quality_link",
}
FG_SDWAN_SERVICE_SCALAR_FIELDS = {
    "addr_mode", "agent_exclusive", "default", "dscp_forward", "dscp_forward_tag",
    "dscp_reverse", "dscp_reverse_tag", "dst_negate", "gateway", "hash_mode",
    "input_device_negate", "internet_service", "link_cost_factor", "load_balance",
    "mode", "name", "passive_measurement", "role", "shortcut", "shortcut_priority",
    "sla_compare_method", "sla_stickiness", "src_negate", "standalone_action", "status",
    "strategy", "tie_break", "tos", "tos_mask", "use_shortcut_sla", "zone_mode",
}


FG_INTERFACE_IPV6_SCALAR_FIELDS = {
    "ip6_address",
    "ip6_mode",
    "ip6_send_adv",
    "ip6_manage_flag",
    "ip6_other_flag",
    "autoconf", "cli_conn6_status", "dhcp6_information_request", "dhcp6_prefix_delegation",
    "dhcp6_relay_interface_id", "dhcp6_relay_service",
    "dhcp6_relay_source_interface", "dhcp6_relay_source_ip", "dhcp6_relay_type",
    "icmp6_send_redirect", "interface_identifier", "ip6_default_life",
    "ip6_delegated_prefix_iaid", "ip6_dns_server_override", "ip6_hop_limit",
    "ip6_link_mtu", "ip6_max_interval", "ip6_min_interval", "ip6_prefix_mode",
    "ip6_reachable_time", "ip6_retrans_time", "ip6_subnet", "ip6_upstream_interface",
}
FG_INTERFACE_IPV6_LIST_FIELDS = {"ip6_allowaccess", "dhcp6_client_options", "dhcp6_relay_ip"}
FG_INTERFACE_IPV6_INT_FIELDS = {
    "cli_conn6_status", "ip6_default_life", "ip6_delegated_prefix_iaid", "ip6_hop_limit", "ip6_link_mtu",
    "ip6_max_interval", "ip6_min_interval", "ip6_reachable_time", "ip6_retrans_time",
}
FG_INTERFACE_INT_FIELDS = {
    "bfd_desired_min_tx",
    "bfd_detect_mult",
    "bfd_required_min_rx",
    "bandwidth_measure_time",
    "snmp_index",
    "weight",
    "mtu",
    "tcp_mss",
    "estimated_upstream_bandwidth",
    "estimated_downstream_bandwidth",
    "link_up_delay",
    "link_down_delay",
    "distance",
    "priority",
    "ha_priority",
    "dhcp_renew_time",
    "lacp_select_timeout",
    "bandwidth",
}
FG_INTERFACE_SCALAR_FIELDS = {
    "interface",
    "defaultgw",
    "dhcp_client_identifier",
    "dhcp_broadcast_flag",
    "dhcp_classless_route_addition",
    "dhcp_relay_agent_option",
    "arpforward",
    "broadcast_forward",
    "vlanforward",
    "trunk",
    "bfd",
    "vrrp_virtual_mac",
    "mtu_override",
    "stp",
    "stp_ha_secondary",
    "preserve_session_route",
    "broadcast_forticlient_discovery",
    "drop_overlapped_fragment",
    "drop_fragment",
    "explicit_web_proxy",
    "gwdetect",
    "ping_serv",
    "dhcp_relay_service",
    "dhcp_relay_type",
    "dhcp_relay_link_selection",
    "dhcp_relay_interface_select_method",
    "dhcp_relay_interface",
    "dhcp_snooping",
    "dhcp_snooping_option82",
    "dhcp_snooping_trust",
    "vlan_protocol",
    "switch",
    "fec",
    "flowcontrol",
    "fortilink",
    "fortilink_neighbor_detect",
    "auto_auth_extension",
    "security_mode",
    "security_mac_auth",
    "security_exempt_list",
    "security_redirect_url",
    "management_ip",
    "ip_managed_by_fortiipam",
}

SOURCE_ONLY_RULE_FAMILIES = {
    "firewall security-policy": "security-policy",
    "firewall local-in-policy": "local-in-policy-ipv4",
    "firewall local-in-policy6": "local-in-policy-ipv6",
    "firewall proxy-policy": "proxy-policy",
    "firewall shaping-policy": "shaping-policy",
    "firewall shaper per-ip-shaper": "per-ip-shaper",
    "firewall shaping-profile": "shaping-profile",
    "system dhcp6 server": "dhcp6-server",
    "firewall proxy-addrgrp": "proxy-address-group",
    "vpn ipsec phase1": "ipsec-phase1-policy-mode",
    "vpn ipsec phase2": "ipsec-phase2-policy-mode",
    "vpn ipsec manualkey": "ipsec-manual-key",
    "firewall ttl-policy": "ttl-policy",
    "firewall ldb-monitor": "load-balance-monitor",
    "firewall ssl-server": "ssl-server",
    "firewall traffic-class": "traffic-class",
    "firewall wildcard-fqdn group": "wildcard-fqdn-group",
    "firewall acl": "acl-ipv4",
    "firewall acl6": "acl-ipv6",
    "firewall interface-policy": "interface-policy-ipv4",
    "firewall interface-policy6": "interface-policy-ipv6",
    "firewall access-proxy": "access-proxy-ipv4",
    "firewall access-proxy6": "access-proxy-ipv6",
    "vpn ipsec manualkey-interface": "ipsec-manual-key-interface",
}

POLICY_ROUTE_FAMILIES = {
    "router policy": "policy-route-ipv4",
    "router policy6": "policy-route-ipv6",
}

CONTEXTUAL_MODEL_SECTIONS = {
    "firewall ippool_grp",
    "system zone", "system interface",
    "firewall address", "firewall address6", "firewall address6-template",
    "firewall multicast-address", "firewall multicast-address6",
    "firewall addrgrp", "firewall addrgrp6",
    "firewall wildcard-fqdn custom",
    "firewall service category",
    "firewall service custom", "firewall service group",
    "firewall schedule recurring", "firewall schedule onetime",
    "firewall schedule group", "firewall shaper traffic-shaper",
    "firewall proxy-address", "firewall ippool", "firewall ippool6",
    "firewall vip", "firewall vip6", "firewall vipgrp", "firewall vipgrp6",
    "firewall policy", "firewall central-snat-map", "firewall ip-translation",
    "firewall multicast-policy", "firewall multicast-policy6",
    "router policy", "router policy6",
    "vpn ipsec phase1-interface", "vpn ipsec phase2-interface",
    "router static", "router static6",
    "ips sensor",
    "system dhcp server",
    "system dns-server", "system dns64",
    "firewall DoS-policy", "firewall DoS-policy6",
    *SOURCE_ONLY_RULE_FAMILIES,
}

IDENTITY_SECTIONS = {"user ldap", "user saml", "user local", "user fsso"}
IDENTITY_SECRET_FIELDS = {
    "password",
    "password2",
    "password3",
    "password4",
    "password5",
    "passwd",
    "seed",
    "activation_code",
    "private_key",
    "ppk_secret",
    "bind_password",
    "bind_secret",
}
ADMIN_SECRET_FIELDS = IDENTITY_SECRET_FIELDS | {"secret", "token", "api_key"}

FORTIOS_UINT32_RANGE = (0, 4294967295)
FORTIOS_UINT8_RANGE = (0, 255)
FG_IS_EXTENSION_DISABLE_ENTRY_ID_RANGE = FORTIOS_UINT32_RANGE
FG_IS_EXTENSION_ENTRY_ID_RANGE = FORTIOS_UINT8_RANGE
FG_IS_EXTENSION_IP_RANGE_ID_RANGE = FORTIOS_UINT32_RANGE
FG_IS_EXTENSION_IP6_RANGE_ID_RANGE = FORTIOS_UINT32_RANGE
FG_IS_EXTENSION_PORT_RANGE_ID_RANGE = FORTIOS_UINT32_RANGE
FG_IS_EXTENSION_ADDR_MODES = frozenset({"ipv4", "ipv6"})


def _classify_pppoe_password(values: List[str]) -> tuple[bool, Optional[str]]:
    if not values:
        return False, None
    value = " ".join(str(item) for item in values).strip()
    if not value:
        return False, None
    return True, "encrypted" if value.upper().startswith("ENC ") else "plaintext"


def _initialize_section_registry() -> None:
    """Register the parser's static section metadata once at module import."""

    models = {
        "system interface": FGInterface,
        "system zone": FGSystemZone,
        "firewall wildcard-fqdn custom": FGWildcardFQDN,
        "firewall service category": FGServiceCategory,
        "firewall address": FGAddress,
        "firewall address6": FGAddress,
        "firewall address6-template": FGAddress6Template,
        "firewall addrgrp": FGAddressGroup,
        "firewall addrgrp6": FGAddressGroup,
        "firewall service custom": FGService,
        "firewall service group": FGServiceGroup,
        "firewall proxy-address": FGProxyAddress,
        "firewall schedule recurring": FGSchedule,
        "firewall schedule onetime": FGSchedule,
        "firewall schedule group": FGScheduleGroup,
        "firewall ippool": FGIPPool,
        "firewall ippool6": FGIPPool6,
        "firewall ippool_grp": FGIPPoolGroup,
        "endpoint-control fctems": FGFCTEMS,
        "user adgrp": FGADGroup,
        "user saml": FGUserSAML,
        "system dns-server": FGDnsServer,
        "firewall vip": FGVIP,
        "firewall vip6": FGVIP6,
        "firewall vipgrp": FGVIPGroup,
        "firewall vipgrp6": FGVIPGroup6,
        "firewall vip realservers": FGVIPRealServer,
        "firewall vip6 realservers": FGVIPRealServer,
        "system interface secondaryip": FGInterfaceSecondaryIP,
        "firewall policy": FGPolicy,
        "firewall security-policy": FGSecurityPolicy,
        "firewall shaping-policy": FGShapingPolicy,
        "firewall central-snat-map": FGCentralSNATRule,
        "router static": FGStaticRoute,
        "router static6": FGStaticRoute,
        "router policy": FGPolicyRoute,
        "router policy6": FGPolicyRoute,
        "system dhcp server": FGDHCPServer,
        "system dhcp6 server": FGDHCP6Server,
        "system dns": FGDns,
        "authentication scheme": FGAuthenticationScheme,
        "authentication rule": FGAuthenticationRule,
        "vpn ipsec phase1-interface": FGPhase1Interface,
        "vpn ipsec phase1": FGPhase1Policy,
        "vpn ipsec phase2-interface": FGPhase2Interface,
        "vpn ipsec phase2": FGPhase2Policy,
    }
    common_list_fields = {
        "allowaccess", "detectprotocol", "dhcp_relay_ip", "member", "day",
        "srcintf", "dstintf", "srcaddr", "dstaddr", "dst", "dst6",
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
        "firewall service category": "service_categories",
        "firewall address": "addresses",
        "firewall address6": "addresses",
        "firewall address6-template": "address6_templates",
        "firewall addrgrp": "address_groups",
        "firewall addrgrp6": "address_groups",
        "firewall service custom": "services",
        "firewall service group": "service_groups",
        "firewall proxy-address": "proxy_addresses",
        "firewall schedule recurring": "schedules",
        "firewall schedule onetime": "schedules",
        "firewall schedule group": "schedule_groups",
        "firewall ippool": "ip_pools",
        "firewall ippool6": "ip_pools6",
        "firewall ippool_grp": "ip_pool_groups",
        "endpoint-control fctems": "fctems_connectors",
        "user adgrp": "ad_groups",
        "user saml": "user_saml_servers",
        "system dns-server": "dns_servers",
        "firewall vip": "vips",
        "firewall vip6": "vips6",
        "firewall vipgrp": "vip_groups",
        "firewall vipgrp6": "vip_groups6",
        "firewall policy": "policies",
        "firewall security-policy": "security_policies",
        "firewall shaping-policy": "shaping_policies",
        "firewall central-snat-map": "central_snat_rules",
        "router static": "static_routes",
        "router static6": "static_routes",
        "router policy": "policy_routes",
        "router policy6": "policy_routes",
        "system dhcp server": "dhcp_servers",
        "system dhcp6 server": "dhcp6_servers",
        "authentication scheme": "authentication_schemes",
        "authentication rule": "authentication_rules",
        "vpn ipsec phase1-interface": "phase1_interfaces",
        "vpn ipsec phase1": "phase1_policies",
        "vpn ipsec phase2-interface": "phase2_interfaces",
        "vpn ipsec phase2": "phase2_policies",
    }
    integer_fields = {
        path: set(fields) for path, fields in SECTION_INTEGER_FIELDS.items()
    }
    integer_fields.update({
        "router policy": FG_POLICY_ROUTE_INT_FIELDS,
        "router policy6": FG_POLICY_ROUTE_INT_FIELDS,
        "system sdwan zone": FG_SDWAN_ZONE_INT_FIELDS,
        "system sdwan health-check": FG_SDWAN_HEALTH_CHECK_INT_FIELDS,
        "system sdwan health-check sla": FG_SDWAN_HEALTH_CHECK_SLA_INT_FIELDS,
        "system sdwan service": FG_SDWAN_SERVICE_INT_FIELDS,
        "system dhcp server": FG_DHCP_SERVER_INT_FIELDS,
        "system dhcp server ip-range": FG_DHCP_RANGE_INT_FIELDS,
        "system dhcp server options": FG_DHCP_OPTION_INT_FIELDS,
        "authentication scheme": {"saml_timeout"},
        "system global": SYSTEM_GLOBAL_SESSION_TIMER_FIELDS,
        "system session-ttl port": SESSION_TTL_OVERRIDE_INT_FIELDS,
    })
    integer_list_fields = {
        path: set(fields) for path, fields in SECTION_INTEGER_LIST_FIELDS.items()
    }
    integer_list_fields.update({
        "router policy": FG_POLICY_ROUTE_INT_LIST_FIELDS,
        "router policy6": FG_POLICY_ROUTE_INT_LIST_FIELDS,
        "system sdwan service": FG_SDWAN_SERVICE_INT_LIST_FIELDS,
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
        path: IDENTITY_SECRET_FIELDS for path in IDENTITY_SECTIONS
    }
    secret_fields.update({
        "system admin": ADMIN_SECRET_FIELDS,
        "vpn ipsec phase1": {"psksecret", "psksecret_remote", "authpasswd", "group_authentication_secret", "ppk_secret"},
        "vpn ipsec phase1-interface": {"psksecret", "psksecret_remote", "authpasswd", "group_authentication_secret", "ppk_secret"},
    })
    paths = (
        set(models)
        | set(list_fields)
        | set(SECTION_EXPLICIT_FIELDS)
        | CONTEXTUAL_MODEL_SECTIONS
        | STRUCTURED_SECURITY_SECTIONS
        | STRUCTURED_ROUTING_SECTIONS
        | STRUCTURED_ROUTING_DEPENDENCY_SECTIONS
        | STRUCTURED_IDENTITY_SECTIONS
        | STRUCTURED_OPERATIONAL_SECTIONS
    )
    register_sections(
        paths,
        models=models,
        destination_collections=destination_collections,
        list_fields=list_fields,
        integer_fields=integer_fields,
        integer_list_fields=integer_list_fields,
        scalar_fields=scalar_fields,
        explicit_fields=SECTION_EXPLICIT_FIELDS,
        secret_fields=secret_fields,
    )


_initialize_section_registry()

STANDARD_SECTION_PATHS = frozenset({
    "system zone",
    "firewall wildcard-fqdn custom",
    "firewall service category",
    "firewall service group",
    "firewall schedule group",
    "firewall proxy-address",
    "firewall ippool6",
    "endpoint-control fctems",
    "user adgrp",
    "user saml",
    "authentication scheme",
    "authentication rule",
    "system dns-server",
})

def _extract_extra_settings(
    attributes: Dict[str, Any],
    model_fields: set[str],
) -> Dict[str, Any]:
    """
    Remove attributes that are not represented by typed model fields
    and retain a sanitized audit copy.

    Secret-like source settings are redacted through the shared
    FortiGate source-attribute sanitizer before being preserved.
    """

    unknown_attributes = {
        key: value
        for key, value in attributes.items()
        if key not in model_fields
    }

    extra_settings = sanitize_source_attributes(
        unknown_attributes
    )

    for key in unknown_attributes:
        attributes.pop(key, None)

    return extra_settings


def _apply_address_defaults(
    section_path: str,
    attributes: Dict[str, Any],
) -> None:
    """Record FortiOS effective address defaults without source invention."""

    defaults = dict(attributes.get("source_effective_defaults") or {})

    def set_default(key: str, value: Any) -> None:
        if key not in attributes:
            attributes[key] = value
            defaults[key] = value

    if section_path == "firewall address":
        set_default("type", "ipmask")
        if attributes.get("type") == "ipmask":
            set_default("subnet", "0.0.0.0 0.0.0.0")
    elif section_path == "firewall address6":
        set_default("type", "ipprefix")
        if attributes.get("type") == "ipprefix":
            set_default("ip6", "::/0")
    elif section_path == "firewall multicast-address":
        set_default("type", "multicastrange")
        if attributes.get("type") == "multicastrange":
            set_default("start_ip", "0.0.0.0")
            set_default("end_ip", "0.0.0.0")
        elif attributes.get("type") == "broadcastmask":
            set_default("subnet", "0.0.0.0 0.0.0.0")
    elif section_path == "firewall multicast-address6":
        set_default("ip6", "::/0")

    if defaults:
        attributes["source_effective_defaults"] = defaults


def _parse_bounded_int(
    value: Any,
    *,
    minimum: int,
    maximum: int,
    field_name: str,
    extra_settings: Dict[str, Any],
) -> Optional[int]:
    if value is None or isinstance(value, bool):
        if value is not None:
            extra_settings.setdefault("unparsed_fields", {})[field_name] = value
            extra_settings.setdefault(f"unparsed_{field_name}", value)
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        extra_settings.setdefault("unparsed_fields", {})[field_name] = value
        extra_settings.setdefault(f"unparsed_{field_name}", value)
        return None
    if parsed < minimum or parsed > maximum:
        extra_settings.setdefault("invalid_fields", {})[field_name] = value
        return None
    return parsed


def _parse_enum(
    value: Any,
    *,
    field_name: str,
    allowed: set[str],
    extra_settings: Dict[str, Any],
) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).lower()
    if normalized in allowed:
        return normalized
    extra_settings.setdefault("invalid_fields", {})[field_name] = value
    return None


def _typed_internet_item(
    raw: Dict[str, Any],
    model: Any,
    *,
    int_ranges: Dict[str, tuple[int, int]] = None,
    enums: Dict[str, set[str]] = None,
) -> Any:
    attributes = dict(raw)
    validation_settings: Dict[str, Any] = {}
    source_name = attributes.pop("name", None)
    if "id" not in attributes:
        if "id" in model.model_fields:
            attributes["id"] = None
        if source_name is not None:
            validation_settings.setdefault("unparsed_fields", {})["id"] = source_name
    elif source_name is not None and source_name != str(attributes.get("id")):
        validation_settings.setdefault("unparsed_fields", {})["id"] = source_name

    for field, (minimum, maximum) in (int_ranges or {}).items():
        if field in attributes:
            attributes[field] = _parse_bounded_int(
                attributes[field],
                minimum=minimum,
                maximum=maximum,
                field_name=field,
                extra_settings=validation_settings,
            )
    for field, allowed in (enums or {}).items():
        if field in attributes:
            attributes[field] = _parse_enum(
                attributes[field],
                field_name=field,
                allowed=allowed,
                extra_settings=validation_settings,
            )
    attributes.update(validation_settings)
    attributes["extra_settings"] = _extract_extra_settings(
        attributes, set(model.model_fields)
    )
    return model(**attributes)


def _append_repeated_setting(
    attributes: Dict[str, Any], key: str, values: List[str]
) -> None:
    value: Any = values[0] if len(values) == 1 else list(values)
    if key not in attributes:
        attributes[key] = value
        return
    previous = attributes[key]
    if not isinstance(previous, list):
        previous = [previous]
    attributes[key] = previous + (value if isinstance(value, list) else [value])


def _repeated_command_attributes(commands: List[Any]) -> Dict[str, Any]:
    attributes: Dict[str, Any] = {}
    for command in commands:
        _append_repeated_setting(
            attributes, command.key.replace("-", "_"), command.values
        )
    return attributes


def _typed_profile_node(node: FGSourceNode) -> FGProfileNestedSection:
    settings: Dict[str, Any] = {}
    for command in node.commands:
        key = command.key.replace("-", "_")
        value: Any = list(command.values)
        if len(value) == 1:
            value = value[0]
        settings.update(sanitize_source_attributes({key: value}))
    entries = [_typed_profile_node(child) for child in node.children]
    return FGProfileNestedSection(name=node.name, settings=settings, entries=entries)

class ParserError(Exception):
    pass


class FortiGateParser:
    def __init__(self, tokenizer: FortiGateTokenizer):
        self.tokens = list(tokenizer.tokenize())
        self.pos = 0
        self.config = FGConfig()
        self.source_inventory_items: List[SourceInventoryItem] = []
        self.structured_source_objects: List[FGStructuredSourceObject] = []
        self.current_context = "root"
        self._source_order = 0

    def peek(self) -> Optional[Token]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None

    def next_token(self) -> Optional[Token]:
        token = self.peek()
        if token:
            self.pos += 1
        return token

    def _sdwan_for_current_context(self) -> FGSDWan:
        """Return the SD-WAN configuration owned by the active VDOM."""
        source_context = self.current_context or "root"
        for sdwan in self.config.sdwans:
            if sdwan.source_context == source_context:
                return sdwan

        sdwan = FGSDWan(source_context=source_context)
        self.config.sdwans.append(sdwan)
        return sdwan

    def consume(self, expected_type: TokenType) -> Token:
        token = self.next_token()

        if not token:
            raise ParserError(
                f"Expected {expected_type}, but reached end of file"
            )

        if token.type != expected_type:
            raise ParserError(
                f"Expected {expected_type} at line "
                f"{token.line_number}, got {token.type} ({token.value})"
            )

        return token

    def parse(self) -> FGConfig:
        while self.peek():
            token = self.next_token()

            if token.type == TokenType.COMMENT:
                self._parse_header_comment(token.value)
                continue

            elif token.type == TokenType.CONFIG:
                self.parse_config_block("")

            else:
                pass

        _refresh_interface_ipv6_from_source(self.config, sys.modules[__name__])
        _refresh_policy_address_families(self.config)
        return self.config

    def _parse_header_comment(self, value: str) -> None:
        """Extract recognized FortiOS header metadata without changing comments."""
        config_version = re.match(
            r"^#\s*config-version\s*=\s*(.+)$",
            value,
            flags=re.IGNORECASE,
        )
        if config_version:
            header = config_version.group(1)
            version = re.search(r"(?:^|-)(\d+\.\d+\.\d+)(?:-|:|$)", header)
            build = re.search(r"(?:^|-)build(\d+)(?:-|:|$)", header, re.IGNORECASE)
            if version:
                self.config.source_version = version.group(1)
            if build:
                self.config.source_build = build.group(1)
            return

        build_number = re.match(
            r"^#\s*buildno\s*=\s*(\d+)",
            value,
            flags=re.IGNORECASE,
        )
        if build_number and not self.config.source_build:
            self.config.source_build = build_number.group(1)

    def parse_config_block(self, parent_path: str):
        current_path = self.read_section_name()

        if not current_path:
            return

        full_path = f"{parent_path} {current_path}".strip()
        self.parse_config_contents(full_path)

    def read_section_name(self) -> str:
        section_parts = []

        while self.peek() and self.peek().type == TokenType.STRING:
            section_parts.append(self.next_token().value)

        return " ".join(section_parts)

    def parse_config_contents(self, full_path: str):
        root = self.parse_source_node("config", full_path)
        self._process_config_source_node(full_path, root)
        return

    def _process_config_source_node(self, full_path: str, root: FGSourceNode) -> None:
        if full_path == "vdom":
            previous_context = self.current_context
            for vdom in (child for child in root.children if child.node_type == "edit"):
                self.current_context = vdom.name
                self._execution_context(vdom.name)
                for child in vdom.children:
                    if child.node_type == "config":
                        self._process_config_source_node(child.name, child)
            self.current_context = previous_context
            return

        if full_path in (
            STRUCTURED_SECURITY_SECTIONS
            | STRUCTURED_ROUTING_SECTIONS
            | STRUCTURED_ROUTING_DEPENDENCY_SECTIONS
            | STRUCTURED_IDENTITY_SECTIONS
            | STRUCTURED_OPERATIONAL_SECTIONS
        ):
            self._parse_structured_source_section(full_path, root)
            return

        known_edit_or_global_sections = {
            "system settings", "system global", "system dns",
            "system session-ttl", "system session-ttl port",
            "system sdwan", "system sdwan zone", "system sdwan members",
            "system sdwan health-check", "system sdwan service",
            "system sdwan duplication", "system sdwan neighbor",
            "vpn ssl settings", "vpn ssl settings authentication-rule",
            "user setting", "user quarantine", "web-proxy global",
            "firewall internet-service-name",
            "firewall internet-service-definition",
            "firewall internet-service-addition",
            "firewall internet-service-append",
            "firewall internet-service-custom",
            "firewall internet-service-custom-group",
            "firewall internet-service-extension",
            "firewall internet-service-group",
            "vpn certificate remote", "vpn certificate local", "vpn certificate ca",
            "certificate remote", "certificate local", "certificate ca",
            "firewall ssh local-key", "firewall ssh local-ca",
            "system session-helper",
            "endpoint-control fctems", "user ldap", "user fsso", "user adgrp",
            "user saml", "user local", "user group", "system admin",
            "system accprofile", "user fortitoken", "vpn ssl web portal",
            "vpn ssl web host-check-software", "firewall sniffer",
            "authentication scheme", "authentication rule",
            "firewall ipv6-eh-filter",
        }
        if full_path not in CONTEXTUAL_MODEL_SECTIONS | known_edit_or_global_sections:
            self._parse_unknown_source_section(full_path, root)
            return

        saw_edit = False
        for child in root.children:
            if child.node_type == "edit":
                saw_edit = True
                self.build_model(full_path, self._project_edit_source_node(full_path, child))
                continue
            if child.node_type != "config":
                continue
            nested_path = f"{full_path} {child.name}".strip()
            if full_path == "vpn ssl settings" and child.name == "authentication-rule":
                self._attach_ssl_vpn_authentication_rules([
                    self._project_edit_source_node(nested_path, entry)
                    for entry in child.children
                    if entry.node_type == "edit"
                ])
            else:
                self._process_config_source_node(nested_path, child)

        spec = get_section_spec(full_path)
        evaluated = evaluate_section_commands(full_path, root.commands, spec)
        direct_attributes = {**evaluated.attributes, **evaluated.extra_settings}
        if evaluated.explicit_fields:
            direct_attributes["source_explicit_fields"] = evaluated.explicit_fields

        for command in root.commands:
            if command.operation == "set":
                if full_path == "firewall internet-service-append":
                    continue
                self.apply_global_set(full_path, command.key, list(command.values))
            elif command.operation == "unset":
                if full_path == "firewall internet-service-append":
                    continue
                self.apply_global_unset(full_path, command.key)
            elif command.operation == "append" and full_path == "system dns":
                clean_key = self._normalize_attribute_key(command.key)
                if clean_key == "server_hostname":
                    values = evaluated.attributes.get(clean_key, [])
                    self.apply_global_set(full_path, command.key, list(values))

        if full_path == "firewall internet-service-append" and not saw_edit:
            self.build_model(full_path, direct_attributes)

        if root.commands:
            inventory = self._source_node_inventory(root, full_path)
            if full_path == "firewall ipv6-eh-filter" and self.config.ipv6_eh_filter:
                item = self.config.ipv6_eh_filter
                inventory.source_attributes = item.model_dump(
                    exclude={"source_context", "source_explicit_fields", "extra_settings"}
                )
                inventory.source_attributes.update({
                    "source_explicit_fields": sorted(item.source_explicit_fields),
                    "source_effective_settings": effective_ipv6_eh_filter_settings(item),
                    "review_reasons": validate_ipv6_eh_filter_746(item),
                    "additional_settings": dict(item.extra_settings),
                })
                inventory.notes.extend(
                    f"validation:{reason}"
                    for reason in inventory.source_attributes["review_reasons"]
                )
            self.source_inventory_items.append(inventory)

    def _parse_unknown_source_section(
        self,
        source_path: str,
        root: Optional[FGSourceNode] = None,
    ) -> None:
        """Capture an unregistered config block without interpreting it."""
        root = root or self.parse_source_node("config", source_path)
        structured = FGStructuredSourceObject(
            source_path=source_path,
            source_context=self.current_context or "root",
            root=root,
        )
        self.structured_source_objects.append(structured)
        self.config.structured_source_objects.append(structured)

        # Existing source inventory consumers expect edited objects at the
        # top level.  Retain that shape while the structured source object
        # above preserves the complete config/edit hierarchy.
        edit_children = [child for child in root.children if child.node_type == "edit"]
        if edit_children:
            for child in edit_children:
                inventory = self._source_node_inventory(child, source_path, child.name)
                inventory.notes.append("unknown-section-source-fallback")
                self.source_inventory_items.append(inventory)
        elif root.commands or root.children:
            inventory = self._source_node_inventory(root, source_path)
            inventory.notes.append("unknown-section-source-fallback")
            self.source_inventory_items.append(inventory)


    def _execution_context(self, vdom: Optional[str] = None) -> FGExecutionContext:
        context_name = vdom or self.current_context or "root"
        for context in self.config.execution_contexts:
            if context.vdom == context_name:
                return context
        context = FGExecutionContext(vdom=context_name)
        self.config.execution_contexts.append(context)
        return context

    def _parse_structured_source_section(
        self,
        source_path: str,
        root: Optional[FGSourceNode] = None,
    ) -> None:
        root = root or self.parse_source_node("config", source_path)
        top_edits = [child for child in root.children if child.node_type == "edit"]
        current_ctx = self.current_context or "root"
        objects = [
            FGStructuredSourceObject(
                source_path=source_path,
                name=child.name,
                source_id=child.name if child.name.isdigit() else None,
                source_context=current_ctx,
                root=child,
            )
            for child in top_edits
        ]
        if root.commands or any(child.node_type != "edit" for child in root.children):
            objects.append(FGStructuredSourceObject(source_path=source_path, source_context=current_ctx, root=root))
        if not objects:
            objects.append(FGStructuredSourceObject(source_path=source_path, source_context=current_ctx, root=root))

        for source_object in objects:
            self.structured_source_objects.append(source_object)
            self.config.structured_source_objects.append(source_object)
            inventory = self._source_node_inventory(
                source_object.root,
                source_path,
                source_object.name,
            )
            if source_path in STRUCTURED_ROUTING_SECTIONS:
                note = "structured-routing-protocol"
            elif source_path in STRUCTURED_ROUTING_DEPENDENCY_SECTIONS:
                note = "structured-routing-dependency"
            elif source_path in STRUCTURED_IDENTITY_SECTIONS:
                note = "structured-identity-routing"
            elif source_path in STRUCTURED_OPERATIONAL_SECTIONS:
                note = "structured-operational-config"
            else:
                note = "structured-security-profile"
            inventory.notes.append(note)
            self.source_inventory_items.append(inventory)

        self._build_structured_typed_parents(source_path, top_edits if top_edits else [root])

    def _build_structured_typed_parents(
        self,
        source_path: str,
        top_edits: List[FGSourceNode],
    ) -> None:
        """Expose common fields while keeping the recursive source tree authoritative."""
        if source_path == "ips sensor":
            _build_ips_sensor(self, top_edits)
            return
        models: Dict[str, tuple[str, Any]] = {
            "firewall network-service-dynamic": ("network_service_dynamics", FGNetworkServiceDynamic),
            "system sdn-connector": ("sdn_connectors", FGSDNConnector),
            "user radius": ("radius_servers", FGUserRADIUS),
            "user fsso-polling": ("fsso_polling", FGFSSOPolling),
            "firewall profile-group": ("profile_groups", FGProfileGroup),
            "user tacacs+": ("tacacs_servers", FGUserTACACS),
            "system link-monitor": ("link_monitors", FGLinkMonitor),
            "system dns-server": ("dns_servers", FGDnsServer),
            "system dns64": ("dns64_settings", FGDns64),
            "system switch-interface": ("topology_objects", FGTopologyObject),
            "system virtual-wire-pair": ("virtual_wire_pairs", FGVirtualWirePair),
            "system vdom-link": ("vdom_links", FGVDOMLink),
            "system pppoe-interface": ("topology_objects", FGTopologyObject),
            "firewall access-proxy": ("access_proxies", FGAccessProxy),
            "firewall access-proxy6": ("access_proxies", FGAccessProxy),
            "firewall access-proxy-virtual-host": ("access_proxies", FGAccessProxy),
            "firewall access-proxy-ssh-client-cert": ("access_proxies", FGAccessProxy),
            "endpoint-control fctems-override": ("ems_overrides", FGEMSOverride),
            "vpn ssl web realm": ("ssl_vpn_realms", FGSSLVPNRealm),
            "vpn ssl web user-bookmark": ("ssl_vpn_bookmarks", FGSSLVPNBookmark),
            "vpn ssl web group-bookmark": ("ssl_vpn_bookmarks", FGSSLVPNBookmark),
            "vpn ipsec manualkey-interface": ("manualkey_interfaces", FGManualKeyInterface),
            "antivirus profile": ("antivirus_profiles", FGAntivirusProfile),
            "webfilter profile": ("webfilter_profiles", FGWebFilterProfile),
            "dnsfilter profile": ("dnsfilter_profiles", FGDNSFilterProfile),
            "application list": ("application_lists", FGApplicationList),
            "application custom": ("application_lists", FGApplicationList),
            "firewall ssl-ssh-profile": ("ssl_ssh_profiles", FGSSLSSHProfile),
            "certificate remote": ("certificates", FGCertificate),
            "certificate local": ("certificates", FGCertificate),
            "certificate ca": ("certificates", FGCertificate),
        }
        target = models.get(source_path)
        if target is None:
            return
        collection_name, model = target
        list_fields = {
            "srcintf", "members", "member", "virtual_hosts", "realservers",
            "capabilities", "groups", "users", "protocol", "class",
            "switch_controller_service_type",
        }
        access_proxy_list_fields = {
            "srcintf", "alias", "realservers", "ssl_ciphers"
        }
        if source_path == "system link-monitor":
            list_fields.add("server")
        secret_fields = {
            "password", "passwd", "secret", "psksecret", "token", "key", "key2", "key3",
            "api_key", "key_string", "private_key", "encryption_key",
            "authentication_key", "auth_key", "secondary_key", "tertiary_key",
            "bind_password", "bind_secret", "tertiary_secret",
        }
        for node in top_edits:
            if model is FGAccessProxy:
                attributes = {
                    "name": node.name,
                    "source_context": self.current_context or "root",
                    "nested_configs": list(node.children),
                }
                for command in node.commands:
                    key = command.key.replace("-", "_")
                    if key in secret_fields:
                        attributes["extra_settings"] = attributes.get("extra_settings", {})
                        attributes["extra_settings"][f"has_{key}"] = bool(command.values)
                        continue
                    value: Any = (
                        list(command.values)
                        if key in access_proxy_list_fields or len(command.values) > 1
                        else (command.values[0] if command.values else True)
                    )
                    attributes[key] = value
                attributes["family"] = "ipv6" if source_path.endswith("6") else "ipv4"
                if "port" in attributes:
                    try:
                        attributes["port"] = int(attributes["port"])
                    except (TypeError, ValueError):
                        attributes.setdefault("extra_settings", {})["port_raw"] = attributes.pop("port")
                if source_path == "firewall access-proxy-virtual-host":
                    host_fields = set(FGAccessProxyVirtualHost.model_fields) - {"name", "extra_settings"}
                    host_values = {key: value for key, value in attributes.items() if key in host_fields}
                    for field in ("alias", "ssl_ciphers", "ssl_certificate"):
                        if field in host_values and not isinstance(host_values[field], list):
                            host_values[field] = [host_values[field]]
                    attributes["virtual_hosts"] = [FGAccessProxyVirtualHost(name=node.name, **host_values)]
                attributes["extra_settings"] = sanitize_source_attributes(
                    attributes.get("extra_settings", {})
                )
                for child in node.children:
                    child_name = child.name.lower().replace("-", "_")
                    entries = [
                        _typed_profile_node(entry)
                        for entry in child.children
                        if entry.node_type == "edit"
                    ]
                    if child_name in {"destination", "destinations", "api_gateway", "api_gateway6", "realserver", "realservers"}:
                        target_bucket = (
                            "servers" if "realserver" in child_name else "destinations"
                        )
                        target_model = FGAccessProxyServer if target_bucket == "servers" else FGAccessProxyDestination
                        for entry in entries:
                            values = dict(entry.settings)
                            values["name"] = entry.name
                            known = set(target_model.model_fields) - {"name", "extra_settings"}
                            for field in ("alias", "realservers", "ssl_ciphers", "ssl_certificate"):
                                if field in values and not isinstance(values[field], list):
                                    values[field] = [values[field]]
                            values["extra_settings"] = sanitize_source_attributes(
                                {key: value for key, value in values.items() if key not in known and key != "name"}
                            )
                            values = {key: value for key, value in values.items() if key in known or key == "name" or key == "extra_settings"}
                            if "port" in values:
                                try:
                                    values["port"] = int(values["port"])
                                except (TypeError, ValueError):
                                    values["extra_settings"]["port_raw"] = values.pop("port")
                            if "weight" in values:
                                try:
                                    values["weight"] = int(values["weight"])
                                except (TypeError, ValueError):
                                    values["extra_settings"]["weight_raw"] = values.pop("weight")
                            attributes.setdefault(target_bucket, []).append(target_model(**values))
                    elif "virtual" in child_name or "host" in child_name:
                        for entry in entries:
                            values = dict(entry.settings)
                            values["name"] = entry.name
                            known = set(FGAccessProxyVirtualHost.model_fields) - {"name", "extra_settings"}
                            for field in ("alias", "ssl_ciphers", "ssl_certificate"):
                                if field in values and not isinstance(values[field], list):
                                    values[field] = [values[field]]
                            values["extra_settings"] = sanitize_source_attributes(
                                {key: value for key, value in values.items() if key not in known and key != "name"}
                            )
                            values = {key: value for key, value in values.items() if key in known or key in {"name", "extra_settings"}}
                            for field in ("port",):
                                if field in values:
                                    try:
                                        values[field] = int(values[field])
                                    except (TypeError, ValueError):
                                        values["extra_settings"][f"{field}_raw"] = values.pop(field)
                            attributes.setdefault("virtual_hosts", []).append(FGAccessProxyVirtualHost(**values))
                    elif child_name == "cert_extension":
                        for entry in entries:
                            values = dict(entry.settings)
                            values["name"] = entry.name
                            known = set(FGAccessProxySSHClientCertExtension.model_fields) - {"name", "extra_settings"}
                            values["extra_settings"] = sanitize_source_attributes(
                                {key: value for key, value in values.items() if key not in known and key != "name"}
                            )
                            values = {
                                key: value for key, value in values.items()
                                if key in known or key in {"name", "extra_settings"}
                            }
                            attributes.setdefault("cert_extensions", []).append(
                                FGAccessProxySSHClientCertExtension(**values)
                            )
                    elif "mapping" in child_name or "rule" in child_name:
                        for entry in entries:
                            values = dict(entry.settings)
                            values["name"] = entry.name
                            known = set(FGAccessProxyMapping.model_fields) - {"name", "extra_settings"}
                            if "realservers" in values and not isinstance(values["realservers"], list):
                                values["realservers"] = [values["realservers"]]
                            values["extra_settings"] = sanitize_source_attributes(
                                {key: value for key, value in values.items() if key not in known and key != "name"}
                            )
                            values = {key: value for key, value in values.items() if key in known or key in {"name", "extra_settings"}}
                            if "port" in values:
                                try:
                                    values["port"] = int(values["port"])
                                except (TypeError, ValueError):
                                    values["extra_settings"]["port_raw"] = values.pop("port")
                            attributes.setdefault("mappings", []).append(FGAccessProxyMapping(**values))
                    else:
                        attributes.setdefault("entries", []).extend(entries)
                getattr(self.config, collection_name).append(FGAccessProxy(**attributes))
                continue
            if model is FGSecurityProfile:
                settings: Dict[str, Any] = {}
                for command in node.commands:
                    key = command.key.replace("-", "_")
                    value: Any = list(command.values)
                    if len(value) == 1:
                        value = value[0]
                    settings.update(sanitize_source_attributes({key: value}))
                profile = FGSecurityProfile(name=node.name, settings=settings)
                for child in node.children:
                    typed = _typed_profile_node(child)
                    bucket = profile.entries
                    child_name = child.name.lower()
                    if child_name in {"http", "ftp", "smtp", "imap", "pop3", "nntp", "ssh"}:
                        bucket = profile.protocols
                    elif "category" in child_name or "filter" in child_name:
                        bucket = profile.categories
                    elif "override" in child_name:
                        bucket = profile.overrides
                    elif "url" in child_name:
                        bucket = profile.url_filters
                    elif "domain" in child_name:
                        bucket = profile.domain_filters
                    elif "botnet" in child_name:
                        bucket = profile.botnet_controls
                    elif "exempt" in child_name:
                        bucket = profile.exemptions
                    bucket.append(typed)
                getattr(self.config, collection_name).append(profile)
                continue
            if model in {FGAntivirusProfile, FGWebFilterProfile}:
                def node_settings(source: FGSourceNode) -> Dict[str, Any]:
                    settings: Dict[str, Any] = {}
                    for command in source.commands:
                        key = command.key.replace("-", "_")
                        value: Any = list(command.values)
                        if len(value) == 1:
                            value = value[0]
                        settings.update(sanitize_source_attributes({key: value}))
                    return settings

                def child_values(source: FGSourceNode, child_model: Any) -> Dict[str, Any]:
                    values = node_settings(source)
                    known = set(child_model.model_fields) - {"name", "settings", "extra_settings"}
                    return {
                        key: value for key, value in values.items() if key in known
                    }

                profile_values = node_settings(node)
                profile = model(name=node.name, **{
                    key: value for key, value in profile_values.items()
                    if key in model.model_fields and key != "name"
                })
                profile.extra_settings = sanitize_source_attributes({
                    key: value for key, value in profile_values.items()
                    if key not in model.model_fields
                })
                for child in node.children:
                    child_name = child.name.lower().replace("-", "_")
                    child_entries = [entry for entry in child.children if entry.node_type == "edit"]
                    if model is FGAntivirusProfile:
                        if child_name in {"http", "ftp", "smtp", "imap", "pop3", "nntp", "ssh"}:
                            protocol = FGAntivirusProtocol(
                                name=child.name,
                                settings=node_settings(child),
                                **child_values(child, FGAntivirusProtocol),
                                entries=[_typed_profile_node(entry) for entry in child_entries],
                            )
                            protocol.extra_settings = sanitize_source_attributes({
                                key: value for key, value in node_settings(child).items()
                                if key not in FGAntivirusProtocol.model_fields
                            })
                            for nested in child.children:
                                if nested.node_type == "config":
                                    for entry in nested.children:
                                        if entry.node_type != "edit":
                                            continue
                                        settings = node_settings(entry)
                                        config = FGAntivirusProfileConfig(
                                            name=entry.name,
                                            settings=settings,
                                            **{key: value for key, value in settings.items()
                                               if key in FGAntivirusProfileConfig.model_fields and key not in {"name", "settings", "extra_settings"}},
                                        )
                                        config.extra_settings = sanitize_source_attributes({
                                            key: value for key, value in settings.items()
                                            if key not in FGAntivirusProfileConfig.model_fields
                                        })
                                        protocol.configs.append(config)
                            profile.protocols.append(protocol)
                        else:
                            settings = node_settings(child)
                            profile.configs.append(FGAntivirusProfileConfig(
                                name=child.name,
                                settings=settings,
                                **{key: value for key, value in settings.items()
                                   if key in FGAntivirusProfileConfig.model_fields and key not in {"name", "settings", "extra_settings"}},
                                extra_settings=sanitize_source_attributes({
                                    key: value for key, value in settings.items()
                                    if key not in FGAntivirusProfileConfig.model_fields
                                }),
                            ))
                    else:
                        def add_webfilter_nodes(source: FGSourceNode) -> None:
                            source_name = source.name.lower().replace("-", "_")
                            entries = [entry for entry in source.children if entry.node_type == "edit"]
                            if entries:
                                target_model = (
                                    FGWebFilterOverride if "override" in source_name
                                    else FGWebFilterURLFilter if "url" in source_name
                                    else FGWebFilterCategory
                                )
                                target_bucket = (
                                    profile.overrides if target_model is FGWebFilterOverride
                                    else profile.url_filters if target_model is FGWebFilterURLFilter
                                    else profile.categories
                                )
                                for entry in entries:
                                    settings = node_settings(entry)
                                    if "auth_users" in settings and not isinstance(settings["auth_users"], list):
                                        settings["auth_users"] = [settings["auth_users"]]
                                    values = {key: value for key, value in settings.items()
                                              if key in target_model.model_fields and key not in {"name", "settings", "extra_settings"}}
                                    target_bucket.append(target_model(
                                        name=entry.name,
                                        settings=settings,
                                        **values,
                                        extra_settings=sanitize_source_attributes({
                                            key: value for key, value in settings.items()
                                            if key not in target_model.model_fields
                                        }),
                                    ))
                            for nested in source.children:
                                if nested.node_type == "config":
                                    add_webfilter_nodes(nested)

                        add_webfilter_nodes(child)
                getattr(self.config, collection_name).append(profile)
                continue
            if model in {FGDNSFilterProfile, FGApplicationList, FGSSLSSHProfile}:
                def node_settings(source: FGSourceNode) -> Dict[str, Any]:
                    settings: Dict[str, Any] = {}
                    for command in source.commands:
                        key = command.key.replace("-", "_")
                        value: Any = list(command.values)
                        if len(value) == 1:
                            value = value[0]
                        settings.update(sanitize_source_attributes({key: value}))
                    return settings

                profile_values = node_settings(node)
                profile = model(name=node.name, **{
                    key: value for key, value in profile_values.items()
                    if key in model.model_fields and key != "name"
                })
                profile.extra_settings = sanitize_source_attributes({
                    key: value for key, value in profile_values.items()
                    if key not in model.model_fields
                })

                def add_nested(source: FGSourceNode) -> None:
                    source_name = source.name.lower().replace("-", "_")
                    entries = [entry for entry in source.children if entry.node_type == "edit"]
                    if model is FGSSLSSHProfile and source.commands and source_name in {
                        "http", "https", "ftp", "ftps", "smtp", "smtps", "imap", "pop3", "ssh",
                    }:
                        settings = node_settings(source)
                        ports = settings.get("ports", [])
                        if not isinstance(ports, list):
                            ports = [ports]
                        profile.protocols.append(FGSSLSSHProtocolInspection(
                            name=source.name,
                            status=settings.get("status"),
                            action=settings.get("action"),
                            ports=ports,
                            settings=settings,
                            extra_settings=sanitize_source_attributes({
                                key: value for key, value in settings.items()
                                if key not in FGSSLSSHProtocolInspection.model_fields
                            }),
                        ))
                    for entry in entries:
                        settings = node_settings(entry)
                        if model is FGDNSFilterProfile:
                            target_model = (
                                FGDNSFilterBotnet if "botnet" in source_name
                                else FGDNSFilterDomainFilter if "domain" in source_name
                                else FGDNSFilterCategory if "categor" in source_name or "filter" in source_name or "ftgd" in source_name
                                else FGDNSFilterAction
                            )
                            target_bucket = (
                                profile.botnet if target_model is FGDNSFilterBotnet
                                else profile.domain_filters if target_model is FGDNSFilterDomainFilter
                                else profile.categories if target_model is FGDNSFilterCategory
                                else profile.actions
                            )
                        elif model is FGApplicationList:
                            target_model = (
                                FGApplicationOverride if "override" in source_name
                                else FGApplicationFilter if "filter" in source_name
                                else FGApplicationEntry
                            )
                            target_bucket = (
                                profile.overrides if target_model is FGApplicationOverride
                                else profile.filters if target_model is FGApplicationFilter
                                else profile.entries
                            )
                            if target_model is FGApplicationEntry:
                                for field in ("application", "category", "risk"):
                                    self._parse_and_record_application_control_ints(
                                        source_path=source_path,
                                        section_name=source_name,
                                        profile_name=node.name,
                                        entry_name=entry.name,
                                        settings=settings,
                                        field=field,
                                    )
                                if "application" in settings:
                                    settings["application_id"] = (
                                        settings["application"][0]
                                        if settings["application"]
                                        else None
                                    )
                            elif target_model is FGApplicationFilter:
                                for field in ("category", "risk"):
                                    self._parse_and_record_application_control_ints(
                                        source_path=source_path,
                                        section_name=source_name,
                                        profile_name=node.name,
                                        entry_name=entry.name,
                                        settings=settings,
                                        field=field,
                                    )
                            elif target_model is FGApplicationOverride:
                                for field in ("application", "category"):
                                    self._parse_and_record_application_control_ints(
                                        source_path=source_path,
                                        section_name=source_name,
                                        profile_name=node.name,
                                        entry_name=entry.name,
                                        settings=settings,
                                        field=field,
                                    )
                        else:
                            target_model = (
                                FGSSLSSHCertificate if "cert" in source_name
                                else FGSSLSSHExemption if "exempt" in source_name
                                else FGSSLSSHProtocolInspection
                            )
                            target_bucket = (
                                profile.certificates if target_model is FGSSLSSHCertificate
                                else profile.exemptions if target_model is FGSSLSSHExemption
                                else profile.protocols
                            )
                        known = set(target_model.model_fields) - {"name", "settings", "extra_settings"}
                        values = {key: value for key, value in settings.items() if key in known}
                        if target_model is FGSSLSSHProtocolInspection and "ports" in values and not isinstance(values["ports"], list):
                            values["ports"] = [values["ports"]]
                        target_bucket.append(target_model(
                            name=entry.name,
                            **values,
                            **({"settings": settings} if "settings" in target_model.model_fields else {}),
                            extra_settings=sanitize_source_attributes({
                                key: value for key, value in settings.items() if key not in target_model.model_fields
                            }),
                        ))
                    for nested in source.children:
                        if nested.node_type == "config":
                            add_nested(nested)

                for child in node.children:
                    add_nested(child)
                getattr(self.config, collection_name).append(profile)
                continue
            attributes: Dict[str, Any] = {
                "name": node.name,
                "source_context": self.current_context or "root",
                "nested_configs": list(node.children),
            }
            repeated_extra_settings: Dict[str, Any] = {}
            explicit_fields = set()
            for command in node.commands:
                key = command.key.replace("-", "_")
                operation = getattr(command, "operation", "set")
                values = list(command.values)

                if operation == "unset":
                    explicit_fields.discard(key)
                    if key in secret_fields:
                        attributes.pop("has_password", None)
                        attributes.pop("has_secret", None)
                        attributes.pop("has_encryption_key", None)
                        attributes.pop("has_authentication_key", None)
                    elif source_path == "system virtual-wire-pair" and key in {"outer_vlan_id", "outer-vlan-id"}:
                        attributes["outer_vlan_id"] = []
                    elif source_path == "system virtual-wire-pair" and key in {"member", "members"}:
                        attributes["members"] = []
                    elif source_path == "system link-monitor" and key in {"server", "srcintf", "protocol"}:
                        attributes[key] = []
                    elif key in list_fields:
                        attributes[key] = []
                    else:
                        attributes.pop(key, None)
                    continue

                explicit_fields.add(key)
                if key in secret_fields:
                    if key in {
                        "secret", "password", "passwd", "token", "key", "key2", "key3", "api_key",
                        "key_string", "shared_secret", "secondary_key", "tertiary_key",
                        "tertiary_secret",
                    }:
                        attributes["has_password" if source_path == "user fsso-polling" else "has_secret"] = True
                    elif key == "encryption_key":
                        attributes["has_encryption_key"] = True
                    elif key in {"authentication_key", "auth_key"}:
                        attributes["has_authentication_key"] = True
                    continue

                if operation == "append":
                    if source_path == "system virtual-wire-pair" and key in {"outer_vlan_id", "outer-vlan-id"}:
                        for v in values:
                            try:
                                attributes.setdefault("outer_vlan_id", []).append(int(v))
                            except (TypeError, ValueError):
                                pass
                    elif source_path == "system virtual-wire-pair" and key in {"member", "members"}:
                        attributes.setdefault("members", []).extend(values)
                    elif source_path == "system link-monitor" and key in {"server", "srcintf", "protocol"}:
                        attributes.setdefault(key, []).extend(values)
                    elif key in list_fields:
                        attributes.setdefault(key, []).extend(values)
                    elif key in attributes:
                        attributes[key] = f"{attributes[key]} {' '.join(values)}".strip()
                    else:
                        attributes[key] = " ".join(values)
                    continue

                if source_path == "system virtual-wire-pair" and key in {"outer_vlan_id", "outer-vlan-id"}:
                    parsed_vlans = []
                    for v in values:
                        try:
                            parsed_vlans.append(int(v))
                        except (TypeError, ValueError):
                            pass
                    attributes["outer_vlan_id"] = parsed_vlans
                elif source_path == "system virtual-wire-pair" and key in {"member", "members"}:
                    attributes["members"] = list(values)
                elif key == "class" and source_path == "user radius":
                    attributes["class_"] = values
                elif key in list_fields:
                    attributes[key] = values
                elif not values:
                    attributes[key] = True
                elif len(values) == 1:
                    if source_path == "user fsso-polling" and key not in model.model_fields:
                        _append_repeated_setting(repeated_extra_settings, key, values)
                    else:
                        attributes[key] = values[0]
                else:
                    if source_path == "user fsso-polling" and key not in model.model_fields:
                        _append_repeated_setting(repeated_extra_settings, key, values)
                    else:
                        attributes[key] = " ".join(values)
            if model is FGDns64:
                attributes.pop("name", None)
            if source_path.endswith("6") and model is not FGDns64:
                attributes["family"] = "ipv6"
                attributes["address_family"] = "ipv6"
            if source_path == "vpn ssl web user-bookmark":
                attributes["bookmark_type"] = "user"
            elif source_path == "vpn ssl web group-bookmark":
                attributes["bookmark_type"] = "group"
            if source_path == "system virtual-wire-pair" and "member" in attributes:
                attributes["members"] = attributes.pop("member")
            if source_path == "system virtual-wire-pair":
                if "outer_vlan_id" in attributes and not isinstance(attributes["outer_vlan_id"], list):
                    if isinstance(attributes["outer_vlan_id"], int):
                        attributes["outer_vlan_id"] = [attributes["outer_vlan_id"]]
                    elif isinstance(attributes["outer_vlan_id"], str):
                        try:
                            attributes["outer_vlan_id"] = [int(attributes["outer_vlan_id"])]
                        except ValueError:
                            attributes["outer_vlan_id"] = []
            elif source_path == "system link-monitor":
                for f in (
                    "port", "interval", "timeout", "failtime", "recoverytime",
                    "vrf", "ha_priority", "packet_size", "probe_count",
                    "probe_timeout", "class_id",
                ):
                    self._normalize_optional_int(attributes, f)
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(model.model_fields),
            )
            if repeated_extra_settings:
                attributes["extra_settings"].update(
                    sanitize_source_attributes(repeated_extra_settings)
                )
            if "source_explicit_fields" in model.model_fields:
                attributes["source_explicit_fields"] = explicit_fields
            if source_path == "user radius":
                accounting_servers = []
                for child in node.children:
                    if child.node_type != "config" or child.name != "accounting-server":
                        continue
                    for entry in child.children:
                        if entry.node_type != "edit":
                            continue
                        child_attributes: Dict[str, Any] = {"id": entry.name}
                        for command in entry.commands:
                            key = command.key.replace("-", "_")
                            values = list(command.values)
                            if key in secret_fields:
                                if key in {"secret", "password", "passwd", "tertiary_secret"}:
                                    child_attributes["has_secret"] = True
                                continue
                            if key == "class":
                                child_attributes["class_"] = values
                                continue
                            if key == "switch_controller_service_type":
                                child_attributes[key] = values
                                continue
                            if not values:
                                child_attributes[key] = True
                            elif len(values) == 1:
                                child_attributes[key] = values[0]
                            else:
                                child_attributes[key] = " ".join(values)
                        child_attributes["extra_settings"] = _extract_extra_settings(
                            child_attributes,
                            set(FGUserRADIUSAccountingServer.model_fields),
                        )
                        accounting_servers.append(FGUserRADIUSAccountingServer(**child_attributes))
                attributes["accounting_servers"] = accounting_servers
            elif source_path == "user tacacs+":
                self._normalize_optional_int(attributes, "port")
                self._normalize_optional_int(attributes, "status_ttl")
                self._normalize_optional_int(attributes, "vrf_select")
            elif source_path == "system link-monitor":
                server_list = []
                for child in node.children:
                    if child.node_type == "config" and child.name == "server-list":
                        for entry in child.children:
                            if entry.node_type != "edit":
                                continue
                            server_explicit = set()
                            child_attributes: Dict[str, Any] = {
                                "id": int(entry.name) if entry.name.isdigit() else entry.name,
                            }
                            child_extra: Dict[str, Any] = {}
                            for command in entry.commands:
                                c_key = command.key.replace("-", "_")
                                c_values = list(command.values)
                                server_explicit.add(c_key)
                                if c_key == "protocol":
                                    child_attributes["protocol"] = c_values
                                elif c_key in {"port", "weight"} and c_values:
                                    try:
                                        child_attributes[c_key] = int(c_values[0])
                                    except (TypeError, ValueError):
                                        child_extra[c_key] = c_values[0]
                                elif c_key in {"dst", "server"} and c_values:
                                    child_attributes["dst"] = c_values[0]
                                    child_attributes["server"] = c_values[0]
                                elif not c_values:
                                    child_attributes[c_key] = True
                                elif len(c_values) == 1:
                                    child_attributes[c_key] = c_values[0]
                                else:
                                    child_attributes[c_key] = " ".join(c_values)
                            if "dst" in child_attributes and "server" not in child_attributes:
                                child_attributes["server"] = child_attributes["dst"]
                            elif "server" in child_attributes and "dst" not in child_attributes:
                                child_attributes["dst"] = child_attributes["server"]
                            known_server_fields = set(FGLinkMonitorServer.model_fields)
                            for k, v in list(child_attributes.items()):
                                if k not in known_server_fields and k != "source_explicit_fields":
                                    child_extra[k] = child_attributes.pop(k)
                            child_attributes["extra_settings"] = sanitize_source_attributes(child_extra)
                            child_attributes["source_explicit_fields"] = server_explicit
                            server_list.append(FGLinkMonitorServer(**child_attributes))
                attributes["server_list"] = server_list
            elif source_path == "user fsso-polling":
                attributes["ad_groups"] = [
                    FGFSSOPollingADGroup(
                        name=entry.name,
                        extra_settings=_extract_extra_settings(
                            _repeated_command_attributes(entry.commands),
                            set(FGFSSOPollingADGroup.model_fields),
                        ),
                    )
                    for child in node.children
                    if child.node_type == "config" and child.name == "adgrp"
                    for entry in child.children
                    if entry.node_type == "edit"
                ]
            getattr(self.config, collection_name).append(model(**attributes))

    def parse_source_node(self, node_type: str, node_name: str) -> FGSourceNode:
        node = FGSourceNode(
            node_type=node_type,
            name=node_name,
            start_line_number=self.peek().line_number if self.peek() else None,
        )
        while self.peek():
            token = self.peek()
            if token.type == TokenType.END and node_type == "config":
                node.end_line_number = self.consume(TokenType.END).line_number
                break
            if token.type == TokenType.NEXT and node_type == "edit":
                node.end_line_number = self.consume(TokenType.NEXT).line_number
                break
            if token.type == TokenType.EDIT:
                self.consume(TokenType.EDIT)
                name = self.consume(TokenType.STRING).value
                node.children.append(self.parse_source_node("edit", name))
            elif token.type == TokenType.CONFIG:
                self.consume(TokenType.CONFIG)
                name = self.read_section_name()
                node.children.append(self.parse_source_node("config", name))
            elif token.type in {TokenType.SET, TokenType.UNSET, TokenType.APPEND}:
                operation = token.type.value
                line_number = token.line_number
                key, values = self.parse_key_values(token.type)
                safe = self._source_command(operation, key, values)
                node.commands.append(
                    FGSourceCommand(
                        operation=safe.operation,
                        key=safe.key,
                        values=safe.values,
                        line_number=line_number,
                    )
                )
            elif token.type == TokenType.COMMENT:
                node.commands.append(FGSourceCommand(
                    operation="comment",
                    key="#",
                    values=[self.next_token().value],
                    line_number=token.line_number,
                ))
            elif token.type == TokenType.STRING:
                line_number = token.line_number
                values = []
                key = self.next_token().value
                while (
                    self.peek()
                    and self.peek().type == TokenType.STRING
                    and self.peek().line_number == line_number
                ):
                    values.append(self.next_token().value)
                node.commands.append(FGSourceCommand(
                    operation="unknown",
                    key=key,
                    values=values,
                    line_number=line_number,
                ))
            else:
                self.next_token()
        return node

    def _source_node_inventory(
        self,
        node: FGSourceNode,
        source_path: str,
        object_name: Optional[str] = None,
    ) -> SourceInventoryItem:
        return SourceInventoryItem(
            domain=source_path.split(" ", 1)[0],
            source_path=source_path,
            source_context=self.current_context,
            name=object_name if object_name is not None else node.name,
            source_id=(
                object_name
                if object_name is not None and object_name.isdigit()
                else None
            ),
            commands=[
                SourceCommand(
                    operation=command.operation,
                    key=command.key,
                    values=list(command.values),
                    line_number=command.line_number,
                )
                for command in node.commands
            ],
            children=[
                self._source_node_inventory(
                    child,
                    f"{source_path} {child.name}" if child.node_type == "config" else source_path,
                    child.name,
                )
                for child in node.children
            ],
            notes=[f"source-node:{node.node_type}"],
        )

    def parse_edit_block(self, section_path: str):
        self.consume(TokenType.EDIT)
        item_name = self.consume(TokenType.STRING).value
        source_node = self.parse_source_node("edit", item_name)
        attributes = self.parse_edit_attributes(section_path, source_node)
        self.build_model(section_path, attributes)

    def parse_edit_attributes(
        self,
        section_path: str,
        source_node: FGSourceNode,
    ) -> Dict[str, Any]:
        return self._project_edit_source_node(section_path, source_node)

    def _project_edit_source_node(
        self,
        section_path: str,
        node: FGSourceNode,
    ) -> Dict[str, Any]:
        """Project one completed edit node into parser attributes."""

        initial: Dict[str, Any] = {"name": node.name}
        if node.name.isdigit():
            initial["id"] = int(node.name)
            if section_path == "firewall policy":
                initial.pop("name")

        spec = get_section_spec(section_path)
        evaluated = evaluate_section_commands(
            section_path, node.commands, spec, initial=initial
        )
        attributes = {**evaluated.attributes, **evaluated.extra_settings}
        if evaluated.explicit_fields:
            attributes["source_explicit_fields"] = evaluated.explicit_fields

        for command in node.commands:
            clean_key = self._normalize_attribute_key(command.key)
            if command.operation == "unset":
                attributes.setdefault("source_unset_settings", []).append(command.key)
                if section_path == "system dhcp server" and clean_key == "ddns_key":
                    attributes.update(has_ddns_key=False, ddns_key_format=None)
                elif section_path == "system sdwan health-check" and clean_key == "password":
                    attributes.update(has_password=False, password_format=None)
                continue
            if command.operation not in {"set", "append"}:
                continue
            if (
                clean_key in {"password", "passwd", "ppk_secret", "psksecret", "psksecret_remote", "authpasswd", "group_authentication_secret", "ddns_key"}
                or section_path.startswith("vpn certificate ")
                or section_path.startswith("certificate ")
                or section_path.startswith("firewall ssh ")
                or section_path == "system admin"
                or section_path == "user fortitoken"
            ):
                self.apply_attribute(attributes, command.key, list(command.values), section_path)

        nested_collections = {
            ("system interface", "secondaryip"): "secondary_ips",
            ("firewall vip", "realservers"): "realservers",
            ("firewall vip6", "realservers"): "realservers",
            ("firewall addrgrp", "tagging"): "tagging",
            ("firewall addrgrp6", "tagging"): "tagging",
            ("firewall address", "list"): "address_list",
            ("firewall address", "tagging"): "tagging",
            ("firewall address6", "tagging"): "tagging",
            ("firewall multicast-address", "tagging"): "tagging",
            ("firewall multicast-address6", "tagging"): "tagging",
            ("system dhcp server", "ip-range"): "ip_ranges",
            ("system dhcp6 server", "ip-range"): "ip_ranges",
            ("system dhcp server", "exclude-range"): "exclude_ranges",
            ("system dhcp server", "reserved-address"): "reserved_addresses",
            ("system dhcp server", "options"): "options",
            ("system dhcp6 server", "prefix-range"): "prefix_ranges",
            ("system dhcp6 server", "option"): "options",
            ("system dhcp6 server", "options"): "options",
            ("ips sensor", "entries"): "entries",
            ("ips sensor entries", "exempt-ip"): "exempt_ips",
            ("firewall internet-service-definition", "entry"): "entries",
            ("firewall internet-service-definition entry", "port-range"): "port_ranges",
            ("firewall internet-service-custom", "entry"): "entries",
            ("firewall internet-service-addition", "entry"): "entries",
            ("firewall internet-service-custom entry", "port-range"): "port_ranges",
            ("firewall internet-service-addition entry", "port-range"): "port_ranges",
            ("firewall internet-service-extension", "disable-entry"): "disable_entries",
            ("firewall internet-service-extension", "entry"): "entries",
            ("firewall internet-service-extension disable-entry", "ip-range"): "ip_range",
            ("firewall internet-service-extension disable-entry", "ip6-range"): "ip6_range",
            ("firewall internet-service-extension disable-entry", "port-range"): "port_ranges",
            ("firewall internet-service-extension entry", "port-range"): "port_ranges",
            ("system sdwan health-check", "sla"): "sla",
            ("system sdwan service", "sla"): "sla",
            ("user group", "match"): "match",
            ("user group", "guest"): "guests",
            ("vpn ssl web portal", "host-check-software"): "host_checks",
            ("vpn ssl web portal", "bookmark-group"): "bookmark_groups",
            ("vpn ssl web portal", "landing-page"): "landing_pages",
            ("vpn ssl web portal", "mac-addr-check-rule"): "mac_address_check_rules",
            ("vpn ssl web portal", "os-check-list"): "os_check_list",
            ("vpn ssl web portal", "split-dns"): "split_dns",
            ("vpn ssl web portal bookmark-group", "bookmarks"): "bookmarks",
            ("vpn ssl web portal bookmark-group bookmarks", "form-data"): "form_data",
            ("vpn ssl web portal landing-page", "form-data"): "form_data",
            ("vpn ssl web host-check-software", "check-item-list"): "check_items",
            ("firewall DoS-policy", "anomaly"): "anomalies",
            ("firewall DoS-policy6", "anomaly"): "anomalies",
        }
        for child in node.children:
            nested_path = f"{section_path} {child.name}".strip()
            collection = nested_collections.get((section_path, child.name))
            if collection:
                values = [
                    self._project_edit_source_node(nested_path, entry)
                    for entry in child.children
                    if entry.node_type == "edit"
                ]
                attributes.setdefault(collection, []).extend(values)
                continue
            if section_path == "system accprofile" and child.name.endswith("grp-permission"):
                settings = evaluate_commands(child.commands).attributes
                attributes.setdefault("permission_blocks", []).append({
                    "name": child.name,
                    "settings": settings,
                })
                continue
            attributes.setdefault("nested_configs", []).append(child)

        inventory_name = attributes.get("name") if section_path == "firewall policy" else node.name
        self.source_inventory_items.append(SourceInventoryItem(
            domain=section_path.split(" ", 1)[0] if section_path else "unknown",
            source_path=section_path,
            name=inventory_name,
            source_id=node.name if node.name.isdigit() else None,
            source_record_id=(
                node.name
                if section_path.startswith("system dhcp server") and not node.name.isdigit()
                else None
            ),
            source_context=self.current_context,
            commands=[
                SourceCommand(
                    operation=command.operation,
                    key=command.key,
                    values=list(command.values),
                    line_number=command.line_number,
                )
                for command in node.commands
            ],
            children=[
                self._source_node_inventory(
                    child,
                    f"{section_path} {child.name}" if child.node_type == "config" else section_path,
                    child.name,
                )
                for child in node.children
            ],
            notes=(
                ["parse-error: malformed DHCP edit identifier retained as source inventory"]
                if section_path.startswith("system dhcp server") and not node.name.isdigit()
                else []
            ),
        ))
        return attributes

    @staticmethod
    def _nested_command_attributes(
        node: FGSourceNode,
        list_fields: set[str] = frozenset(),
    ) -> Dict[str, Any]:
        attributes: Dict[str, Any] = {}
        for command in node.commands:
            key = command.key.replace("-", "_")
            if command.operation == "unset":
                attributes.pop(key, None)
            elif key in list_fields:
                if command.operation == "append":
                    attributes.setdefault(key, []).extend(command.values)
                else:
                    attributes[key] = list(command.values)
            elif command.operation in {"set", "append"}:
                values = command.values
                attributes[key] = values[0] if len(values) == 1 else " ".join(values)
        return attributes

    @classmethod
    def _interface_nested_entry(
        cls,
        node: FGSourceNode,
        model: Any,
        list_fields: set[str] = frozenset(),
        int_fields: set[str] = frozenset(),
        source_id: bool = False,
    ) -> Any:
        attributes = cls._nested_command_attributes(node, list_fields)
        if source_id:
            attributes["source_id"] = node.name
            try:
                attributes["id"] = int(node.name)
            except (TypeError, ValueError):
                attributes["id"] = None
                attributes.setdefault("extra_settings", {})["unparsed_id"] = node.name
        else:
            attributes["name"] = node.name
        for key in int_fields:
            cls._normalize_optional_int(attributes, key)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes,
            set(model.model_fields),
        )
        return model(**attributes)

    @staticmethod
    def _parse_system_zone_tagging_entry(node: FGSourceNode) -> Dict[str, Any]:
        attributes: Dict[str, Any] = {"name": node.name}
        for command in node.commands:
            key = command.key.replace("-", "_")
            values = list(command.values)
            if command.operation == "unset":
                attributes.pop(key, None)
            elif key == "tags":
                if command.operation == "append":
                    attributes.setdefault(key, []).extend(values)
                else:
                    attributes[key] = values
            elif command.operation in {"set", "append"}:
                attributes[key] = values[0] if len(values) == 1 else " ".join(values)
        attributes["extra_settings"] = _extract_extra_settings(
            attributes, set(FGSystemZoneTaggingEntry.model_fields)
        )
        return dict(FGSystemZoneTaggingEntry(**attributes))



    def _attach_ssl_vpn_authentication_rules(
        self,
        raw_rules: List[Dict[str, Any]],
    ) -> None:
        if not self.config.ssl_vpn_settings:
            self.config.ssl_vpn_settings = FGSSLVPNSettings()
        rules = []
        for attributes in raw_rules:
            if attributes.get("name") == str(attributes.get("id")):
                attributes.pop("name", None)
            attributes["extra_settings"] = _extract_extra_settings(
                attributes,
                set(FGSSLVPNAuthenticationRule.model_fields),
            )
            rules.append(FGSSLVPNAuthenticationRule(**attributes))
        self.config.ssl_vpn_settings.authentication_rules.extend(rules)

    @staticmethod
    def _normalize_int_list(attributes: Dict[str, Any], key: str) -> None:
        values = attributes.get(key, [])
        if not isinstance(values, list):
            values = [values]
        normalized = []
        unparsed = []
        for value in values:
            try:
                normalized.append(int(value))
            except (TypeError, ValueError):
                unparsed.append(value)
        attributes[key] = normalized
        if unparsed:
            attributes[f"unparsed_{key}"] = unparsed

    @staticmethod
    def _normalize_optional_int(attributes: Dict[str, Any], key: str) -> None:
        value = attributes.get(key)
        if value is None:
            return
        try:
            attributes[key] = int(value)
        except (TypeError, ValueError):
            attributes.pop(key, None)
            attributes[f"unparsed_{key}"] = value

    def _parse_and_record_application_control_ints(
        self,
        source_path: str,
        section_name: str,
        profile_name: str,
        entry_name: str,
        settings: Dict[str, Any],
        field: str,
    ) -> None:
        if field not in settings:
            return
        raw_value = settings[field]
        if not isinstance(raw_value, list):
            raw_value = [raw_value]
        parsed_values: List[int] = []
        unparsed_values: List[str] = []
        for v in raw_value:
            tokens = str(v).strip().split() if isinstance(v, str) else [v]
            for part in tokens:
                try:
                    parsed_values.append(int(part))
                except (TypeError, ValueError):
                    unparsed_values.append(str(part))
        settings[field] = parsed_values
        if unparsed_values:
            settings[f"unparsed_{field}"] = unparsed_values
            full_section_path = f"{source_path} {section_name}"
            object_name = f"{profile_name}/{entry_name}"
            issue_note = (
                f"Invalid numeric value {unparsed_values!r} for field '{field}' "
                f"in section '{full_section_path}' object '{object_name}'"
            )
            inv_item = next(
                (
                    item for item in self.source_inventory_items
                    if item.source_path == source_path and item.name == profile_name
                ),
                None,
            )
            if inv_item is not None:
                inv_item.requires_manual_review = True
                if issue_note not in inv_item.notes:
                    inv_item.notes.append(issue_note)
                sub_sec = next((c for c in inv_item.children if c.name == section_name), None)
                if sub_sec is not None:
                    sub_sec.requires_manual_review = True
                    entry_item = next((c for c in sub_sec.children if c.name == entry_name), None)
                    if entry_item is not None:
                        entry_item.requires_manual_review = True
                        entry_item.status = ExtractionStatus.PARTIALLY_NORMALIZED
                        if issue_note not in entry_item.notes:
                            entry_item.notes.append(issue_note)
                        for cmd in entry_item.commands:
                            if cmd.key.replace("-", "_") == field:
                                cmd.status = ExtractionStatus.PARSE_ERROR
                                cmd.requires_manual_review = True

    @staticmethod
    def _parse_port_ranges(value: Optional[str]) -> List[FGPortRange]:
        return parse_service_port_ranges(value)

    def parse_key_values(
        self,
        command_type: TokenType,
    ) -> tuple[str, List[str]]:
        self.consume(command_type)

        key_token = self.consume(TokenType.STRING)
        key = key_token.value

        values = []
        current_line = key_token.line_number

        while (
            self.peek()
            and self.peek().type == TokenType.STRING
            and self.peek().line_number == current_line
        ):
            values.append(
                self.next_token().value
            )

        return key, values

    def parse_set(self) -> tuple[str, List[str]]:
        return self.parse_key_values(TokenType.SET)

    @staticmethod
    def _source_command(
        operation: str,
        key: str,
        values: List[str],
    ) -> SourceCommand:
        sanitized = sanitize_source_attributes({key: values})
        sanitized_value = sanitized.get(key.replace("-", "_"), values)
        safe_values = (
            [sanitized_value]
            if isinstance(sanitized_value, str)
            else list(sanitized_value)
        )
        return SourceCommand(
            operation=operation,
            key=key,
            values=safe_values,
        )

    @staticmethod
    def _normalize_attribute_key(key: str) -> str:
        clean_key = key.replace("-", "_")
        if clean_key == "threshold(default)":
            return "threshold_default"
        if clean_key.lower() == "secondary_ip":
            return "secondary_ip"
        return clean_key

    @staticmethod
    def _record_explicit_field(
        attributes: Dict[str, Any],
        section_path: str,
        key: str,
    ) -> None:
        clean_key = key.replace("-", "_")
        spec = get_section_spec(section_path)
        fields = spec.explicit_fields if spec else ()
        if clean_key not in fields:
            return
        attributes.setdefault("source_explicit_fields", set()).add(clean_key)


    def apply_attribute(
        self,
        attributes: Dict[str, Any],
        key: str,
        values: List[str],
        section_path: str = "",
    ):
        self._record_explicit_field(attributes, section_path, key)
        clean_key = self._normalize_attribute_key(key)
        if (
            section_path in {
                "firewall DoS-policy anomaly",
                "firewall DoS-policy6 anomaly",
            }
            and key == "threshold(default)"
        ):
            clean_key = "threshold_default"
        if clean_key == "tacacs+_server":
            clean_key = "tacacs_server"
        if section_path == "system sdwan health-check" and clean_key == "password":
            value = " ".join(str(item) for item in values).strip()
            attributes["has_password"] = bool(values)
            attributes["password_format"] = "encrypted" if value.upper().startswith("ENC ") else "plaintext"
            return
        if section_path == "system dhcp server" and clean_key == "ddns_key":
            value = " ".join(str(item) for item in values).strip()
            attributes["has_ddns_key"] = bool(values)
            attributes["ddns_key_format"] = (
                "encrypted" if value.upper().startswith("ENC ") else "plaintext"
            ) if values else None
            return
        if clean_key in {"password", "passwd", "ppk_secret"} and section_path == "user group guest":
            attributes["has_password"] = bool(values)
            return

        if section_path in {
            "vpn certificate remote",
            "vpn certificate local",
            "vpn certificate ca",
            "certificate remote",
            "certificate local",
            "certificate ca",
        }:
            self._apply_certificate_attribute(
                attributes,
                clean_key,
                values,
            )
            return

        if section_path in {
            "firewall ssh local-key",
            "firewall ssh local-ca",
        }:
            self._apply_ssh_key_attribute(attributes, clean_key, values)
            return

        if section_path in {"vpn ipsec phase1", "vpn ipsec phase1-interface"}:
            if clean_key in {"psksecret", "psksecret_remote"}:
                attributes["has_psk"] = bool(values) or attributes.get("has_psk", False)
            elif clean_key == "authpasswd":
                attributes["has_auth_password"] = bool(values)
            elif clean_key == "group_authentication_secret":
                attributes["has_group_authentication_secret"] = bool(values)
            elif clean_key == "ppk_secret":
                attributes["has_ppk_secret"] = bool(values)
            if clean_key in {
                "psksecret", "psksecret_remote", "authpasswd",
                "group_authentication_secret", "ppk_secret",
            }:
                return

        if section_path == "system interface" and clean_key == "password":
            has_password, password_format = _classify_pppoe_password(values)
            attributes["has_pppoe_password"] = has_password
            attributes["pppoe_password_format"] = password_format
            attributes["password"] = " ".join(str(item) for item in values)
            return

        if section_path == "system admin" and clean_key in ADMIN_SECRET_FIELDS:
            attributes["credential_configured"] = bool(values)
            return

        if section_path == "user fortitoken" and clean_key in ADMIN_SECRET_FIELDS:
            return

        if section_path in IDENTITY_SECTIONS and clean_key in IDENTITY_SECRET_FIELDS:
            if clean_key == "ppk_secret":
                attributes["has_ppk_secret"] = True
            elif clean_key.startswith("password") or clean_key == "passwd":
                attributes["has_password"] = True
                if clean_key != "password":
                    attributes[f"has_{clean_key}"] = True
            return

        if section_path == "user fsso" and clean_key not in FGFSSOServer.model_fields:
            _append_repeated_setting(attributes, clean_key, values)
            return

        if (
            section_path in {"router static", "router static6"}
            and clean_key == "dstaddr"
        ):
            attributes[clean_key] = (
                values[0] if len(values) == 1 else " ".join(values)
            )
            return

        if section_path == "system sdwan zone" and (
            clean_key in FG_SDWAN_ZONE_INT_FIELDS
            or clean_key in FG_SDWAN_ZONE_SCALAR_FIELDS
        ):
            attributes[clean_key] = values[0] if values else True
            return

        if section_path == "system sdwan service" and (
            clean_key in FG_SDWAN_SERVICE_INT_FIELDS
            or clean_key in FG_SDWAN_SERVICE_SCALAR_FIELDS
        ):
            attributes[clean_key] = values[0] if values else True
            return

        list_fields = {
            "allowaccess",
            "detectprotocol",
            "dhcp_relay_ip",
            "member",
            "day",
            "srcintf",
            "dstintf",
            "srcaddr",
            "dstaddr",
            "dst",
            "dst6",
            "ip_range",
            "ip6_range",
            "groups",
            "users",
            "service",
            "poolname",
            "proposal",
            "internet_service_name",
            "exclude_ip",
            "mappedip",
            "extaddr",
            "src_filter",
            "srcintf_filter",
            "monitor",
            "ztna_ems_tag",
            "ztna_ems_tag_secondary",
            "ztna_geo_tag",
            "capabilities",
        }

        if section_path == "authentication scheme" and clean_key in {
            "method", "user_database",
        }:
            attributes[clean_key] = values
            return
        if section_path == "authentication rule" and clean_key in {
            "srcintf", "srcaddr", "srcaddr6", "dstaddr", "dstaddr6",
            "protocol", "auth_method",
        }:
            attributes[clean_key] = values
            return

        multicast_scalar_interface = (
            section_path in {"firewall multicast-policy", "firewall multicast-policy6"}
            and clean_key in {"srcintf", "dstintf"}
        )
        if (
            (clean_key in list_fields and not multicast_scalar_interface)
            or clean_key in (
                get_section_spec(section_path).list_fields
                if get_section_spec(section_path)
                else ()
            )
            or (
                clean_key == "interface"
                and section_path == "system zone"
            )
        ):
            attributes[clean_key] = values

        elif (
            section_path in POLICY_ROUTE_FAMILIES
            and clean_key in FG_POLICY_ROUTE_SCALAR_FIELDS
        ):
            attributes[clean_key] = values[0] if len(values) == 1 else " ".join(values)

        elif section_path == "system interface" and clean_key in (
            FG_INTERFACE_INT_FIELDS
            | FG_INTERFACE_AGGREGATE_INT_FIELDS
            | FG_INTERFACE_SCALAR_FIELDS
            | FG_INTERFACE_AGGREGATE_SCALAR_FIELDS
        ):
            attributes[clean_key] = " ".join(values) if len(values) > 1 else (values[0] if values else True)

        elif len(values) == 0:
            attributes[clean_key] = True

        elif len(values) == 1:
            attributes[clean_key] = values[0]

        else:
            if key == "subnet" or key == "ip":
                attributes[clean_key] = (
                    f"{values[0]} {values[1]}"
                )

            elif key in [
                "tcp-portrange",
                "udp-portrange",
                "sctp-portrange",
            ]:
                attributes[clean_key] = ",".join(
                    values
                )

            else:
                attributes[clean_key] = " ".join(
                    values
                )

    @staticmethod
    def _apply_certificate_attribute(
        attributes: Dict[str, Any],
        clean_key: str,
        values: List[str],
    ) -> None:
        """Retain safe certificate fields and discard secret values."""
        normalized_key = clean_key.lower()
        value = values[0] if len(values) == 1 else " ".join(values)

        if normalized_key == "private_key":
            attributes["has_private_key"] = True
            attributes["private_key_encrypted"] = any(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----" in item
                for item in values
            )
            return

        if normalized_key in {"password", "passwd"} or any(
            marker in normalized_key
            for marker in (
                "password",
                "passwd",
                "passphrase",
                "credential",
                "secret",
                "token",
                "community",
                "auth_key",
                "api_key",
                "private_key",
            )
        ) or normalized_key == "key":
            if "password" in normalized_key or "passwd" in normalized_key:
                attributes["has_password"] = True
            return

        if normalized_key in {"certificate", "remote", "ca"}:
            attributes["public_certificate"] = value
            attributes["has_certificate"] = bool(value)
            return

        if normalized_key == "comment":
            normalized_key = "comments"

        attributes[normalized_key] = value if values else True

    @staticmethod
    def _apply_ssh_key_attribute(
        attributes: Dict[str, Any],
        clean_key: str,
        values: List[str],
    ) -> None:
        """Retain public SSH metadata while discarding credentials immediately."""
        normalized_key = clean_key.lower()
        value = values[0] if len(values) == 1 else " ".join(values)

        if normalized_key == "private_key":
            attributes["has_private_key"] = bool(values)
            return
        if normalized_key in {"password", "passwd"}:
            attributes["has_password"] = bool(values)
            return
        if normalized_key in {"public_key", "source"}:
            attributes[normalized_key] = value
            return

        attributes[normalized_key] = value if values else True

    def apply_global_set(
        self,
        section_path: str,
        key: str,
        values: List[str],
    ):
        if section_path == "system settings":
            context = self._execution_context()
            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in {"central_nat", "ngfw_mode", "opmode"}:
                setattr(context, clean_key, value)
            else:
                context.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "system session-ttl":
            if not self.config.session_ttl_settings:
                self.config.session_ttl_settings = FGSessionTTLSettings()
            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key == "default" and values:
                if values[0].lower() == "never":
                    self.config.session_ttl_settings.default_timeout = None
                    self.config.session_ttl_settings.default_never = True
                else:
                    try:
                        self.config.session_ttl_settings.default_timeout = int(values[0])
                        self.config.session_ttl_settings.default_never = False
                    except ValueError:
                        self.config.session_ttl_settings.extra_settings["unparsed_default"] = value
            else:
                self.config.session_ttl_settings.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "system global":
            if not self.config.system_global:
                self.config.system_global = (
                    FGSystemGlobal(
                        hostname=None
                    )
                )

            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)

            if clean_key == "central_nat" and values:
                self._execution_context().central_nat = values[0]
                self.config.system_global.extra_settings[clean_key] = values[0]

            elif clean_key == "hostname" and values:
                self.config.system_global.hostname = (
                    values[0]
                )

            elif clean_key in {
                "admin_sport", "admin_http_port", "admin_https_port", "admin_ssh_port",
                "admin_telnet_port", "admin_lockout_threshold", "admin_lockout_duration",
                "admin_console_timeout", "admin_login_max", "admin_hsts_max_age",
            } and values:
                try:
                    parsed_port = int(values[0])
                    setattr(self.config.system_global, clean_key, parsed_port)
                    if clean_key not in {
                        "admin_sport", "admin_http_port", "admin_https_port", "admin_ssh_port",
                    }:
                        self.config.system_global.extra_settings[clean_key] = value
                    if clean_key == "admin_sport":
                        self.config.system_global.admin_https_port = parsed_port
                except (TypeError, ValueError):
                    self.config.system_global.extra_settings[f"{clean_key}_raw"] = value

            elif clean_key in {
                "admin_https_redirect", "admin_restrict_local", "admin_server_cert",
                "admin_hsts_header",
            } and values:
                setattr(self.config.system_global, clean_key, values[0])
                self.config.system_global.extra_settings[clean_key] = values[0]

            elif clean_key == "timezone" and values:
                self.config.system_global.timezone = values[0]

            elif clean_key == "opmode" and values:
                self._execution_context().opmode = values[0]

            elif clean_key != "extra_settings":
                self.config.system_global.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "system dns":
            if not self.config.dns:
                self.config.dns = FGDnsMultiValue746()

            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            self.config.dns.source_explicit_fields.add(clean_key)
            if clean_key in {
                "timeout", "retry", "dns_cache_limit", "dns_cache_ttl",
                "fqdn_cache_ttl", "fqdn_max_refresh", "fqdn_min_refresh",
            } and values:
                try:
                    int_val = int(values[0])
                    setattr(self.config.dns, clean_key, int_val)
                    self.config.dns.extra_settings[clean_key] = int_val
                except (TypeError, ValueError):
                    self.config.dns.extra_settings[clean_key] = value
            elif clean_key in {"protocol", "domain"} and values:
                parsed_value = list(values)
                setattr(self.config.dns, clean_key, parsed_value)
                self.config.dns.extra_settings.update(sanitize_source_attributes({clean_key: parsed_value}))
            elif clean_key in {
                "primary", "secondary", "alt_primary", "alt_secondary",
                "ip6_primary", "ip6_secondary", "server_select_method",
                "interface_select_method", "interface",
                "source_ip", "source_ip6", "ssl_certificate",
                "cache_notfound_responses", "log",
            } and values:
                parsed_value = values[0]
                setattr(self.config.dns, clean_key, parsed_value)
                if clean_key not in {"primary", "secondary"}:
                    self.config.dns.extra_settings.update(sanitize_source_attributes({clean_key: parsed_value}))
            elif clean_key == "server_hostname":
                parsed_value = list(values)
                self.config.dns.server_hostname = parsed_value
                self.config.dns.extra_settings[clean_key] = parsed_value
            elif clean_key != "extra_settings":
                self.config.dns.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "system sdwan":
            sdwan = self._sdwan_for_current_context()

            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in {"status", "load_balance_mode"} and values:
                setattr(sdwan, clean_key, value)
            elif clean_key != "extra_settings":
                sdwan.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "vpn ssl settings":
            if not self.config.ssl_vpn_settings:
                self.config.ssl_vpn_settings = FGSSLVPNSettings()
            clean_key = key.replace("-", "_")
            if clean_key == "servercert":
                self.config.ssl_vpn_settings.servercert_configured = True
            if clean_key in get_section_spec("vpn ssl settings").list_fields:
                value: Any = list(values)
            elif clean_key in {
                "login_attempt_limit", "login_block_time", "auth_timeout",
                "idle_timeout", "port", "deflate_compression_level",
                "deflate_min_data_size", "dtls_heartbeat_fail_count",
                "dtls_heartbeat_idle_timeout", "dtls_heartbeat_interval",
                "dtls_hello_timeout", "http_request_body_timeout",
                "http_request_header_timeout", "login_timeout",
                "saml_redirect_port", "tunnel_user_session_timeout",
            } and values:
                try:
                    value = int(values[0])
                except ValueError:
                    self.config.ssl_vpn_settings.extra_settings.update(
                        sanitize_source_attributes({f"unparsed_{clean_key}": values[0]})
                    )
                    return
            else:
                value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in FGSSLVPNSettings.model_fields and clean_key not in {
                "authentication_rules",
                "extra_settings",
            }:
                setattr(self.config.ssl_vpn_settings, clean_key, value)
            else:
                self.config.ssl_vpn_settings.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "user setting":
            if not self.config.user_authentication_settings:
                self.config.user_authentication_settings = FGUserAuthenticationSettings()
            clean_key = key.replace("-", "_")
            value: Any = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in {
                "auth_timeout", "auth_lockout_threshold", "auth_lockout_duration",
            } and values:
                try:
                    value = int(values[0])
                except ValueError:
                    value = values[0]
            if clean_key == "auth_ssl_min_proto_version":
                self.config.user_authentication_settings.ssl_min_proto_version = value
                self.config.user_authentication_settings.extra_settings.update(
                    {clean_key: value}
                )
                return
            if clean_key in FGUserAuthenticationSettings.model_fields and clean_key != "extra_settings":
                setattr(self.config.user_authentication_settings, clean_key, value)
            else:
                self.config.user_authentication_settings.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "user quarantine":
            if not self.config.user_quarantine:
                self.config.user_quarantine = FGUserQuarantine()
            clean_key = key.replace("-", "_")
            if clean_key == "firewall_groups":
                self.config.user_quarantine.firewall_groups = list(values)
            else:
                value = values[0] if len(values) == 1 else " ".join(values)
                self.config.user_quarantine.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

        elif section_path == "firewall ipv6-eh-filter":
            if self.config.ipv6_eh_filter is None:
                self.config.ipv6_eh_filter = FGIPv6EHFilter(
                    source_context=self.current_context or "root"
                )
            clean_key = key.replace("-", "_")
            item = self.config.ipv6_eh_filter
            item.source_explicit_fields.add(clean_key)
            item.extra_settings.pop(f"unparsed_{clean_key}", None)
            if clean_key == "hdopt_type":
                parsed = []
                invalid = []
                for value in values:
                    try:
                        parsed.append(int(value))
                    except (TypeError, ValueError):
                        invalid.append(value)
                item.hdopt_type = parsed
                if invalid:
                    item.extra_settings["unparsed_hdopt_type"] = invalid
            elif clean_key == "routing_type":
                try:
                    item.routing_type = int(values[0])
                except (IndexError, TypeError, ValueError):
                    item.routing_type = None
                    item.extra_settings["unparsed_routing_type"] = list(values)
            elif clean_key in {
                "auth", "dest_opt", "fragment", "hop_opt", "no_next", "routing",
            }:
                setattr(item, clean_key, values[0] if values else None)
            else:
                item.extra_settings.update(
                    sanitize_source_attributes({
                        clean_key: values[0] if len(values) == 1 else list(values)
                    })
                )

        elif section_path == "web-proxy global":
            if not self.config.web_proxy_global:
                self.config.web_proxy_global = FGWebProxyGlobal()

            clean_key = key.replace("-", "_")
            value = values[0] if len(values) == 1 else " ".join(values)
            if clean_key in FGWebProxyGlobal.model_fields and clean_key != "extra_settings":
                setattr(self.config.web_proxy_global, clean_key, value)
            else:
                self.config.web_proxy_global.extra_settings.update(
                    sanitize_source_attributes({clean_key: value})
                )

    def apply_global_unset(self, section_path: str, key: str) -> None:
        clean_key = key.replace("-", "_")
        if section_path == "system settings":
            context = self._execution_context()
            if clean_key in {"central_nat", "ngfw_mode", "opmode"}:
                setattr(context, clean_key, None)
            context.extra_settings.pop(clean_key, None)
        elif section_path == "system session-ttl" and self.config.session_ttl_settings:
            if clean_key == "default":
                self.config.session_ttl_settings.default_timeout = None
                self.config.session_ttl_settings.default_never = False
            self.config.session_ttl_settings.extra_settings.pop(clean_key, None)
        elif section_path == "system global" and self.config.system_global:
            if clean_key == "hostname":
                self.config.system_global.hostname = None
            elif clean_key == "admin_sport":
                self.config.system_global.admin_sport = None
            elif clean_key == "timezone":
                self.config.system_global.timezone = None
            elif clean_key == "opmode":
                self._execution_context().opmode = None
            self.config.system_global.extra_settings.pop(clean_key, None)
        elif section_path == "system dns" and self.config.dns:
            self.config.dns.source_explicit_fields.discard(clean_key)
            if clean_key in {"protocol", "domain", "server_hostname"}:
                setattr(self.config.dns, clean_key, [])
            elif clean_key in FGDns.model_fields and clean_key not in {"extra_settings", "source_explicit_fields"}:
                setattr(self.config.dns, clean_key, None)
            self.config.dns.extra_settings.pop(clean_key, None)
        elif section_path == "web-proxy global" and self.config.web_proxy_global:
            if clean_key in FGWebProxyGlobal.model_fields and clean_key != "extra_settings":
                setattr(self.config.web_proxy_global, clean_key, None)
            self.config.web_proxy_global.extra_settings.pop(clean_key, None)
        elif section_path == "system sdwan":
            sdwan = self._sdwan_for_current_context()
            if clean_key == "status":
                sdwan.status = "disable"
            elif clean_key == "load_balance_mode":
                sdwan.load_balance_mode = None
            sdwan.extra_settings.pop(clean_key, None)
        elif section_path == "vpn ssl settings" and self.config.ssl_vpn_settings:
            if clean_key in get_section_spec("vpn ssl settings").list_fields:
                setattr(self.config.ssl_vpn_settings, clean_key, [])
            elif clean_key in FGSSLVPNSettings.model_fields and clean_key not in {
                "authentication_rules",
                "extra_settings",
            }:
                setattr(self.config.ssl_vpn_settings, clean_key, None)
            self.config.ssl_vpn_settings.extra_settings.pop(clean_key, None)
        elif section_path == "user setting" and self.config.user_authentication_settings:
            if clean_key in FGUserAuthenticationSettings.model_fields and clean_key != "extra_settings":
                setattr(self.config.user_authentication_settings, clean_key, None)
            self.config.user_authentication_settings.extra_settings.pop(clean_key, None)
        elif section_path == "user quarantine" and self.config.user_quarantine:
            if clean_key == "firewall_groups":
                self.config.user_quarantine.firewall_groups = []
            self.config.user_quarantine.extra_settings.pop(clean_key, None)
        elif section_path == "firewall ipv6-eh-filter" and self.config.ipv6_eh_filter:
            item = self.config.ipv6_eh_filter
            item.source_explicit_fields.discard(clean_key)
            if clean_key == "hdopt_type":
                item.hdopt_type = []
            elif clean_key == "routing_type" or clean_key in {
                "auth", "dest_opt", "fragment", "hop_opt", "no_next", "routing",
            }:
                setattr(item, clean_key, None)
            item.extra_settings.pop(clean_key, None)
            item.extra_settings.pop(f"unparsed_{clean_key}", None)

    @staticmethod
    def _normalize_address_nested_entries(attributes: Dict[str, Any]) -> None:
        normalized_list = []
        for raw_entry in attributes.get("address_list", []):
            entry = dict(raw_entry)
            entry["extra_settings"] = _extract_extra_settings(
                entry, set(FGAddressListEntry.model_fields)
            )
            normalized_list.append(FGAddressListEntry(**entry))
        attributes["address_list"] = normalized_list

        normalized_tagging = []
        for raw_entry in attributes.get("tagging", []):
            entry = dict(raw_entry)
            entry["extra_settings"] = _extract_extra_settings(
                entry, set(FGAddressTaggingEntry.model_fields)
            )
            normalized_tagging.append(FGAddressTaggingEntry(**entry))
        attributes["tagging"] = normalized_tagging

    @staticmethod
    def _normalize_ssl_vpn_nested(attributes: Dict[str, Any]) -> None:
        def safe_entry(raw: Dict[str, Any], model: Any) -> Any:
            entry = dict(raw)
            if entry.get("name") == str(entry.get("id")):
                entry.pop("name", None)
            entry["extra_settings"] = _extract_extra_settings(
                entry, set(model.model_fields)
            )
            return model(**entry)

        split_dns = [
            safe_entry(item, FGSSLVPNPortalSplitDNS)
            for item in attributes.pop("split_dns", [])
        ]
        mac_rules = [
            safe_entry(item, FGSSLVPNPortalMACAddressRule)
            for item in attributes.pop("mac_address_check_rules", [])
        ]
        os_checks = [
            safe_entry(item, FGSSLVPNPortalOSCheck)
            for item in attributes.pop("os_check_list", [])
        ]

        def form_items(raw_items: List[Dict[str, Any]], model: Any) -> List[Any]:
            result = []
            for raw in raw_items:
                item = dict(raw)
                item.pop("value", None)
                item["value_configured"] = True
                result.append(safe_entry(item, model))
            return result

        bookmarks = []
        for raw_group in attributes.pop("bookmark_groups", []):
            group = dict(raw_group)
            raw_bookmarks = group.pop("bookmarks", [])
            group["bookmarks"] = []
            for raw_bookmark in raw_bookmarks:
                bookmark = dict(raw_bookmark)
                bookmark["has_logon_password"] = "logon_password" in bookmark
                bookmark["has_sso_password"] = "sso_password" in bookmark
                bookmark.pop("logon_password", None)
                bookmark.pop("sso_password", None)
                bookmark["form_data"] = form_items(
                    bookmark.pop("form_data", []), FGSSLVPNPortalBookmarkFormData
                )
                group["bookmarks"].append(safe_entry(bookmark, FGSSLVPNPortalBookmark))
            bookmarks.append(safe_entry(group, FGSSLVPNPortalBookmarkGroup))

        landing_pages = []
        for raw_page in attributes.pop("landing_pages", []):
            page = dict(raw_page)
            page["has_sso_password"] = "sso_password" in page
            page.pop("sso_password", None)
            page["form_data"] = form_items(
                page.pop("form_data", []), FGSSLVPNPortalLandingPageFormData
            )
            landing_pages.append(safe_entry(page, FGSSLVPNPortalLandingPage))

        attributes.update({
            "bookmark_groups": bookmarks,
            "landing_pages": landing_pages,
            "mac_address_check_rules": mac_rules,
            "os_check_list": os_checks,
            "split_dns": split_dns,
        })

    def build_model(
        self,
        section_path: str,
        attributes: Dict[str, Any],
    ) -> None:
        from fwmigrate.parsers.fortigate.builders import build_model as build_section

        if build_section(self, section_path, attributes):
            return
def parse_fortigate_config(
    text: str,
) -> FGConfig:
    tokenizer = FortiGateTokenizer(text)
    parser = FortiGateParser(tokenizer)

    return parser.parse()
