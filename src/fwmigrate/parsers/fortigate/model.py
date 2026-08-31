from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field, model_validator

from fwmigrate.parsers.fortigate.source_tree import FGSourceNode, FGStructuredSourceObject


class FGContextualModel(BaseModel):
    """Source object identity is scoped by VDOM, never by name alone."""

    source_context: str = "root"
    nested_configs: List[FGSourceNode] = Field(default_factory=list)


class FGExecutionContext(BaseModel):
    vdom: str = "root"
    scope: str = "vdom"
    central_nat: Optional[str] = None
    ngfw_mode: Optional[str] = None
    opmode: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGInterfaceSecondaryIP(BaseModel):
    id: int
    ip: Optional[str] = None
    allowaccess: List[str] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGInterface(BaseModel):
    name: str
    vdom: str = "root"
    source_context: str = "root"

    ip: Optional[str] = None
    remote_ip: Optional[str] = None

    # FortiOS parent enable-state for the nested ``secondaryip`` collection.
    # Child entries remain preserved in ``secondary_ips`` even when disabled.
    secondary_ip: Optional[str] = None
    secondary_ips: List[
        FGInterfaceSecondaryIP
    ] = Field(default_factory=list)

    allowaccess: List[str] = Field(default_factory=list)

    # Common FortiOS IPv6 interface settings. Complex IPv6 behavior remains
    # in ipv6_source_settings and the recursive nested source tree below.
    ip6_address: Optional[str] = None
    ip6_allowaccess: List[str] = Field(default_factory=list)
    ip6_mode: Optional[str] = None
    ip6_send_adv: Optional[str] = None
    ip6_manage_flag: Optional[str] = None
    ip6_other_flag: Optional[str] = None

    # FortiOS exposes these interface settings as ordered multi-value CLI
    # fields.  They remain source-oriented fields; the transformer retains
    # them in IRInterface.source_attributes for extraction/reporting.
    fail_alert_interfaces: List[str] = Field(default_factory=list)
    fail_detect_option: List[str] = Field(default_factory=list)
    dns_server_protocol: List[str] = Field(default_factory=list)
    security_groups: List[str] = Field(default_factory=list)

    type: Optional[str] = None
    # Aggregate and redundant interfaces retain their ordered FortiOS member
    # relationships as typed source topology.
    members: List[str] = Field(default_factory=list)
    role: str = "undefined"
    alias: Optional[str] = None
    description: Optional[str] = None

    vlanid: Optional[int] = None
    interface: Optional[str] = None
    vrf: Optional[int] = None

    status: str = "up"
    mode: str = "static"
    username: Optional[str] = None

    # Nested FortiGate interface configuration that is not yet
    # represented by a dedicated typed interface model.
    #
    # Examples:
    #   config ipv6
    #   config vrrp
    #   config client-options
    #   config tagging
    #   config l2tp-client-settings
    #
    # This is extraction-only source data. Target generators must
    # never interpret this structure as portable interface semantics.
    nested_configs: List[
        FGSourceNode
    ] = Field(default_factory=list)
    ipv6_source_settings: Dict[str, Any] = Field(default_factory=dict)

    # Explicit top-level `set` values retained for
    # extraction/reporting only.
    source_attributes: Dict[str, Any] = Field(
        default_factory=dict
    )

class FGSystemZone(FGContextualModel):
    name: str
    interface: List[str] = Field(default_factory=list)
    tag: Optional[str] = None
    description: Optional[str] = None

class FGAddressListEntry(BaseModel):
    name: str
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAddressTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAddress(FGContextualModel):
    name: str
    uuid: Optional[str] = None
    type: str = "ipmask"  # ipmask, fqdn, iprange, dynamic
    sub_type: Optional[str] = None
    subnet: Optional[str] = None  # e.g. "192.168.1.0 255.255.255.0"
    ip6: Optional[str] = None
    fqdn: Optional[str] = None
    wildcard_fqdn: Optional[str] = None
    wildcard: Optional[str] = None
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    country: Optional[str] = None
    interface: Optional[str] = None
    route_tag: Optional[int] = None
    comment: Optional[str] = None
    macaddr: Optional[str] = None
    mac: Optional[str] = None
    associated_interface: Optional[str] = None
    allow_routing: Optional[str] = None
    color: Optional[int] = None
    # For dynamic addresses (e.g. EMS tags)
    ems_tag_name: Optional[str] = None
    obj_tag: Optional[str] = None
    tag_type: Optional[str] = None
    obj_type: Optional[str] = None
    dirty: Optional[str] = None
    sdn: Optional[str] = None
    filter: Optional[str] = None
    address_list: List[FGAddressListEntry] = Field(default_factory=list)
    tagging: List[FGAddressTaggingEntry] = Field(default_factory=list)
    is_ipv6: bool = False
    is_multicast: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGAddressGroupTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAddressGroup(FGContextualModel):
    name: str
    member: List[str] = Field(default_factory=list)
    exclude: Optional[str] = None
    exclude_member: List[str] = Field(default_factory=list)
    comment: Optional[str] = None
    uuid: Optional[str] = None
    allow_routing: Optional[str] = None
    color: Optional[int] = None
    category: Optional[str] = None
    type: Optional[str] = None
    fabric_object: Optional[str] = None
    tagging: List[FGAddressGroupTaggingEntry] = Field(default_factory=list)
    is_ipv6: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGWildcardFQDN(FGContextualModel):
    name: str
    wildcard_fqdn: str
    comment: Optional[str] = None
    uuid: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGServiceCategory(FGContextualModel):
    name: str
    comment: Optional[str] = None
    fabric_object: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGService(FGContextualModel):
    name: str
    protocol: str = "tcp/udp/sctp"  # default
    source_protocol_configured: Optional[str] = None
    tcp_portrange: Optional[str] = None
    udp_portrange: Optional[str] = None
    sctp_portrange: Optional[str] = None
    protocol_number: Optional[int] = None
    icmpcode: Optional[int] = None
    icmptype: Optional[int] = None
    comment: Optional[str] = None
    uuid: Optional[str] = None
    category: Optional[str] = None
    proxy: Optional[str] = None
    color: Optional[int] = None
    fabric_object: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGServiceGroup(FGContextualModel):
    name: str
    member: List[str] = Field(default_factory=list)
    comment: Optional[str] = None
    uuid: Optional[str] = None
    color: Optional[int] = None
    proxy: Optional[str] = None
    fabric_object: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGSchedule(FGContextualModel):
    name: str
    type: str = "recurring"
    start: Optional[str] = None
    end: Optional[str] = None
    day: List[str] = Field(default_factory=list)
    color: Optional[int] = None
    expiration_days: Optional[int] = None
    fabric_object: Optional[str] = None
    start_utc: Optional[str] = None
    end_utc: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGTrafficShaper(FGContextualModel):
    name: str
    guaranteed_bandwidth: Optional[int] = None
    maximum_bandwidth: Optional[int] = None
    bandwidth_unit: Optional[str] = None
    priority: Optional[str] = None
    per_policy: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGProxyAddress(FGContextualModel):
    name: str
    uuid: Optional[str] = None
    type: Optional[str] = None
    host: Optional[str] = None
    host_regex: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGWebProxyGlobal(BaseModel):
    proxy_fqdn: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGIPPool(FGContextualModel):
    name: str

    type: str = "overload"

    startip: Optional[str] = None
    endip: Optional[str] = None

    source_startip: Optional[str] = None
    source_endip: Optional[str] = None
    source_prefix6: Optional[str] = None

    startport: Optional[int] = None
    endport: Optional[int] = None

    associated_interface: Optional[str] = None

    arp_reply: str = "enable"
    arp_intf: Optional[str] = None

    permit_any_host: str = "disable"
    exclude_ip: List[str] = Field(default_factory=list)

    block_size: Optional[int] = None
    num_blocks_per_user: Optional[int] = None
    pba_timeout: Optional[int] = None
    pba_interim_log: Optional[int] = None
    port_per_user: Optional[int] = None
    privileged_port_use_pba: Optional[str] = None

    nat64: str = "disable"
    add_nat64_route: Optional[str] = None
    client_prefix_length: Optional[int] = None
    subnet_broadcast_in_ippool: Optional[str] = None

    tcp_session_quota: Optional[int] = None
    udp_session_quota: Optional[int] = None
    icmp_session_quota: Optional[int] = None

    cgn_block_size: Optional[int] = None
    cgn_client_startip: Optional[str] = None
    cgn_client_endip: Optional[str] = None
    cgn_client_ipv6shift: Optional[int] = None
    cgn_fixedalloc: Optional[str] = None
    cgn_overload: Optional[str] = None
    cgn_port_start: Optional[int] = None
    cgn_port_end: Optional[int] = None
    cgn_spa: Optional[str] = None

    utilization_alarm_clear: Optional[int] = None
    utilization_alarm_raise: Optional[int] = None

    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGScheduleGroup(FGContextualModel):
    name: str
    member: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGIPPool6(FGContextualModel):
    name: str
    startip: Optional[str] = None
    endip: Optional[str] = None
    nat46: Optional[str] = None
    add_nat46_route: Optional[str] = None
    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGVIPRealServer(BaseModel):
    id: int
    type: str = "ip"
    address: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    status: Optional[str] = None
    weight: Optional[int] = None
    holddown_interval: Optional[int] = None
    healthcheck: Optional[str] = None
    http_host: Optional[str] = None
    translate_host: Optional[str] = None
    max_connections: Optional[int] = None
    monitor: List[str] = Field(default_factory=list)
    client_ip: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGVIP(FGContextualModel):
    name: str

    id: Optional[int] = None
    uuid: Optional[str] = None

    type: str = "static-nat"
    status: str = "enable"

    extip: Optional[str] = None
    extaddr: List[str] = Field(default_factory=list)
    mappedip: List[str] = Field(default_factory=list)
    mapped_addr: Optional[str] = None

    extintf: str = "any"
    arp_reply: str = "enable"

    portforward: str = "disable"
    protocol: Optional[str] = None
    extport: Optional[str] = None
    mappedport: Optional[str] = None
    portmapping_type: Optional[str] = None

    nat_source_vip: str = "disable"
    add_nat46_route: Optional[str] = None
    nat44: Optional[str] = None
    nat46: Optional[str] = None
    ipv6_mappedip: Optional[str] = None
    ipv6_mappedport: Optional[str] = None

    src_filter: List[str] = Field(default_factory=list)
    srcintf_filter: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)

    gratuitous_arp_interval: Optional[int] = None

    ldb_method: Optional[str] = None
    server_type: Optional[str] = None
    persistence: Optional[str] = None
    http_redirect: Optional[str] = None
    monitor: List[str] = Field(default_factory=list)
    max_embryonic_connections: Optional[int] = None
    realservers: List[FGVIPRealServer] = Field(default_factory=list)

    comment: Optional[str] = None
    color: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGVIPGroup(FGContextualModel):
    name: str
    uuid: Optional[str] = None
    interface: Optional[str] = None
    color: Optional[int] = None
    member: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    comment: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGVIP6(FGContextualModel):
    name: str
    id: Optional[int] = None
    uuid: Optional[str] = None
    type: str = "static-nat"
    status: str = "enable"
    extip: Optional[str] = None
    extport: Optional[str] = None
    mappedip: List[str] = Field(default_factory=list)
    mappedport: Optional[str] = None
    ipv4_mappedip: Optional[str] = None
    ipv4_mappedport: Optional[str] = None
    embedded_ipv4_address: Optional[str] = None
    nat_source_vip: Optional[str] = None
    nat64: Optional[str] = None
    nat66: Optional[str] = None
    add_nat64_route: Optional[str] = None
    ndp_reply: Optional[str] = None
    portforward: Optional[str] = None
    protocol: Optional[str] = None
    ldb_method: Optional[str] = None
    server_type: Optional[str] = None
    persistence: Optional[str] = None
    monitor: List[str] = Field(default_factory=list)
    src_filter: List[str] = Field(default_factory=list)
    realservers: List[FGVIPRealServer] = Field(default_factory=list)
    comment: Optional[str] = None
    color: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGVIPGroup6(FGContextualModel):
    name: str
    uuid: Optional[str] = None
    color: Optional[int] = None
    member: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGPolicy(FGContextualModel):
    # Portable policy intent.  These fields are the source-side values that
    # can be normalized into the vendor-neutral policy match/action model.
    id: int
    uuid: Optional[str] = None
    name: Optional[str] = None
    srcintf: List[str] = Field(default_factory=list)
    dstintf: List[str] = Field(default_factory=list)
    srcaddr: List[str] = Field(default_factory=list)
    dstaddr: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    action: str = "deny"
    schedule: Optional[str] = None
    service: List[str] = Field(default_factory=list)
    logtraffic: str = "utm"
    logtraffic_start: Optional[str] = None
    status: str = "enable"
    comments: Optional[str] = None

    # FortiGate-specific typed source semantics.  These are intentionally
    # kept separate from portable intent so a target generator cannot mistake
    # a FortiOS-only behavior for a complete cross-vendor conversion.
    service_negate: Optional[str] = None
    srcaddr_negate: Optional[str] = None
    dstaddr_negate: Optional[str] = None
    srcaddr6: List[str] = Field(default_factory=list)
    dstaddr6: List[str] = Field(default_factory=list)
    srcaddr6_negate: Optional[str] = None
    dstaddr6_negate: Optional[str] = None
    nat: str = "disable"
    ippool: str = "disable"
    poolname: List[str] = Field(default_factory=list)
    poolname6: List[str] = Field(default_factory=list)
    fixedport: Optional[str] = None
    match_vip: Optional[str] = None
    match_vip_only: Optional[str] = None
    nat46: Optional[str] = None
    nat64: Optional[str] = None
    natinbound: Optional[str] = None
    natoutbound: Optional[str] = None
    natip: Optional[str] = None
    utm_status: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    av_profile: Optional[str] = None
    webfilter_profile: Optional[str] = None
    ips_sensor: Optional[str] = None
    application_list: Optional[str] = None
    profile_type: Optional[str] = None
    profile_group: Optional[str] = None
    profile_protocol_options: Optional[str] = None
    internet_service: str = "disable"
    internet_service_custom: List[str] = Field(default_factory=list)
    internet_service_custom_group: List[str] = Field(default_factory=list)
    internet_service_group: List[str] = Field(default_factory=list)
    internet_service_name: List[str] = Field(default_factory=list)
    internet_service_negate: Optional[str] = None
    internet_service_src: str = "disable"
    internet_service_src_custom: List[str] = Field(default_factory=list)
    internet_service_src_custom_group: List[str] = Field(default_factory=list)
    internet_service_src_group: List[str] = Field(default_factory=list)
    internet_service_src_name: List[str] = Field(default_factory=list)
    internet_service_src_negate: Optional[str] = None
    internet_service6: str = "disable"
    internet_service6_custom: List[str] = Field(default_factory=list)
    internet_service6_custom_group: List[str] = Field(default_factory=list)
    internet_service6_group: List[str] = Field(default_factory=list)
    internet_service6_name: List[str] = Field(default_factory=list)
    internet_service6_negate: Optional[str] = None
    internet_service6_src: str = "disable"
    internet_service6_src_custom: List[str] = Field(default_factory=list)
    internet_service6_src_custom_group: List[str] = Field(default_factory=list)
    internet_service6_src_group: List[str] = Field(default_factory=list)
    internet_service6_src_name: List[str] = Field(default_factory=list)
    internet_service6_src_negate: Optional[str] = None
    inspection_mode: Optional[str] = None
    ztna_status: Optional[str] = None
    ztna_device_ownership: Optional[str] = None
    ztna_ems_tag: List[str] = Field(default_factory=list)
    ztna_ems_tag_secondary: List[str] = Field(default_factory=list)
    ztna_geo_tag: List[str] = Field(default_factory=list)
    ztna_policy_redirect: Optional[str] = None
    ztna_tags_match_logic: Optional[str] = None
    vpntunnel: Optional[str] = None

    # Any recognized source setting that is not important and known enough to
    # type remains here.  The parser sanitizes these values for audit/export.
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGPhase1Interface(FGContextualModel):
    name: str
    type: Optional[str] = None
    interface: str
    local_gw: Optional[str] = None
    remote_gw: Optional[str] = None
    ike_version: Optional[str] = None
    mode: Optional[str] = None
    peertype: Optional[str] = None
    net_device: Optional[str] = None
    proposal: List[str] = Field(default_factory=list)
    mode_cfg: Optional[str] = None
    eap: Optional[str] = None
    eap_identity: Optional[str] = None
    authusrgrp: Optional[str] = None
    ipv4_start_ip: Optional[str] = None
    ipv4_end_ip: Optional[str] = None
    dns_mode: Optional[str] = None
    ipv4_split_include: List[str] = Field(default_factory=list)
    dpd_retryinterval: Optional[int] = None
    comments: Optional[str] = None
    has_psk: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGPhase2Interface(FGContextualModel):
    name: str
    phase1name: str
    proposal: List[str] = Field(default_factory=list)
    src_addr_type: Optional[str] = None
    dst_addr_type: Optional[str] = None
    src_name: List[str] = Field(default_factory=list)
    dst_name: List[str] = Field(default_factory=list)
    src_subnet: Optional[str] = None
    dst_subnet: Optional[str] = None
    auto_negotiate: Optional[str] = None
    dhgrp: List[int] = Field(default_factory=list)
    keepalive: Optional[str] = None
    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGStaticRoute(FGContextualModel):
    id: int
    address_family: str = "ipv4"
    dst: Optional[str] = None
    dstaddr: Optional[str] = None
    gateway: Optional[str] = None
    device: Optional[str] = None
    # FortiOS effective defaults.  These remain Optional so an explicitly
    # malformed numeric source value can be retained as unresolved rather
    # than silently replaced by the effective default.
    distance: Optional[int] = 10
    priority: Optional[int] = 1
    weight: Optional[int] = 0
    comment: Optional[str] = None
    sdwan_zone: List[str] = Field(default_factory=list)
    dynamic_gateway: Optional[str] = None
    link_monitor_exempt: Optional[str] = None
    src: Optional[str] = None
    bfd: Optional[str] = None
    vrf: Optional[int] = None
    tag: Optional[int] = None
    internet_service: Optional[int] = None
    internet_service_custom: Optional[str] = None
    blackhole: str = "disable"
    status: Optional[str] = "enable"
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGCentralSNATRule(FGContextualModel):
    id: int
    status: str = "enable"
    srcintf: List[str] = Field(default_factory=list)
    dstintf: List[str] = Field(default_factory=list)
    orig_addr: List[str] = Field(default_factory=list)
    dst_addr: List[str] = Field(default_factory=list)
    protocol: Optional[str] = None
    orig_port: Optional[str] = None
    dst_port: Optional[str] = None
    nat: Optional[str] = None
    nat_ippool: List[str] = Field(default_factory=list)
    nat_port: Optional[str] = None
    nat46: Optional[str] = None
    nat64: Optional[str] = None
    port_preserve: Optional[str] = None
    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSourceOnlyRule(FGContextualModel):
    """A distinct FortiGate rule family retained outside portable policy IR."""

    family: str
    id: Optional[int] = None
    name: Optional[str] = None
    source_order: int = 0
    status: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    nested_configs: List[FGSourceNode] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGSDWanZone(BaseModel):
    name: str
    source_context: str = "root"
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGSDWanMember(BaseModel):
    """FortiOS SD-WAN member with effective defaults and source provenance."""

    id: int
    source_context: str = "root"
    interface: str
    zone: str = "virtual-wan-link"
    gateway: Optional[str] = None
    source: Optional[str] = None
    gateway6: Optional[str] = None
    source6: Optional[str] = None
    cost: Optional[int] = None
    weight: int = 1
    priority: int = 1
    priority6: Optional[int] = None
    spillover_threshold: Optional[int] = None
    ingress_spillover_threshold: Optional[int] = None
    volume_ratio: Optional[int] = None
    status: str = "enable"
    comment: Optional[str] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanSLA(BaseModel):
    id: int
    source_context: str = "root"
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanHealthCheck(BaseModel):
    """FortiOS SD-WAN health check with effective defaults and provenance."""

    name: str
    source_context: str = "root"
    server: Optional[str] = None
    members: List[int] = Field(default_factory=list)
    protocol: str = "ping"
    port: Optional[int] = None
    interval: int = 500
    probe_timeout: Optional[int] = None
    failtime: int = 5
    recoverytime: int = 5
    update_static_route: Optional[str] = None
    vrf: Optional[int] = None
    source: Optional[str] = None
    sla: List[FGSDWanSLA] = Field(default_factory=list)
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanServiceSLA(BaseModel):
    name: str
    source_context: str = "root"
    id: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanService(BaseModel):
    """FortiOS SD-WAN service rule with effective defaults and provenance."""

    id: int
    source_context: str = "root"
    name: Optional[str] = None
    mode: str = "manual"
    status: str = "enable"
    src: List[str] = Field(default_factory=list)
    dst: List[str] = Field(default_factory=list)
    health_check: List[str] = Field(default_factory=list)
    priority_members: List[int] = Field(default_factory=list)
    priority_zone: List[str] = Field(default_factory=list)
    internet_service: Optional[str] = None
    internet_service_name: List[str] = Field(default_factory=list)
    internet_service_app_ctrl: List[int] = Field(default_factory=list)
    sla_compare_method: Optional[str] = None
    tie_break: Optional[str] = None
    use_shortcut_sla: Optional[str] = None
    sla: List[FGSDWanServiceSLA] = Field(default_factory=list)
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanDuplication(BaseModel):
    id: int
    source_context: str = "root"
    service_id: Optional[int] = None
    srcaddr: List[str] = Field(default_factory=list)
    dstaddr: List[str] = Field(default_factory=list)
    srcaddr6: List[str] = Field(default_factory=list)
    dstaddr6: List[str] = Field(default_factory=list)
    srcintf: List[str] = Field(default_factory=list)
    dstintf: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    packet_duplication: Optional[str] = None
    sla_match_service: Optional[str] = None
    packet_de_duplication: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanNeighbor(BaseModel):
    name: str
    source_context: str = "root"
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWan(BaseModel):
    source_context: str = "root"
    status: str = "disable"
    load_balance_mode: Optional[str] = None
    zones: List[FGSDWanZone] = Field(default_factory=list)
    members: List[FGSDWanMember] = Field(default_factory=list)
    health_checks: List[FGSDWanHealthCheck] = Field(default_factory=list)
    services: List[FGSDWanService] = Field(default_factory=list)
    duplication_rules: List[FGSDWanDuplication] = Field(default_factory=list)
    neighbors: List[FGSDWanNeighbor] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDns(BaseModel):
    primary: Optional[str] = None
    secondary: Optional[str] = None
    # FortiOS-specific behavior is retained explicitly for audit/reporting;
    # only primary/secondary are portable IR fields today.
    protocol: Optional[str] = None
    server_select_method: Optional[str] = None
    domain: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    source_ip: Optional[str] = None
    source_ip6: Optional[str] = None
    ssl_certificate: Optional[str] = None
    timeout: Optional[int] = None
    retry: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSystemGlobal(BaseModel):
    hostname: Optional[str] = None
    admin_sport: Optional[int] = None
    timezone: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGInternetService(BaseModel):
    name: str
    id: Optional[int] = None
    comment: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGInternetServiceDefinitionPortRange(BaseModel):
    id: int
    start_port: Optional[int] = None
    end_port: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGInternetServiceDefinitionEntry(BaseModel):
    seq_num: int
    category_id: Optional[int] = None
    name: Optional[str] = None
    protocol: Optional[int] = None
    port_ranges: List[FGInternetServiceDefinitionPortRange] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGInternetServiceDefinition(BaseModel):
    id: int
    entries: List[FGInternetServiceDefinitionEntry] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGFCTEMS(BaseModel):
    id: int
    name: Optional[str] = None
    status: str = "disable"

    fortinetone_cloud_authentication: Optional[str] = None
    serial_number: Optional[str] = None
    tenant_id: Optional[str] = None

    capabilities: List[str] = Field(default_factory=list)

    verifying_ca: Optional[str] = None
    verified_cn: Optional[str] = None

    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSessionHelper(BaseModel):
    id: int
    name: Optional[str] = None
    protocol: Optional[int] = None
    port: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSessionTTLOverride(BaseModel):
    id: int
    protocol: Optional[int] = None
    timeout: Optional[int] = None
    start_port: Optional[int] = None
    end_port: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGDHCPIPRange(BaseModel):
    id: int
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDHCPReservation(BaseModel):
    id: int
    ip: Optional[str] = None
    mac: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDHCPExcludeRange(BaseModel):
    id: int
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDHCPOption(BaseModel):
    id: int
    code: Optional[int] = None
    type: Optional[str] = None
    value: Optional[str] = None
    ip: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDHCPServer(FGContextualModel):
    id: int
    status: str = "enable"

    interface: Optional[str] = None
    default_gateway: Optional[str] = None
    netmask: Optional[str] = None
    lease_time: Optional[int] = None

    dns_service: Optional[str] = None
    dns_server1: Optional[str] = None
    dns_server2: Optional[str] = None
    dns_server3: Optional[str] = None

    timezone_option: Optional[str] = None

    ip_ranges: List[FGDHCPIPRange] = Field(default_factory=list)
    exclude_ranges: List[FGDHCPExcludeRange] = Field(default_factory=list)
    reserved_addresses: List[FGDHCPReservation] = Field(
        default_factory=list
    )
    options: List[FGDHCPOption] = Field(default_factory=list)

    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGCertificate(BaseModel):
    name: str
    certificate_type: str

    range: Optional[str] = None
    source: Optional[str] = None
    comments: Optional[str] = None
    last_updated: Optional[int] = None

    public_certificate: Optional[str] = None

    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    public_key_algorithm: Optional[str] = None
    public_key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    sha256_fingerprint: Optional[str] = None
    is_self_signed: Optional[bool] = None
    is_ca: Optional[bool] = None

    has_certificate: bool = False
    has_private_key: bool = False
    private_key_encrypted: bool = False
    has_password: bool = False

    parse_error: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGIPSSensorEntry(BaseModel):
    id: int
    rules: List[int] = Field(default_factory=list)
    severity: List[str] = Field(default_factory=list)
    location: Optional[str] = None
    protocol: List[str] = Field(default_factory=list)
    status: Optional[str] = None
    action: Optional[str] = None
    rate_count: Optional[int] = None
    rate_duration: Optional[int] = None
    quarantine: Optional[str] = None
    quarantine_expiry: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGIPSSensor(FGContextualModel):
    name: str
    comment: Optional[str] = None
    block_malicious_url: Optional[str] = None
    scan_botnet_connections: Optional[str] = None
    entries: List[FGIPSSensorEntry] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSHKey(BaseModel):
    name: str
    key_type: str
    public_key: Optional[str] = None
    source: Optional[str] = None
    has_private_key: bool = False
    has_password: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserLDAP(BaseModel):
    name: str
    server: Optional[str] = None
    cnid: Optional[str] = None
    dn: Optional[str] = None
    type: Optional[str] = None
    username: Optional[str] = None
    has_password: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGFSSOServer(BaseModel):
    name: str
    server: Optional[str] = None
    has_password: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGADGroup(BaseModel):
    name: str
    server_name: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserSAML(BaseModel):
    name: str
    entity_id: Optional[str] = None
    single_sign_on_url: Optional[str] = None
    single_logout_url: Optional[str] = None
    idp_entity_id: Optional[str] = None
    idp_single_sign_on_url: Optional[str] = None
    idp_single_logout_url: Optional[str] = None
    idp_cert: Optional[str] = None
    user_name: Optional[str] = None
    group_name: Optional[str] = None
    digest_method: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGLocalUser(BaseModel):
    name: str
    status: Optional[str] = None
    type: Optional[str] = None
    has_password: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserGroupMatch(BaseModel):
    id: int
    server_name: Optional[str] = None
    group_name: Optional[str] = None


class FGUserGroup(BaseModel):
    name: str
    group_type: Optional[str] = None
    member: List[str] = Field(default_factory=list)
    match: List[FGUserGroupMatch] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAdministrator(BaseModel):
    name: str
    accprofile: Optional[str] = None
    accprofile_override: Optional[str] = None
    vdom: List[str] = Field(default_factory=list)
    vdom_override: Optional[str] = None
    trusthost1: Optional[str] = None
    trusthost2: Optional[str] = None
    trusthost3: Optional[str] = None
    trusthost4: Optional[str] = None
    trusthost5: Optional[str] = None
    trusthost6: Optional[str] = None
    trusthost7: Optional[str] = None
    trusthost8: Optional[str] = None
    trusthost9: Optional[str] = None
    trusthost10: Optional[str] = None
    ip6_trusthost1: Optional[str] = None
    ip6_trusthost2: Optional[str] = None
    ip6_trusthost3: Optional[str] = None
    ip6_trusthost4: Optional[str] = None
    ip6_trusthost5: Optional[str] = None
    ip6_trusthost6: Optional[str] = None
    ip6_trusthost7: Optional[str] = None
    ip6_trusthost8: Optional[str] = None
    ip6_trusthost9: Optional[str] = None
    ip6_trusthost10: Optional[str] = None
    two_factor: Optional[str] = None
    two_factor_authentication: Optional[str] = None
    two_factor_notification: Optional[str] = None
    fortitoken: Optional[str] = None
    email_to: Optional[str] = None
    remote_auth: Optional[str] = None
    remote_group: Optional[str] = None
    guest_auth: Optional[str] = None
    guest_lang: Optional[str] = None
    guest_usergroups: List[str] = Field(default_factory=list)
    schedule: Optional[str] = None
    peer_auth: Optional[str] = None
    peer_group: Optional[str] = None
    ssh_certificate: Optional[str] = None
    ssh_public_key1: Optional[str] = None
    ssh_public_key2: Optional[str] = None
    ssh_public_key3: Optional[str] = None
    wildcard: Optional[str] = None
    credential_configured: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAdminProfilePermissionBlock(BaseModel):
    name: str
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSessionTTLSettings(BaseModel):
    default_timeout: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserAuthenticationSettings(BaseModel):
    auth_cert: Optional[str] = None
    auth_ca_cert: Optional[str] = None
    auth_timeout: Optional[int] = None
    auth_lockout_threshold: Optional[int] = None
    auth_lockout_duration: Optional[int] = None
    ssl_min_proto_version: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserQuarantine(BaseModel):
    firewall_groups: List[str] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAdminProfile(BaseModel):
    name: str
    permission_blocks: List[FGAdminProfilePermissionBlock] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGFortiToken(BaseModel):
    serial: str
    status: Optional[str] = None
    comments: Optional[str] = None
    assigned_user: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNHostCheckItem(BaseModel):
    id: int
    action: Optional[str] = None
    md5s: List[str] = Field(default_factory=list)
    target: Optional[str] = None
    type: Optional[str] = None
    version: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNHostCheckSoftware(BaseModel):
    name: str
    type: Optional[str] = None
    os_type: Optional[str] = None
    guid: Optional[str] = None
    version: Optional[str] = None
    check_items: List[FGSSLVPNHostCheckItem] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNPortal(BaseModel):
    name: str
    tunnel_mode: Optional[str] = None
    ipv6_tunnel_mode: Optional[str] = None
    ip_pools: List[str] = Field(default_factory=list)
    ipv6_pools: List[str] = Field(default_factory=list)
    split_tunneling: Optional[str] = None
    limit_user_logins: Optional[str] = None
    forticlient_download: Optional[str] = None
    host_check: Optional[str] = None
    host_check_policy: List[str] = Field(default_factory=list)
    host_check_interval: Optional[int] = None
    allow_user_access: List[str] = Field(default_factory=list)
    auto_connect: Optional[str] = None
    exclusive_routing: Optional[str] = None
    ip_mode: Optional[str] = None
    service_restriction: Optional[str] = None
    split_tunneling_routing_address: List[str] = Field(default_factory=list)
    split_tunneling_routing_negate: Optional[str] = None
    host_checks: List[FGSSLVPNHostCheckSoftware] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNAuthenticationRule(BaseModel):
    id: int
    auth: Optional[str] = None
    cipher: Optional[str] = None
    client_cert: Optional[str] = None
    realm: Optional[str] = None
    source_address: List[str] = Field(default_factory=list)
    source_address_negate: Optional[str] = None
    source_address6: List[str] = Field(default_factory=list)
    source_address6_negate: Optional[str] = None
    source_interface: List[str] = Field(default_factory=list)
    user_peer: Optional[str] = None
    users: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    portal: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNSettings(BaseModel):
    status: Optional[str] = None
    ssl_min_proto_ver: Optional[str] = None
    banned_cipher: List[str] = Field(default_factory=list)
    servercert: Optional[str] = None
    servercert_configured: bool = False
    ssl_max_proto_ver: Optional[str] = None
    algorithm: Optional[str] = None
    client_sigalgs: List[str] = Field(default_factory=list)
    reqclientcert: Optional[str] = None
    dtls_tunnel: Optional[str] = None
    login_attempt_limit: Optional[int] = None
    login_block_time: Optional[int] = None
    auth_timeout: Optional[int] = None
    idle_timeout: Optional[int] = None
    port: Optional[int] = None
    dns_server1: Optional[str] = None
    dns_server2: Optional[str] = None
    wins_server1: Optional[str] = None
    wins_server2: Optional[str] = None
    source_interface: List[str] = Field(default_factory=list)
    source_address: List[str] = Field(default_factory=list)
    tunnel_ip_pools: List[str] = Field(default_factory=list)
    default_portal: Optional[str] = None
    authentication_rules: List[FGSSLVPNAuthenticationRule] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDoSAnomaly(BaseModel):
    name: str
    status: Optional[str] = None
    log: Optional[str] = None
    action: Optional[str] = None
    threshold: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDoSPolicy(BaseModel):
    id: int
    source_context: str = "root"
    address_family: str = "ipv4"
    status: Optional[str] = None
    interface: Optional[str] = None
    srcaddr: List[str] = Field(default_factory=list)
    dstaddr: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    anomalies: List[FGDoSAnomaly] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGNetworkServiceDynamic(FGContextualModel):
    name: str
    filter: Optional[str] = None
    sdn: Optional[str] = None
    comment: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDNConnector(FGContextualModel):
    name: str
    type: Optional[str] = None
    status: Optional[str] = None
    server: Optional[str] = None
    has_secret: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserRADIUS(FGContextualModel):
    name: str
    server: Optional[str] = None
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None
    auth_type: Optional[str] = None
    nas_ip: Optional[str] = None
    source_ip: Optional[str] = None
    radius_port: Optional[int] = None
    acct_interim_interval: Optional[int] = None
    has_secret: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserTACACS(FGContextualModel):
    name: str
    server: Optional[str] = None
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None
    port: Optional[int] = None
    authen_type: Optional[str] = None
    authorization: Optional[str] = None
    source_ip: Optional[str] = None
    has_secret: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGLinkMonitor(FGContextualModel):
    name: str
    srcintf: List[str] = Field(default_factory=list)
    server: List[str] = Field(default_factory=list)
    protocol: Optional[str] = None
    status: Optional[str] = None
    gateway_ip: Optional[str] = None
    source_ip: Optional[str] = None
    interval: Optional[int] = None
    failtime: Optional[int] = None
    recoverytime: Optional[int] = None
    update_static_route: Optional[str] = None
    update_policy_route: Optional[str] = None
    update_cascade_interface: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGTopologyObject(FGContextualModel):
    name: str
    members: List[str] = Field(default_factory=list)
    parent: Optional[str] = None
    interface: Optional[str] = None
    status: Optional[str] = None
    type: Optional[str] = None
    mode: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAccessProxy(FGContextualModel):
    name: str
    family: str = "ipv4"
    vip: Optional[str] = None
    extip: Optional[str] = None
    extport: Optional[str] = None
    server_type: Optional[str] = None
    client_cert: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGEMSOverride(FGContextualModel):
    name: str
    kind: str = "OVERRIDE"
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNRealm(FGContextualModel):
    name: str
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNBookmark(FGContextualModel):
    name: str
    bookmark_type: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGManualKeyInterface(FGContextualModel):
    name: str
    interface: Optional[str] = None
    local_gateway: Optional[str] = None
    remote_gateway: Optional[str] = None
    address_family: str = "ipv4"
    spi: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    authentication_algorithm: Optional[str] = None
    has_encryption_key: bool = False
    has_authentication_key: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGFirewallSniffer(BaseModel):
    id: int
    uuid: Optional[str] = None
    logtraffic: Optional[str] = None
    ipv6: Optional[str] = None
    non_ip: Optional[str] = None
    application_list_status: Optional[str] = None
    application_list: Optional[str] = None
    ips_sensor_status: Optional[str] = None
    ips_sensor: Optional[str] = None
    av_profile_status: Optional[str] = None
    av_profile: Optional[str] = None
    webfilter_profile_status: Optional[str] = None
    webfilter_profile: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAuthenticationScheme(BaseModel):
    name: str
    method: Optional[str] = None
    user_database: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAuthenticationRule(BaseModel):
    name: str
    srcintf: List[str] = Field(default_factory=list)
    srcaddr: List[str] = Field(default_factory=list)
    active_auth_method: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGConfig(BaseModel):
    """Root model for a parsed FortiGate configuration."""

    source_version: Optional[str] = None
    source_build: Optional[str] = None
    execution_contexts: List[FGExecutionContext] = Field(default_factory=list)

    system_global: Optional[FGSystemGlobal] = None
    dns: Optional[FGDns] = None

    system_zones: List[FGSystemZone] = Field(default_factory=list)
    interfaces: List[FGInterface] = Field(default_factory=list)

    addresses: List[FGAddress] = Field(default_factory=list)
    address_groups: List[FGAddressGroup] = Field(default_factory=list)
    wildcard_fqdns: List[FGWildcardFQDN] = Field(default_factory=list)

    service_categories: List[FGServiceCategory] = Field(default_factory=list)
    services: List[FGService] = Field(default_factory=list)
    service_groups: List[FGServiceGroup] = Field(default_factory=list)

    schedules: List[FGSchedule] = Field(default_factory=list)
    schedule_groups: List[FGScheduleGroup] = Field(default_factory=list)
    traffic_shapers: List[FGTrafficShaper] = Field(default_factory=list)
    proxy_addresses: List[FGProxyAddress] = Field(default_factory=list)
    web_proxy_global: Optional[FGWebProxyGlobal] = None

    ip_pools: List[FGIPPool] = Field(default_factory=list)
    ip_pools6: List[FGIPPool6] = Field(default_factory=list)

    vips: List[FGVIP] = Field(default_factory=list)
    vips6: List[FGVIP6] = Field(default_factory=list)
    vip_groups: List[FGVIPGroup] = Field(default_factory=list)
    vip_groups6: List[FGVIPGroup6] = Field(default_factory=list)

    policies: List[FGPolicy] = Field(default_factory=list)
    central_snat_rules: List[FGCentralSNATRule] = Field(default_factory=list)
    security_policies: List[FGSourceOnlyRule] = Field(default_factory=list)
    policy_routes: List[FGSourceOnlyRule] = Field(default_factory=list)
    local_in_policies: List[FGSourceOnlyRule] = Field(default_factory=list)
    proxy_policies: List[FGSourceOnlyRule] = Field(default_factory=list)
    shaping_policies: List[FGSourceOnlyRule] = Field(default_factory=list)
    dhcp6_servers: List[FGSourceOnlyRule] = Field(default_factory=list)
    source_only_rules: List[FGSourceOnlyRule] = Field(default_factory=list)
    custom_internet_services: List[FGSourceOnlyRule] = Field(default_factory=list)
    custom_internet_service_groups: List[FGSourceOnlyRule] = Field(default_factory=list)

    ips_sensors: List[FGIPSSensor] = Field(default_factory=list)

    phase1_interfaces: List[FGPhase1Interface] = Field(
        default_factory=list
    )
    phase2_interfaces: List[FGPhase2Interface] = Field(
        default_factory=list
    )

    certificates: List[FGCertificate] = Field(default_factory=list)
    ssh_keys: List[FGSSHKey] = Field(default_factory=list)

    static_routes: List[FGStaticRoute] = Field(default_factory=list)

    sdwans: List[FGSDWan] = Field(default_factory=list)

    internet_services: List[FGInternetService] = Field(
        default_factory=list
    )
    internet_service_definitions: List[FGInternetServiceDefinition] = Field(
        default_factory=list
    )

    fctems_connectors: List[FGFCTEMS] = Field(
        default_factory=list
    )

    session_helpers: List[FGSessionHelper] = Field(
        default_factory=list
    )

    session_ttl_overrides: List[FGSessionTTLOverride] = Field(
        default_factory=list
    )
    session_ttl_settings: Optional[FGSessionTTLSettings] = None

    dhcp_servers: List[FGDHCPServer] = Field(
        default_factory=list
    )
    user_ldap_servers: List[FGUserLDAP] = Field(default_factory=list)
    fsso_servers: List[FGFSSOServer] = Field(default_factory=list)
    ad_groups: List[FGADGroup] = Field(default_factory=list)
    user_saml_servers: List[FGUserSAML] = Field(default_factory=list)
    local_users: List[FGLocalUser] = Field(default_factory=list)
    user_groups: List[FGUserGroup] = Field(default_factory=list)
    user_authentication_settings: Optional[FGUserAuthenticationSettings] = None
    user_quarantine: Optional[FGUserQuarantine] = None
    administrators: List[FGAdministrator] = Field(default_factory=list)
    admin_profiles: List[FGAdminProfile] = Field(default_factory=list)
    fortitokens: List[FGFortiToken] = Field(default_factory=list)
    ssl_vpn_portals: List[FGSSLVPNPortal] = Field(default_factory=list)
    ssl_vpn_host_check_software: List[FGSSLVPNHostCheckSoftware] = Field(
        default_factory=list
    )
    ssl_vpn_settings: Optional[FGSSLVPNSettings] = None
    dos_policies: List[FGDoSPolicy] = Field(default_factory=list)
    firewall_sniffers: List[FGFirewallSniffer] = Field(default_factory=list)
    authentication_schemes: List[FGAuthenticationScheme] = Field(default_factory=list)
    authentication_rules: List[FGAuthenticationRule] = Field(default_factory=list)
    structured_source_objects: List[FGStructuredSourceObject] = Field(default_factory=list)

    # Typed FortiGate parents whose nested/source-specific semantics remain
    # extraction-only.  Their recursive counterparts remain in
    # structured_source_objects and source inventory.
    network_service_dynamics: List[FGNetworkServiceDynamic] = Field(default_factory=list)
    sdn_connectors: List[FGSDNConnector] = Field(default_factory=list)
    radius_servers: List[FGUserRADIUS] = Field(default_factory=list)
    tacacs_servers: List[FGUserTACACS] = Field(default_factory=list)
    link_monitors: List[FGLinkMonitor] = Field(default_factory=list)
    topology_objects: List[FGTopologyObject] = Field(default_factory=list)
    access_proxies: List[FGAccessProxy] = Field(default_factory=list)
    ems_overrides: List[FGEMSOverride] = Field(default_factory=list)
    ssl_vpn_realms: List[FGSSLVPNRealm] = Field(default_factory=list)
    ssl_vpn_bookmarks: List[FGSSLVPNBookmark] = Field(default_factory=list)
    manualkey_interfaces: List[FGManualKeyInterface] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_sdwan_field(cls, value: Any) -> Any:
        """Accept the pre-VDOM single-SD-WAN field when constructing FGConfig."""
        if not isinstance(value, dict) or "sdwan" not in value:
            return value
        migrated = dict(value)
        legacy_sdwan = migrated.pop("sdwan")
        if "sdwans" not in migrated and legacy_sdwan is not None:
            migrated["sdwans"] = [legacy_sdwan]
        return migrated

    @property
    def sdwan(self) -> Optional[FGSDWan]:
        """Backward-compatible access for unambiguous single-SD-WAN configs."""
        return self.sdwans[0] if len(self.sdwans) == 1 else None

    @property
    def network_services_dynamic(self) -> List[FGNetworkServiceDynamic]:
        return self.network_service_dynamics

    @property
    def user_radius(self) -> List[FGUserRADIUS]:
        return self.radius_servers

    @property
    def user_tacacs(self) -> List[FGUserTACACS]:
        return self.tacacs_servers
