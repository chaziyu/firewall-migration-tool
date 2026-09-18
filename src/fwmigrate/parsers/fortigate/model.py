from datetime import datetime
from ipaddress import ip_address
from typing import Any, Dict, List, Literal, Optional, Set, Union
from pydantic import BaseModel, ConfigDict, Field, SerializeAsAny, field_validator, model_validator

from fwmigrate.parsers.fortigate.source_tree import FGSourceNode


SYSTEM_GLOBAL_SESSION_TIMER_FIELDS = {
    "tcp_halfclose_timer",
    "tcp_halfopen_timer",
    "tcp_rst_timer",
    "tcp_timewait_timer",
    "udp_idle_timer",
}

SESSION_TTL_OVERRIDE_INT_FIELDS = {
    "protocol",
    "start_port",
    "end_port",
}


def _preserve_malformed_int_fields(value: Any, fields: Set[str]) -> Any:
    """Normalize numeric source fields without repairing malformed input.

    Invalid values remain available in ``extra_settings`` under an
    ``unparsed_<field>`` key so extraction remains zero-silent-loss while the
    typed field is left unresolved.
    """
    if not isinstance(value, dict):
        return value

    normalized = dict(value)
    extra_settings = dict(normalized.get("extra_settings") or {})
    for field in fields:
        if field not in normalized or normalized[field] is None:
            continue

        raw_value = normalized[field]
        if isinstance(raw_value, bool):
            extra_settings[f"unparsed_{field}"] = raw_value
            normalized[field] = None
            continue

        try:
            normalized[field] = int(raw_value)
        except (TypeError, ValueError):
            extra_settings[f"unparsed_{field}"] = raw_value
            normalized[field] = None

    normalized["extra_settings"] = extra_settings
    return normalized


def _preserve_malformed_int_lists(value: Any, fields: Set[str]) -> Any:
    if not isinstance(value, dict):
        return value
    normalized = dict(value)
    extra_settings = dict(normalized.get("extra_settings") or {})
    for field in fields:
        raw = normalized.get(field)
        if raw is None:
            continue
        values = raw if isinstance(raw, list) else [raw]
        parsed, unparsed = [], []
        for item in values:
            if isinstance(item, bool):
                unparsed.append(item)
                continue
            try:
                parsed.append(int(item))
            except (TypeError, ValueError):
                unparsed.append(item)
        normalized[field] = parsed
        if unparsed:
            extra_settings[f"unparsed_{field}"] = unparsed
    normalized["extra_settings"] = extra_settings
    return normalized


FORTIOS_VIP_GROUP_COLOR_MIN = 0
FORTIOS_VIP_GROUP_COLOR_MAX = 32
FORTIOS_VIP_GROUP_NAME_MAX_LENGTH = 79
FORTIOS_VIP_GROUP_MEMBER_MAX_LENGTH = 79
FORTIOS_VIP_GROUP_COMMENT_MAX_LENGTH = 255
FORTIOS_VIP_GROUP_INTERFACE_MAX_LENGTH = 35


def _validate_vip_group_source_constraints(
    value: Any,
    *,
    validate_interface: bool,
) -> Any:
    normalized = _preserve_malformed_int_fields(value, {"color"})
    if not isinstance(normalized, dict):
        return normalized

    normalized = dict(normalized)
    extra_settings = dict(normalized.get("extra_settings") or {})
    existing_invalid_fields = extra_settings.get("invalid_fields")
    if isinstance(existing_invalid_fields, dict):
        invalid_fields = dict(existing_invalid_fields)
    elif existing_invalid_fields is None:
        invalid_fields = {}
    else:
        invalid_fields = {"_existing": existing_invalid_fields}

    raw_color = value.get("color")
    parsed_color = normalized.get("color")
    if (
        raw_color is not None
        and (
            parsed_color is None
            or not FORTIOS_VIP_GROUP_COLOR_MIN <= parsed_color <= FORTIOS_VIP_GROUP_COLOR_MAX
        )
    ):
        invalid_fields["color"] = raw_color

    for field, maximum in (
        ("name", FORTIOS_VIP_GROUP_NAME_MAX_LENGTH),
        ("comments", FORTIOS_VIP_GROUP_COMMENT_MAX_LENGTH),
    ):
        raw_value = value.get(field)
        if isinstance(raw_value, str) and len(raw_value) > maximum:
            invalid_fields[field] = raw_value

    members = value.get("member")
    if isinstance(members, list):
        invalid_members = [
            member for member in members
            if isinstance(member, str) and len(member) > FORTIOS_VIP_GROUP_MEMBER_MAX_LENGTH
        ]
        if invalid_members:
            invalid_fields["member"] = invalid_members

    raw_interface = value.get("interface")
    if (
        validate_interface
        and isinstance(raw_interface, str)
        and len(raw_interface) > FORTIOS_VIP_GROUP_INTERFACE_MAX_LENGTH
    ):
        invalid_fields["interface"] = raw_interface

    if invalid_fields or existing_invalid_fields is not None:
        extra_settings["invalid_fields"] = invalid_fields
    normalized["extra_settings"] = extra_settings
    return normalized


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
    detectprotocol: List[str] = Field(default_factory=list)
    detectserver: Optional[str] = None
    gwdetect: Optional[str] = None
    ha_priority: Optional[int] = None
    ping_serv: Optional[str] = None
    ping_serv_status: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_ping_serv_status(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(value, {"ping_serv_status"})

class FGInterfaceIPv6ExtraAddress(BaseModel):
    source_address: str
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGIPv6PrefixAdvertisement(BaseModel):
    prefix: str
    autonomous_flag: Optional[str] = None
    dnssl: List[str] = Field(default_factory=list)
    onlink_flag: Optional[str] = None
    preferred_life_time: Optional[int] = None
    rdnss: List[str] = Field(default_factory=list)
    valid_life_time: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGIPv6DelegatedPrefixAdvertisement(BaseModel):
    prefix_id: str
    autonomous_flag: Optional[str] = None
    delegated_prefix_iaid: Optional[int] = None
    onlink_flag: Optional[str] = None
    rdnss: List[str] = Field(default_factory=list)
    rdnss_service: Optional[str] = None
    subnet: Optional[str] = None
    upstream_interface: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGDHCPv6IAPD(BaseModel):
    source_iaid: str
    iaid: Optional[int] = None
    prefix_hint: Optional[str] = None
    prefix_hint_plt: Optional[int] = None
    prefix_hint_vlt: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGInterfaceVRRP6(BaseModel):
    source_vrid: str
    vrid: Optional[int] = None
    accept_mode: Optional[str] = None
    adv_interval: Optional[int] = None
    ignore_default_route: Optional[str] = None
    preempt: Optional[str] = None
    priority: Optional[int] = None
    start_time: Optional[int] = None
    status: Optional[str] = None
    vrdst6: Optional[str] = None
    vrdst6_priority: Optional[int] = None
    vrgrp: Optional[int] = None
    vrip6: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGInterfaceClientOption(BaseModel):
    source_id: str
    id: Optional[int] = None
    code: Optional[int] = None
    ip: List[str] = Field(default_factory=list)
    type: Optional[str] = None
    value: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGInterfaceDHCPSnoopingServer(BaseModel):
    name: str
    server_ip: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGInterfaceTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGInterfaceVRRPProxyARP(BaseModel):
    source_id: str
    id: Optional[int] = None
    ip: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGInterfaceVRRP(BaseModel):
    source_vrid: str
    vrid: Optional[int] = None
    accept_mode: Optional[str] = None
    adv_interval: Optional[int] = None
    ignore_default_route: Optional[str] = None
    preempt: Optional[str] = None
    priority: Optional[int] = None
    start_time: Optional[int] = None
    status: Optional[str] = None
    version: Optional[int] = None
    vrdst: Optional[str] = None
    vrdst_priority: Optional[int] = None
    vrgrp: Optional[int] = None
    vrip: Optional[str] = None
    proxy_arp: List[FGInterfaceVRRPProxyARP] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGInterfaceEgressQueues(BaseModel):
    cos0: Optional[str] = None
    cos1: Optional[str] = None
    cos2: Optional[str] = None
    cos3: Optional[str] = None
    cos4: Optional[str] = None
    cos5: Optional[str] = None
    cos6: Optional[str] = None
    cos7: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGL2TPClientSettings(BaseModel):
    user: Optional[str] = None
    peer_host: Optional[str] = None
    status: Optional[str] = None
    mtu: Optional[int] = None
    has_password: bool = False
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

    client_options: List[FGInterfaceClientOption] = Field(default_factory=list)
    dhcp_snooping_server_list: List[FGInterfaceDHCPSnoopingServer] = Field(default_factory=list)
    tagging: List[FGInterfaceTaggingEntry] = Field(default_factory=list)
    vrrp: List[FGInterfaceVRRP] = Field(default_factory=list)
    egress_queues: Optional[FGInterfaceEgressQueues] = None
    l2tp_client_settings: Optional[FGL2TPClientSettings] = None

    allowaccess: List[str] = Field(default_factory=list)
    detectprotocol: List[str] = Field(default_factory=list)
    detectserver: Optional[str] = None
    ping_serv_status: Optional[int] = None
    defaultgw: Optional[str] = None
    dhcp_client_identifier: Optional[str] = None
    dhcp_broadcast_flag: Optional[str] = None
    dhcp_classless_route_addition: Optional[str] = None
    dhcp_relay_agent_option: Optional[str] = None
    arpforward: Optional[str] = None
    broadcast_forward: Optional[str] = None
    vlanforward: Optional[str] = None
    trunk: Optional[str] = None
    bfd: Optional[str] = None
    bfd_desired_min_tx: Optional[int] = None
    bfd_detect_mult: Optional[int] = None
    bfd_required_min_rx: Optional[int] = None
    bandwidth_measure_time: Optional[int] = None
    snmp_index: Optional[int] = None
    vrrp_virtual_mac: Optional[str] = None
    weight: Optional[int] = None

    # Common FortiOS IPv6 interface settings. Complex IPv6 behavior remains
    # in ipv6_source_settings and the recursive nested source tree below.
    ip6_address: Optional[str] = None
    ip6_allowaccess: List[str] = Field(default_factory=list)
    ip6_mode: Optional[str] = None
    ip6_send_adv: Optional[str] = None
    ip6_manage_flag: Optional[str] = None
    ip6_other_flag: Optional[str] = None
    ipv6_autoconf: Optional[str] = None
    cli_conn6_status: Optional[int] = None
    dhcp6_client_options: List[str] = Field(default_factory=list)
    dhcp6_information_request: Optional[str] = None
    dhcp6_prefix_delegation: Optional[str] = None
    dhcp6_relay_interface_id: Optional[str] = None
    dhcp6_relay_ip: List[str] = Field(default_factory=list)
    dhcp6_relay_service: Optional[str] = None
    dhcp6_relay_source_interface: Optional[str] = None
    dhcp6_relay_source_ip: Optional[str] = None
    dhcp6_relay_type: Optional[str] = None
    icmp6_send_redirect: Optional[str] = None
    interface_identifier: Optional[str] = None
    ip6_default_life: Optional[int] = None
    ip6_delegated_prefix_iaid: Optional[int] = None
    ip6_dns_server_override: Optional[str] = None
    ip6_hop_limit: Optional[int] = None
    ip6_link_mtu: Optional[int] = None
    ip6_max_interval: Optional[int] = None
    ip6_min_interval: Optional[int] = None
    ip6_prefix_mode: Optional[str] = None
    ip6_reachable_time: Optional[int] = None
    ip6_retrans_time: Optional[int] = None
    ip6_subnet: Optional[str] = None
    ip6_upstream_interface: Optional[str] = None
    ipv6_extra_addresses: List[FGInterfaceIPv6ExtraAddress] = Field(default_factory=list)
    ipv6_prefix_advertisements: List[FGIPv6PrefixAdvertisement] = Field(default_factory=list)
    ipv6_delegated_prefix_advertisements: List[FGIPv6DelegatedPrefixAdvertisement] = Field(default_factory=list)
    dhcp6_iapd: List[FGDHCPv6IAPD] = Field(default_factory=list)
    vrrp6: List[FGInterfaceVRRP6] = Field(default_factory=list)

    # FortiOS exposes these interface settings as ordered multi-value CLI
    # fields.  They remain source-oriented fields; the transformer retains
    # them in IRInterface.source_attributes for extraction/reporting.
    fail_alert_interfaces: List[str] = Field(default_factory=list)
    fail_detect_option: List[str] = Field(default_factory=list)
    dns_server_protocol: List[str] = Field(default_factory=list)
    security_groups: List[str] = Field(default_factory=list)

    mtu_override: Optional[str] = None
    mtu: Optional[int] = None
    tcp_mss: Optional[int] = None
    estimated_upstream_bandwidth: Optional[int] = None
    estimated_downstream_bandwidth: Optional[int] = None
    link_up_delay: Optional[int] = None
    link_down_delay: Optional[int] = None
    preserve_session_route: Optional[str] = None
    stp: Optional[str] = None
    stp_ha_secondary: Optional[str] = None
    broadcast_forticlient_discovery: Optional[str] = None
    drop_overlapped_fragment: Optional[str] = None
    drop_fragment: Optional[str] = None
    explicit_web_proxy: Optional[str] = None

    type: Optional[str] = None
    # Aggregate and redundant interfaces retain their ordered FortiOS member
    # relationships as typed source topology.
    members: List[str] = Field(default_factory=list)
    lacp_mode: str = "active"
    lacp_ha_secondary: str = "enable"
    system_id_type: str = "auto"
    system_id: Optional[str] = None
    lacp_speed: str = "slow"
    min_links: int = 1
    min_links_down: str = "operational"
    algorithm: str = "L4"
    aggregate_type: str = "physical"
    priority_override: str = "enable"
    aggregate_parent: Optional[str] = None
    redundant_interface_parent: Optional[str] = None
    role: str = "undefined"
    # FortiOS interface dedication/purpose.
    dedicated_to: Optional[str] = None
    alias: Optional[str] = None
    description: Optional[str] = None

    vlanid: Optional[int] = None
    interface: Optional[str] = None
    vrf: Optional[int] = None

    status: str = "up"
    mode: str = "static"
    username: Optional[str] = None
    # FortiOS interface DNS server override setting.
    # Keep exact source enable/disable semantics.
    dns_server_override: Optional[str] = None
    has_pppoe_password: Optional[bool] = None
    pppoe_password_format: Optional[str] = None

    # FortiOS physical interface speed option. Preserve the exact source token.
    speed: Optional[str] = None

    # FortiOS interface media/SFP type. Preserve the exact source token.
    mediatype: Optional[str] = None

    # FortiOS bandwidth-monitoring toggle. Preserve the exact source token.
    monitor_bandwidth: Optional[str] = None

    # FortiOS passive device identification setting.
    device_identification: Optional[str] = None

    # FortiOS SAML server referenced for IKE authentication.
    ike_saml_server: Optional[str] = None

    # FortiOS source-IP validation/check setting.
    src_check: Optional[str] = None

    # Additional FortiOS 7.4.6 interface fields
    distance: Optional[int] = None
    priority: Optional[int] = None
    gwdetect: Optional[str] = None
    ha_priority: Optional[int] = None
    ping_serv: Optional[str] = None
    dhcp_renew_time: Optional[int] = None
    dhcp_relay_service: Optional[str] = None
    dhcp_relay_ip: List[str] = Field(default_factory=list)
    dhcp_relay_type: Optional[str] = None
    dhcp_relay_link_selection: Optional[str] = None
    dhcp_relay_interface_select_method: Optional[str] = None
    dhcp_relay_interface: Optional[str] = None
    dhcp_snooping: Optional[str] = None
    dhcp_snooping_option82: Optional[str] = None
    dhcp_snooping_trust: Optional[str] = None
    vlan_protocol: Optional[str] = None
    switch: Optional[str] = None
    lacp_select_timeout: Optional[int] = None
    bandwidth: Optional[int] = None
    fec: Optional[str] = None
    flowcontrol: Optional[str] = None
    fortilink: Optional[str] = None
    fortilink_neighbor_detect: Optional[str] = None
    auto_auth_extension: Optional[str] = None
    security_mode: Optional[str] = None
    security_mac_auth: Optional[str] = None
    security_exempt_list: Optional[str] = None
    security_redirect_url: Optional[str] = None
    management_ip: Optional[str] = None
    ip_managed_by_fortiipam: Optional[str] = None

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
    source_explicit_fields: Set[str] = Field(default_factory=set)

class FGSystemZoneTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSystemZone(FGContextualModel):
    name: str
    interface: List[str] = Field(default_factory=list)
    tag: Optional[str] = None
    description: Optional[str] = None
    intrazone: Optional[str] = None
    tagging: List[FGSystemZoneTaggingEntry] = Field(default_factory=list)
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGAddressListEntry(BaseModel):
    name: str
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAddressTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAddress(FGContextualModel):
    # Keep normalized nested source entries available to legacy callers while
    # scalar vendor-only settings remain in extra_settings.
    model_config = ConfigDict(extra="allow")
    name: str
    uuid: Optional[str] = None
    type: Optional[str] = None  # ipmask, fqdn, iprange, dynamic
    subnet: Optional[str] = None  # e.g. "192.168.1.0 255.255.255.0"
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    fqdn: Optional[str] = None
    wildcard: Optional[str] = None
    wildcard_fqdn: Optional[str] = None
    associated_interface: Optional[str] = None
    comment: Optional[str] = None
    # Compatibility fields retained while IPv6 and multicast sections share this model.
    ip6: Optional[str] = None
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


class FGService(FGContextualModel):
    name: str
    protocol: Optional[str] = None
    session_ttl: Optional[Union[int, Literal["never"]]] = None
    tcp_halfclose_timer: Optional[int] = None
    tcp_halfopen_timer: Optional[int] = None
    tcp_rst_timer: Optional[int] = None
    tcp_timewait_timer: Optional[int] = None
    udp_idle_timer: Optional[int] = None
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

    @model_validator(mode="before")
    @classmethod
    def _normalize_session_timer_fields(cls, value: Any) -> Any:
        normalized = _preserve_malformed_int_fields(
            value,
            SYSTEM_GLOBAL_SESSION_TIMER_FIELDS,
        )
        if not isinstance(normalized, dict):
            return normalized

        raw_session_ttl = normalized.get("session_ttl")
        if raw_session_ttl is None:
            return normalized
        if isinstance(raw_session_ttl, str) and raw_session_ttl.lower() == "never":
            normalized = dict(normalized)
            normalized["session_ttl"] = "never"
            extra_settings = dict(normalized.get("extra_settings") or {})
            extra_settings.pop("unparsed_session_ttl", None)
            normalized["extra_settings"] = extra_settings
            return normalized
        return _preserve_malformed_int_fields(normalized, {"session_ttl"})

class FGServiceGroup(FGContextualModel):
    name: str
    # Raw FortiOS member names; dependency resolution happens downstream.
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


class FGIPPool(FGContextualModel):
    name: str
    source_explicit_fields: Set[str] = Field(default_factory=set)

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

    @model_validator(mode="before")
    @classmethod
    def _normalize_numeric_source_fields(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(
            value,
            {
                "startport",
                "endport",
                "block_size",
                "num_blocks_per_user",
                "pba_timeout",
                "pba_interim_log",
                "port_per_user",
                "client_prefix_length",
                "tcp_session_quota",
                "udp_session_quota",
                "icmp_session_quota",
                "cgn_block_size",
                "cgn_client_ipv6shift",
                "cgn_port_start",
                "cgn_port_end",
                "utilization_alarm_clear",
                "utilization_alarm_raise",
            },
        )


class FGScheduleGroup(FGContextualModel):
    name: str
    member: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    color: Optional[int] = None
    fabric_object: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGIPPool6(FGContextualModel):
    name: str
    source_explicit_fields: Set[str] = Field(default_factory=set)
    startip: Optional[str] = None
    endip: Optional[str] = None
    nat46: Optional[str] = None
    add_nat46_route: Optional[str] = None
    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGIPPoolGroup(FGContextualModel):
    """Typed FortiOS ``config firewall ippool_grp`` source object."""

    name: str
    member: List[str] = Field(default_factory=list)
    source_explicit_fields: Set[str] = Field(default_factory=set)
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

    @model_validator(mode="before")
    @classmethod
    def _normalize_numeric_source_fields(cls, value: Any) -> Any:
        normalized = _preserve_malformed_int_fields(
            value, {"port", "weight", "holddown_interval", "max_connections"}
        )
        if not isinstance(normalized, dict):
            return normalized

        normalized = dict(normalized)
        raw_value = normalized.get("translate_host")
        if raw_value is None:
            return normalized
        if isinstance(raw_value, str) and raw_value.lower() in {"enable", "disable"}:
            normalized["translate_host"] = raw_value.lower()
            return normalized

        extra_settings = dict(normalized.get("extra_settings") or {})
        extra_settings["unparsed_translate_host"] = raw_value
        normalized["translate_host"] = None
        normalized["extra_settings"] = extra_settings
        return normalized


class FGVIPGSLBPublicIP(BaseModel):
    index: Optional[int] = None
    ip: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_index(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(value, {"index"})


class FGVIPQUICSettings(BaseModel):
    max_idle_timeout: Optional[int] = None
    max_udp_payload_size: Optional[int] = None
    active_connection_id_limit: Optional[int] = None
    ack_delay_exponent: Optional[int] = None
    max_ack_delay: Optional[int] = None
    max_datagram_frame_size: Optional[int] = None
    active_migration: Optional[str] = None
    grease_quic_bit: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_numeric_fields(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(
            value,
            {
                "max_idle_timeout",
                "max_udp_payload_size",
                "active_connection_id_limit",
                "ack_delay_exponent",
                "max_ack_delay",
                "max_datagram_frame_size",
            },
        )


class FGVIPSSLCipherSuite(BaseModel):
    priority: Optional[int] = None
    cipher: Optional[str] = None
    versions: List[str] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_priority(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(value, {"priority"})


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
    src_vip_filter: Optional[str] = None
    srcintf_filter: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)

    gratuitous_arp_interval: Optional[int] = None

    ldb_method: Optional[str] = None
    server_type: Optional[str] = None
    persistence: Optional[str] = None
    http_redirect: Optional[str] = None
    h2_support: Optional[str] = None
    h3_support: Optional[str] = None
    http_multiplex: Optional[str] = None
    ssl_mode: Optional[str] = None
    ssl_certificate: Optional[str] = None
    ssl_algorithm: Optional[str] = None
    ssl_min_version: Optional[str] = None
    ssl_max_version: Optional[str] = None
    ssl_server_algorithm: Optional[str] = None
    ssl_server_min_version: Optional[str] = None
    ssl_server_max_version: Optional[str] = None
    ssl_pfs: Optional[str] = None
    gslb_domain_name: Optional[str] = None
    gslb_hostname: Optional[str] = None
    monitor: List[str] = Field(default_factory=list)
    max_embryonic_connections: Optional[int] = None
    realservers: List[FGVIPRealServer] = Field(default_factory=list)
    gslb_public_ips: List[FGVIPGSLBPublicIP] = Field(default_factory=list)
    quic: Optional[FGVIPQUICSettings] = None
    ssl_cipher_suites: List[FGVIPSSLCipherSuite] = Field(default_factory=list)
    ssl_server_cipher_suites: List[FGVIPSSLCipherSuite] = Field(default_factory=list)

    comment: Optional[str] = None
    color: Optional[int] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_numeric_source_fields(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(
            value, {"id", "gratuitous_arp_interval", "max_embryonic_connections", "color"}
        )

class FGVIPGroup(FGContextualModel):
    name: str
    uuid: Optional[str] = None
    interface: Optional[str] = None
    color: Optional[int] = None
    member: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    comment: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_numeric_source_fields(cls, value: Any) -> Any:
        return _validate_vip_group_source_constraints(value, validate_interface=True)


class FGVIP6(FGContextualModel):
    name: str
    id: Optional[int] = None
    uuid: Optional[str] = None
    type: str = "static-nat"
    status: str = "enable"
    extip: Optional[str] = None
    extintf: Optional[str] = None
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
    http_redirect: Optional[str] = None
    max_embryonic_connections: Optional[int] = None
    ldb_method: Optional[str] = None
    server_type: Optional[str] = None
    persistence: Optional[str] = None
    h2_support: Optional[str] = None
    h3_support: Optional[str] = None
    http_multiplex: Optional[str] = None
    ssl_mode: Optional[str] = None
    ssl_certificate: Optional[str] = None
    ssl_algorithm: Optional[str] = None
    ssl_min_version: Optional[str] = None
    ssl_max_version: Optional[str] = None
    ssl_server_algorithm: Optional[str] = None
    ssl_server_min_version: Optional[str] = None
    ssl_server_max_version: Optional[str] = None
    ssl_pfs: Optional[str] = None
    gslb_domain_name: Optional[str] = None
    gslb_hostname: Optional[str] = None
    monitor: List[str] = Field(default_factory=list)
    src_filter: List[str] = Field(default_factory=list)
    realservers: List[FGVIPRealServer] = Field(default_factory=list)
    gslb_public_ips: List[FGVIPGSLBPublicIP] = Field(default_factory=list)
    quic: Optional[FGVIPQUICSettings] = None
    ssl_cipher_suites: List[FGVIPSSLCipherSuite] = Field(default_factory=list)
    ssl_server_cipher_suites: List[FGVIPSSLCipherSuite] = Field(default_factory=list)
    comment: Optional[str] = None
    color: Optional[int] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_numeric_source_fields(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(
            value,
            {"id", "color", "max_embryonic_connections"},
        )


class FGVIPGroup6(FGContextualModel):
    name: str
    uuid: Optional[str] = None
    color: Optional[int] = None
    member: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_numeric_source_fields(cls, value: Any) -> Any:
        return _validate_vip_group_source_constraints(value, validate_interface=False)

class FGPolicy(FGContextualModel):
    # Portable policy intent.  These fields are the source-side values that
    # can be normalized into the vendor-neutral policy match/action model.
    id: int
    ngfw_mode: Optional[str] = None
    address_family: str = "dual-stack"
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
    policy_expiry: Optional[str] = None
    policy_expiry_date: Optional[str] = None
    policy_expiry_date_utc: Optional[str] = None
    schedule_timeout: Optional[str] = None
    reputation_direction: Optional[str] = None
    reputation_direction6: Optional[str] = None
    reputation_minimum6: Optional[int] = None
    nat46: Optional[str] = None
    nat64: Optional[str] = None
    natinbound: Optional[str] = None
    natoutbound: Optional[str] = None
    natip: Optional[str] = None
    pcp_inbound: Optional[str] = None
    pcp_outbound: Optional[str] = None
    pcp_poolname: List[str] = Field(default_factory=list)
    permit_any_host: Optional[str] = None
    permit_stun_host: Optional[str] = None
    rtp_nat: Optional[str] = None
    rtp_addr: List[str] = Field(default_factory=list)
    utm_status: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    av_profile: Optional[str] = None
    webfilter_profile: Optional[str] = None
    casb_profile: Optional[str] = None
    cifs_filter_profile: Optional[str] = None
    diameter_filter_profile: Optional[str] = None
    dlp_sensor: Optional[str] = None
    dlp_profile: Optional[str] = None
    dnsfilter_profile: Optional[str] = None
    emailfilter_profile: Optional[str] = None
    file_filter_profile: Optional[str] = None
    icap_profile: Optional[str] = None
    ips_sensor: Optional[str] = None
    ips_voip_filter: Optional[str] = None
    application_list: Optional[str] = None
    profile_type: Optional[str] = None
    profile_group: Optional[str] = None
    profile_protocol_options: Optional[str] = None
    sctp_filter_profile: Optional[str] = None
    ssh_filter_profile: Optional[str] = None
    videofilter_profile: Optional[str] = None
    virtual_patch_profile: Optional[str] = None
    voip_profile: Optional[str] = None
    waf_profile: Optional[str] = None
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
    timeout_send_rst: Optional[str] = None
    auto_asic_offload: Optional[str] = None
    np_acceleration: Optional[str] = None
    port_preserve: Optional[str] = None
    ztna_status: Optional[str] = None
    ztna_device_ownership: Optional[str] = None
    ztna_ems_tag: List[str] = Field(default_factory=list)
    ztna_ems_tag_secondary: List[str] = Field(default_factory=list)
    ztna_geo_tag: List[str] = Field(default_factory=list)
    ztna_policy_redirect: Optional[str] = None
    ztna_tags_match_logic: Optional[str] = None
    vpntunnel: Optional[str] = None
    identity_based_route: Optional[str] = None
    central_nat: Optional[str] = None
    fsso_groups: List[str] = Field(default_factory=list)
    ntlm_enabled_browsers: List[str] = Field(default_factory=list)
    sgt: List[str] = Field(default_factory=list)
    src_vendor_mac: List[str] = Field(default_factory=list)
    application: List[int] = Field(default_factory=list)
    app_category: List[int] = Field(default_factory=list)
    app_group: List[str] = Field(default_factory=list)
    url_category: List[str] = Field(default_factory=list)
    tcp_mss_sender: Optional[int] = None
    tcp_mss_receiver: Optional[int] = None
    session_ttl: Optional[int] = None
    vlan_cos_fwd: Optional[int] = None
    vlan_cos_rev: Optional[int] = None
    reputation_minimum: Optional[int] = None
    diffserv_forward: Optional[str] = None
    diffserv_reverse: Optional[str] = None
    diffservcode_forward: Optional[str] = None
    diffservcode_rev: Optional[str] = None
    wccp: Optional[str] = None
    disclaimer: Optional[str] = None
    email_collect: Optional[str] = None
    auth_cert: Optional[str] = None
    auth_path: Optional[str] = None
    auth_redirect_addr: Optional[str] = None
    redirect_url: Optional[str] = None
    block_notification: Optional[str] = None
    capture_packet: Optional[str] = None
    traffic_shaper: Optional[str] = None
    traffic_shaper_reverse: Optional[str] = None
    per_ip_shaper: Optional[str] = None
    cifs_profile: Optional[str] = None
    webcache: Optional[str] = None
    webcache_https: Optional[str] = None
    webproxy_forward_server: Optional[str] = None
    webproxy_profile: Optional[str] = None
    ssh_policy_redirect: Optional[str] = None
    fsso: Optional[str] = None
    wsso: Optional[str] = None
    rsso: Optional[str] = None
    passive_wan_health_measurement: Optional[str] = None
    reputation_direction: Optional[str] = None
    send_deny_packet: Optional[str] = None
    fsso_agent_for_ntlm: Optional[str] = None
    ntlm_guest: Optional[str] = None
    radius_mac_auth_bypass: Optional[str] = None
    delay_tcp_npu_session: Optional[str] = None
    inbound: Optional[str] = None
    outbound: Optional[str] = None

    # Any recognized source setting that is not important and known enough to
    # type remains here.  The parser sanitizes these values for audit/export.
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGPhase1Common(BaseModel):
    """Shared, source-preserving Phase 1 settings for both FortiOS modes."""

    type: Optional[str] = None
    interface: Optional[str] = None
    local_gw: Optional[str] = None
    remote_gw: Optional[str] = None
    local_gw6: Optional[str] = None
    remote_gw6: Optional[str] = None
    remotegw_ddns: Optional[str] = None
    ike_version: Optional[str] = None
    mode: Optional[str] = None
    peertype: Optional[str] = None
    net_device: Optional[str] = None
    proposal: List[str] = Field(default_factory=list)
    dhgrp: List[int] = Field(default_factory=list)
    authmethod: Optional[str] = None
    authmethod_remote: Optional[str] = None
    certificate: List[str] = Field(default_factory=list)
    peerid: Optional[str] = None
    peerid_check: Optional[str] = None
    peer: Optional[str] = None
    peergrp: Optional[str] = None
    localid: Optional[str] = None
    localid_type: Optional[str] = None
    nattraversal: Optional[str] = None
    dpd: Optional[str] = None
    dpd_retrycount: Optional[int] = None
    dpd_retryinterval: Optional[int] = None
    mode_cfg: Optional[str] = None
    mode_cfg_allow_client_selector: Optional[str] = None
    assign_ip: Optional[str] = None
    assign_ip_from: Optional[str] = None
    eap: Optional[str] = None
    eap_identity: Optional[str] = None
    eap_exclude_peergrp: Optional[str] = None
    authusr: Optional[str] = None
    authusrgrp: Optional[str] = None
    ip_version: Optional[str] = None
    remote_gw_match: Optional[str] = None
    remote_gw_start_ip: Optional[str] = None
    remote_gw_subnet: Optional[str] = None
    remote_gw_country: Optional[str] = None
    remote_gw_ztna_tags: List[str] = Field(default_factory=list)
    cert_trust_store: Optional[str] = None
    cert_peer_username_strip: Optional[str] = None
    cert_peer_username_validation: Optional[str] = None
    acct_verify: Optional[str] = None
    default_gw: Optional[str] = None
    default_gw_priority: Optional[int] = None
    distance: Optional[int] = None
    priority: Optional[int] = None
    dns_suffix_search: List[str] = Field(default_factory=list)
    xauthtype: Optional[str] = None
    ipv4_start_ip: Optional[str] = None
    ipv4_end_ip: Optional[str] = None
    ipv4_netmask: Optional[str] = None
    ipv4_name: Optional[str] = None
    ipv4_dns_server1: Optional[str] = None
    ipv4_dns_server2: Optional[str] = None
    ipv4_dns_server3: Optional[str] = None
    ipv4_wins_server1: Optional[str] = None
    ipv4_wins_server2: Optional[str] = None
    ipv4_split_include: List[str] = Field(default_factory=list)
    ipv4_split_exclude: List[str] = Field(default_factory=list)
    ipv6_start_ip: Optional[str] = None
    ipv6_end_ip: Optional[str] = None
    ipv6_prefix: Optional[int] = None
    ipv6_name: Optional[str] = None
    ipv6_dns_server1: Optional[str] = None
    ipv6_dns_server2: Optional[str] = None
    ipv6_dns_server3: Optional[str] = None
    ipv6_split_include: List[str] = Field(default_factory=list)
    ipv6_split_exclude: List[str] = Field(default_factory=list)
    dns_mode: Optional[str] = None
    domain: Optional[str] = None
    backup_gateway: List[str] = Field(default_factory=list)
    banner: Optional[str] = None
    keylife: Optional[int] = None
    rekey: Optional[str] = None
    reauth: Optional[str] = None
    idle_timeout: Optional[str] = None
    idle_timeoutinterval: Optional[int] = None
    negotiate_timeout: Optional[int] = None
    keepalive: Optional[int] = None
    add_gw_route: Optional[str] = None
    add_route: Optional[str] = None
    auto_negotiate: Optional[str] = None
    client_auto_negotiate: Optional[str] = None
    client_keep_alive: Optional[str] = None
    auto_discovery_crossover: Optional[str] = None
    auto_discovery_forwarder: Optional[str] = None
    auto_discovery_offer_interval: Optional[int] = None
    auto_discovery_psk: Optional[str] = None
    auto_discovery_receiver: Optional[str] = None
    auto_discovery_sender: Optional[str] = None
    ipsec_tunnel_slot: Optional[str] = None
    cert_id_validation: Optional[str] = None
    send_cert_chain: Optional[str] = None
    digital_signature_auth: Optional[str] = None
    signature_hash_alg: List[str] = Field(default_factory=list)
    rsa_signature_format: Optional[str] = None
    rsa_signature_hash_override: Optional[str] = None
    suite_b: Optional[str] = None
    esn: Optional[str] = None
    childless_ike: Optional[str] = None
    fragmentation: Optional[str] = None
    fragmentation_mtu: Optional[int] = None
    ip_fragmentation: Optional[str] = None
    npu_offload: Optional[str] = None
    transport: Optional[str] = None
    exchange_ip_addr4: List[str] = Field(default_factory=list)
    exchange_ip_addr6: List[str] = Field(default_factory=list)
    remote_gw_end_ip: Optional[str] = None
    network_overlay: Optional[str] = None
    network_id: Optional[int] = None
    include_local_lan: Optional[str] = None
    unity_support: Optional[str] = None
    save_password: Optional[str] = None
    forticlient_enforcement: Optional[str] = None
    group_authentication: Optional[str] = None
    ppk: Optional[str] = None
    ppk_identity: Optional[str] = None
    split_include_service: List[str] = Field(default_factory=list)
    has_psk: bool = False
    has_auth_password: bool = False
    has_group_authentication_secret: bool = False
    has_ppk_secret: bool = False
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_phase1_ints(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(
            value,
            {"default_gw_priority", "distance", "priority"},
        )


class FGPhase1Interface(FGPhase1Common, FGContextualModel):
    name: str
    interface: str
    comments: Optional[str] = None
    aggregate_member: Optional[str] = None
    aggregate_weight: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_interface_phase1_ints(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(value, {"aggregate_weight"})

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
    src_subnet6: Optional[str] = None
    dst_subnet6: Optional[str] = None
    src_start_ip: Optional[str] = None
    src_end_ip: Optional[str] = None
    src_start_ip6: Optional[str] = None
    src_end_ip6: Optional[str] = None
    dst_start_ip: Optional[str] = None
    dst_end_ip: Optional[str] = None
    dst_start_ip6: Optional[str] = None
    dst_end_ip6: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_name6: List[str] = Field(default_factory=list)
    dst_name6: List[str] = Field(default_factory=list)
    protocol: Optional[int] = None
    add_route: Optional[str] = None
    auto_discovery_forwarder: Optional[str] = None
    auto_discovery_sender: Optional[str] = None
    dhcp_ipsec: Optional[str] = None
    diffserv: Optional[str] = None
    diffservcode: Optional[str] = None
    encapsulation: Optional[str] = None
    inbound_dscp_copy: Optional[str] = None
    initiator_ts_narrow: Optional[str] = None
    ipv4_df: Optional[str] = None
    l2tp: Optional[str] = None
    single_source: Optional[str] = None
    auto_negotiate: Optional[str] = None
    pfs: Optional[str] = None
    dhgrp: List[int] = Field(default_factory=list)
    keylife: Optional[int] = None
    keylife_type: Optional[str] = None
    keylifeseconds: Optional[int] = None
    keylifekbs: Optional[int] = None
    replay: Optional[str] = None
    esn: Optional[str] = None
    initiator_autoclose: Optional[int] = None
    route_overlap: Optional[str] = None
    selector_match: Optional[str] = None
    network_overlay: Optional[str] = None
    network_id: Optional[int] = None
    keepalive: Optional[str] = None
    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_selector_ints(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(
            value,
            {"protocol", "src_port", "dst_port"},
        )

class FGStaticRoute(FGContextualModel):
    id: int
    address_family: str = "ipv4"
    dst: Optional[str] = None
    dstaddr: Optional[str] = None
    gateway: Optional[str] = None
    device: Optional[str] = None
    devindex: Optional[int] = None
    preferred_source: Optional[str] = None
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

    @model_validator(mode="before")
    @classmethod
    def _apply_address_family_defaults(cls, value: Any) -> Any:
        if not isinstance(value, dict) or value.get("address_family") != "ipv6":
            return value
        if "priority" not in value:
            value = dict(value)
            value["priority"] = 1024
        return value


class FGCentralSNATRule(FGContextualModel):
    id: int
    source_order: int = 0

    uuid: Optional[str] = None
    type: str = "ipv4"
    status: str = "enable"
    srcintf: List[str] = Field(default_factory=list)
    dstintf: List[str] = Field(default_factory=list)
    orig_addr: List[str] = Field(default_factory=list)
    orig_addr6: List[str] = Field(default_factory=list)
    dst_addr: List[str] = Field(default_factory=list)
    dst_addr6: List[str] = Field(default_factory=list)
    protocol: Optional[int] = None
    orig_port: Optional[str] = None
    dst_port: Optional[str] = None
    nat: str = "enable"
    nat_ippool: List[str] = Field(default_factory=list)
    nat_ippool6: List[str] = Field(default_factory=list)
    nat_port: Optional[str] = None
    nat46: str = "disable"
    nat64: str = "disable"
    port_preserve: str = "enable"
    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_protocol(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(value, {"protocol"})


class FGIPTranslation(FGContextualModel):
    id: int
    source_order: int = 0
    type: str = "SCTP"
    startip: Optional[str] = None
    endip: Optional[str] = None
    map_startip: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGRuleSourceModel(FGContextualModel):
    """Shared shape for explicitly supported FortiGate rule families."""

    family: str
    id: Optional[int] = None
    name: Optional[str] = None
    source_order: int = 0
    status: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSecurityPolicy(FGRuleSourceModel):
    ngfw_mode: Optional[str] = None
    uuid: Optional[str] = None
    srcintf: List[str] = Field(default_factory=list)
    dstintf: List[str] = Field(default_factory=list)
    srcaddr: List[str] = Field(default_factory=list)
    dstaddr: List[str] = Field(default_factory=list)
    srcaddr6: List[str] = Field(default_factory=list)
    dstaddr6: List[str] = Field(default_factory=list)
    srcaddr_negate: Optional[str] = None
    dstaddr_negate: Optional[str] = None
    srcaddr6_negate: Optional[str] = None
    dstaddr6_negate: Optional[str] = None
    service: List[str] = Field(default_factory=list)
    service_negate: Optional[str] = None
    schedule: Optional[str] = None
    action: Optional[str] = None
    application: List[int] = Field(default_factory=list)
    app_category: List[int] = Field(default_factory=list)
    app_group: List[str] = Field(default_factory=list)
    application_list: Optional[str] = None
    av_profile: Optional[str] = None
    casb_profile: Optional[str] = None
    cifs_profile: Optional[str] = None
    diameter_filter_profile: Optional[str] = None
    dlp_profile: Optional[str] = None
    dnsfilter_profile: Optional[str] = None
    emailfilter_profile: Optional[str] = None
    file_filter_profile: Optional[str] = None
    icap_profile: Optional[str] = None
    ips_sensor: Optional[str] = None
    ips_voip_filter: Optional[str] = None
    webfilter_profile: Optional[str] = None
    videofilter_profile: Optional[str] = None
    virtual_patch_profile: Optional[str] = None
    voip_profile: Optional[str] = None
    sctp_filter_profile: Optional[str] = None
    ssh_filter_profile: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    profile_group: Optional[str] = None
    profile_protocol_options: Optional[str] = None
    profile_type: Optional[str] = None
    groups: List[str] = Field(default_factory=list)
    fsso_groups: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    internet_service: Optional[str] = None
    internet_service_custom: List[str] = Field(default_factory=list)
    internet_service_custom_group: List[str] = Field(default_factory=list)
    internet_service_group: List[str] = Field(default_factory=list)
    internet_service_name: List[str] = Field(default_factory=list)
    internet_service_negate: Optional[str] = None
    internet_service_src: Optional[str] = None
    internet_service_src_custom: List[str] = Field(default_factory=list)
    internet_service_src_custom_group: List[str] = Field(default_factory=list)
    internet_service_src_group: List[str] = Field(default_factory=list)
    internet_service_src_name: List[str] = Field(default_factory=list)
    internet_service_src_negate: Optional[str] = None
    internet_service6: Optional[str] = None
    internet_service6_custom: List[str] = Field(default_factory=list)
    internet_service6_custom_group: List[str] = Field(default_factory=list)
    internet_service6_group: List[str] = Field(default_factory=list)
    internet_service6_name: List[str] = Field(default_factory=list)
    internet_service6_negate: Optional[str] = None
    internet_service6_src: Optional[str] = None
    internet_service6_src_custom: List[str] = Field(default_factory=list)
    internet_service6_src_custom_group: List[str] = Field(default_factory=list)
    internet_service6_src_group: List[str] = Field(default_factory=list)
    internet_service6_src_name: List[str] = Field(default_factory=list)
    internet_service6_src_negate: Optional[str] = None
    url_category: List[str] = Field(default_factory=list)
    enforce_default_app_port: Optional[str] = None
    learning_mode: Optional[str] = None
    logtraffic: Optional[str] = None
    nat46: Optional[str] = None
    nat64: Optional[str] = None
    send_deny_packet: Optional[str] = None
    status: Optional[str] = None
    comments: Optional[str] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)


class FGPhase1Policy(FGPhase1Common, FGRuleSourceModel):
    comments: Optional[str] = None


class FGPhase2Policy(FGRuleSourceModel):
    phase1name: Optional[str] = None
    use_natip: Optional[str] = None
    proposal: List[str] = Field(default_factory=list)
    src_addr_type: Optional[str] = None
    dst_addr_type: Optional[str] = None
    src_name: List[str] = Field(default_factory=list)
    dst_name: List[str] = Field(default_factory=list)
    src_subnet: Optional[str] = None
    dst_subnet: Optional[str] = None
    src_subnet6: Optional[str] = None
    dst_subnet6: Optional[str] = None
    src_start_ip: Optional[str] = None
    src_end_ip: Optional[str] = None
    src_start_ip6: Optional[str] = None
    src_end_ip6: Optional[str] = None
    dst_start_ip: Optional[str] = None
    dst_end_ip: Optional[str] = None
    dst_start_ip6: Optional[str] = None
    dst_end_ip6: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_name6: List[str] = Field(default_factory=list)
    dst_name6: List[str] = Field(default_factory=list)
    protocol: Optional[int] = None
    add_route: Optional[str] = None
    auto_discovery_forwarder: Optional[str] = None
    auto_discovery_sender: Optional[str] = None
    dhcp_ipsec: Optional[str] = None
    diffserv: Optional[str] = None
    diffservcode: Optional[str] = None
    encapsulation: Optional[str] = None
    inbound_dscp_copy: Optional[str] = None
    initiator_ts_narrow: Optional[str] = None
    ipv4_df: Optional[str] = None
    l2tp: Optional[str] = None
    single_source: Optional[str] = None
    auto_negotiate: Optional[str] = None
    pfs: Optional[str] = None
    dhgrp: List[int] = Field(default_factory=list)
    keylife: Optional[int] = None
    keylife_type: Optional[str] = None
    keylifeseconds: Optional[int] = None
    keylifekbs: Optional[int] = None
    replay: Optional[str] = None
    esn: Optional[str] = None
    initiator_autoclose: Optional[int] = None
    route_overlap: Optional[str] = None
    selector_match: Optional[str] = None
    network_overlay: Optional[str] = None
    network_id: Optional[int] = None
    keepalive: Optional[str] = None
    comments: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_selector_ints(cls, value: Any) -> Any:
        return _preserve_malformed_int_fields(
            value,
            {"protocol", "src_port", "dst_port"},
        )


class FGPolicyRoute(FGContextualModel):
    """Typed FortiGate policy-route source semantics."""

    id: Optional[int] = None
    family: str
    source_order: int = 0

    action: Optional[str] = None
    status: Optional[str] = None
    comments: Optional[str] = None

    input_device: List[str] = Field(default_factory=list)
    input_device_negate: Optional[str] = None

    src: List[str] = Field(default_factory=list)
    srcaddr: List[str] = Field(default_factory=list)
    src_negate: Optional[str] = None

    dst: List[str] = Field(default_factory=list)
    dstaddr: List[str] = Field(default_factory=list)
    dst_negate: Optional[str] = None

    protocol: Optional[int] = None

    start_port: Optional[int] = None
    end_port: Optional[int] = None
    start_source_port: Optional[int] = None
    end_source_port: Optional[int] = None

    gateway: Optional[str] = None
    output_device: Optional[str] = None

    internet_service_custom: List[str] = Field(default_factory=list)
    internet_service_id: List[int] = Field(default_factory=list)

    tos: Optional[str] = None
    tos_mask: Optional[str] = None

    source_explicit_fields: Set[str] = Field(default_factory=set)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanZone(BaseModel):
    name: str
    source_context: str = "root"
    advpn_health_check: Optional[str] = None
    advpn_select: Optional[str] = None
    minimum_sla_meet_members: Optional[int] = None
    service_sla_tie_break: Optional[str] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
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
    cost: Optional[int] = 0
    weight: Optional[int] = 1
    priority: Optional[int] = 1
    priority6: Optional[int] = 1024
    spillover_threshold: Optional[int] = 0
    ingress_spillover_threshold: Optional[int] = 0
    volume_ratio: Optional[int] = 1
    preferred_source: Optional[str] = None
    transport_group: Optional[int] = 0
    status: str = "enable"
    comment: Optional[str] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanSLA(BaseModel):
    id: int
    source_context: str = "root"
    jitter_threshold: Optional[int] = None
    latency_threshold: Optional[int] = None
    link_cost_factor: List[str] = Field(default_factory=list)
    mos_threshold: Optional[str] = None
    packetloss_threshold: Optional[int] = None
    priority_in_sla: Optional[int] = None
    priority_out_sla: Optional[int] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanHealthCheck(BaseModel):
    """FortiOS SD-WAN health check with effective defaults and provenance."""

    name: str
    source_context: str = "root"
    server: Optional[str] = None
    servers: List[str] = Field(default_factory=list)
    members: List[int] = Field(default_factory=list)
    addr_mode: str = "ipv4"
    class_id: int = 0
    detect_mode: str = "active"
    diffservcode: Optional[str] = None
    dns_match_ip: Optional[str] = None
    dns_request_domain: str = "www.example.com"
    embed_measured_health: str = "disable"
    ftp_file: Optional[str] = None
    ftp_mode: str = "passive"
    ha_priority: int = 1
    http_agent: str = "Chrome/ Safari/"
    http_get: str = "/"
    http_match: Optional[str] = None
    mos_codec: str = "g711"
    packet_size: int = 124
    has_password: bool = False
    password_format: Optional[str] = None
    probe_count: int = 30
    probe_packets: str = "enable"
    quality_measured_method: str = "half-open"
    security_mode: str = "none"
    sla_fail_log_period: int = 0
    sla_id_redistribute: int = 0
    sla_pass_log_period: int = 0
    source6: Optional[str] = None
    system_dns: str = "disable"
    threshold_alert_jitter: int = 0
    threshold_alert_latency: int = 0
    threshold_alert_packetloss: int = 0
    threshold_warning_jitter: int = 0
    threshold_warning_latency: int = 0
    threshold_warning_packetloss: int = 0
    update_cascade_interface: str = "enable"
    user: Optional[str] = None
    protocol: str = "ping"
    port: int = 0
    interval: int = 500
    probe_timeout: int = 500
    failtime: int = 5
    recoverytime: int = 5
    update_static_route: str = "enable"
    vrf: int = 0
    source: Optional[str] = None
    sla: List[FGSDWanSLA] = Field(default_factory=list)
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanServiceSLA(BaseModel):
    name: str
    source_context: str = "root"
    id: int = 0
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanService(BaseModel):
    """FortiOS SD-WAN service rule with effective defaults and provenance."""

    id: int
    source_context: str = "root"
    name: Optional[str] = None
    mode: str = "manual"
    strategy: Optional[str] = None
    status: str = "enable"
    addr_mode: str = "ipv4"
    agent_exclusive: str = "disable"
    bandwidth_weight: int = 0
    default: str = "disable"
    dscp_forward: str = "disable"
    dscp_forward_tag: Optional[str] = None
    dscp_reverse: str = "disable"
    dscp_reverse_tag: Optional[str] = None
    dst_negate: str = "disable"
    src: List[str] = Field(default_factory=list)
    src6: List[str] = Field(default_factory=list)
    dst: List[str] = Field(default_factory=list)
    dst6: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    start_port: int = 1
    end_port: int = 65535
    start_src_port: int = 1
    end_src_port: int = 65535
    gateway: str = "disable"
    groups: List[str] = Field(default_factory=list)
    hash_mode: str = "round-robin"
    hold_down_time: int = 0
    health_check: List[str] = Field(default_factory=list)
    input_device: List[str] = Field(default_factory=list)
    input_device_negate: str = "disable"
    input_zone: List[str] = Field(default_factory=list)
    priority_members: List[int] = Field(default_factory=list)
    priority_zone: List[str] = Field(default_factory=list)
    internet_service: str = "disable"
    internet_service_name: List[str] = Field(default_factory=list)
    internet_service_app_ctrl: List[int] = Field(default_factory=list)
    internet_service_app_ctrl_category: List[int] = Field(default_factory=list)
    internet_service_app_ctrl_group: List[str] = Field(default_factory=list)
    internet_service_custom: List[str] = Field(default_factory=list)
    internet_service_custom_group: List[str] = Field(default_factory=list)
    internet_service_group: List[str] = Field(default_factory=list)
    jitter_weight: int = 0
    latency_weight: int = 0
    packet_loss_weight: int = 0
    link_cost_factor: str = "latency"
    link_cost_threshold: int = 10
    load_balance: str = "disable"
    minimum_sla_meet_members: int = 0
    passive_measurement: str = "disable"
    protocol: int = 0
    quality_link: int = 0
    role: str = "standalone"
    shortcut: str = "enable"
    shortcut_priority: str = "auto"
    sla_compare_method: str = "order"
    tie_break: str = "zone"
    use_shortcut_sla: str = "enable"
    sla_stickiness: str = "disable"
    src_negate: str = "disable"
    standalone_action: str = "disable"
    tos: Optional[str] = None
    tos_mask: Optional[str] = None
    users: List[str] = Field(default_factory=list)
    zone_mode: str = "disable"
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
    alt_primary: Optional[str] = None
    alt_secondary: Optional[str] = None
    ip6_primary: Optional[str] = None
    ip6_secondary: Optional[str] = None
    # FortiOS-specific behavior is retained explicitly for audit/reporting;
    # only primary/secondary are portable IR fields today.
    protocol: List[str] = Field(default_factory=list)
    server_select_method: Optional[str] = None
    domain: List[str] = Field(default_factory=list)
    server_hostname: List[str] = Field(default_factory=list)
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    source_ip: Optional[str] = None
    source_ip6: Optional[str] = None
    ssl_certificate: Optional[str] = None
    timeout: Optional[int] = None
    retry: Optional[int] = None
    dns_cache_limit: Optional[int] = None
    dns_cache_ttl: Optional[int] = None
    cache_notfound_responses: Optional[str] = None
    fqdn_cache_ttl: Optional[int] = None
    fqdn_max_refresh: Optional[int] = None
    fqdn_min_refresh: Optional[int] = None
    log: Optional[str] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
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


class FGProfileGroup(FGContextualModel):
    name: str
    application_list: Optional[str] = None
    av_profile: Optional[str] = None
    casb_profile: Optional[str] = None
    cifs_profile: Optional[str] = None
    diameter_filter_profile: Optional[str] = None
    dlp_profile: Optional[str] = None
    dnsfilter_profile: Optional[str] = None
    emailfilter_profile: Optional[str] = None
    file_filter_profile: Optional[str] = None
    icap_profile: Optional[str] = None
    ips_sensor: Optional[str] = None
    profile_protocol_options: Optional[str] = None
    sctp_filter_profile: Optional[str] = None
    ssh_filter_profile: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    videofilter_profile: Optional[str] = None
    virtual_patch_profile: Optional[str] = None
    voip_profile: Optional[str] = None
    waf_profile: Optional[str] = None
    webfilter_profile: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserLDAP(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str
    server: Optional[str] = None
    cnid: Optional[str] = None
    dn: Optional[str] = None
    type: Optional[str] = None
    two_factor: Optional[str] = None
    two_factor_authentication: Optional[str] = None
    two_factor_notification: Optional[str] = None
    two_factor_filter: Optional[str] = None
    username: Optional[str] = None
    has_password: bool = False
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None
    port: Optional[int] = None
    secure: Optional[str] = None
    ca_cert: Optional[str] = None
    server_identity_check: Optional[str] = None
    source_ip: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    group_filter: Optional[str] = None
    group_search_base: Optional[str] = None
    obtain_user_info: Optional[str] = None
    password_expiry_warning: Optional[str] = None
    password_renewal: Optional[str] = None
    account_key_cert_field: Optional[str] = None
    account_key_filter: Optional[str] = None
    account_key_processing: Optional[str] = None
    antiphish: Optional[str] = None
    client_cert: Optional[str] = None
    client_cert_auth: Optional[str] = None
    schema_: Optional[str] = Field(default=None, alias="schema")

    @property
    def schema(self) -> Optional[str]:
        return self.schema_

    @schema.setter
    def schema(self, value: Optional[str]) -> None:
        self.schema_ = value
    username_sensitivity: Optional[str] = None
    timeout: Optional[int] = None
    connect_timeout: Optional[int] = None
    query_timeout: Optional[int] = None
    group_member_check: Optional[str] = None
    group_object_filter: Optional[str] = None
    member_attr: Optional[str] = None
    password_attr: Optional[str] = None
    search_type: List[str] = Field(default_factory=list)
    source_port: Optional[int] = None
    ssl_min_proto_version: Optional[str] = None
    user_info_exchange_server: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGFSSOEndpoint(BaseModel):
    index: int
    server: Optional[str] = None
    port: Optional[int] = None
    has_password: bool = False


class FGFSSOServer(BaseModel):
    name: str
    endpoints: List[FGFSSOEndpoint] = Field(default_factory=list)
    server: Optional[str] = None
    has_password: bool = False
    server2: Optional[str] = None
    server3: Optional[str] = None
    server4: Optional[str] = None
    server5: Optional[str] = None
    port: Optional[int] = None
    port2: Optional[int] = None
    port3: Optional[int] = None
    port4: Optional[int] = None
    port5: Optional[int] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    ldap_poll: Optional[str] = None
    ldap_poll_filter: Optional[str] = None
    ldap_poll_interval: Optional[int] = None
    group_poll_interval: Optional[int] = None
    ldap_server: Optional[str] = None
    logon_timeout: Optional[int] = None
    source_ip: Optional[str] = None
    source_ip6: Optional[str] = None
    ssl: Optional[str] = None
    ssl_server_host_ip_check: Optional[str] = None
    ssl_trusted_cert: Optional[str] = None
    sni: Optional[str] = None
    type: Optional[str] = None
    user_info_server: Optional[str] = None
    vrf_select: Optional[int] = None
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
    cert: Optional[str] = None
    clock_tolerance: Optional[int] = None
    adfs_claim: Optional[str] = None
    limit_relaystate: Optional[str] = None
    reauth: Optional[str] = None
    user_claim_type: Optional[str] = None
    group_claim_type: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGLocalUser(BaseModel):
    name: str
    id: Optional[int] = None
    status: Optional[str] = None
    type: Optional[str] = None
    has_password: bool = False
    passwd_time: Optional[str] = None
    two_factor: Optional[str] = None
    two_factor_authentication: Optional[str] = None
    two_factor_notification: Optional[str] = None
    fortitoken: Optional[str] = None
    email_to: Optional[str] = None
    sms_server: Optional[str] = None
    sms_custom_server: Optional[str] = None
    sms_phone: Optional[str] = None
    ldap_server: Optional[str] = None
    radius_server: Optional[str] = None
    auth_concurrent_override: Optional[str] = None
    auth_concurrent_value: Optional[int] = None
    authtimeout: Optional[int] = None
    passwd_policy: Optional[str] = None
    workstation: Optional[str] = None
    username_sensitivity: Optional[str] = None
    tacacs_server: Optional[str] = None
    ppk_identity: Optional[str] = None
    has_ppk_secret: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGFSSOPollingADGroup(BaseModel):
    name: str
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGFSSOPolling(FGContextualModel):
    name: str
    status: Optional[str] = None
    server: Optional[str] = None
    default_domain: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    has_password: bool = False
    ldap_server: Optional[str] = None
    logon_history: Optional[int] = None
    polling_frequency: Optional[int] = None
    smbv1: Optional[str] = None
    smb_ntlmv1_auth: Optional[str] = None
    ad_groups: List[FGFSSOPollingADGroup] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserGroupMatch(BaseModel):
    id: int
    server_name: Optional[str] = None
    group_name: Optional[str] = None


class FGUserGroupGuest(BaseModel):
    id: int
    name: Optional[str] = None
    user_id: Optional[str] = None
    company: Optional[str] = None
    email: Optional[str] = None
    expiration: Optional[str] = None
    mobile_phone: Optional[str] = None
    sponsor: Optional[str] = None
    has_password: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserGroup(BaseModel):
    name: str
    group_type: Optional[str] = None
    member: List[str] = Field(default_factory=list)
    match: List[FGUserGroupMatch] = Field(default_factory=list)
    auth_concurrent_override: Optional[str] = None
    auth_concurrent_value: Optional[int] = None
    authtimeout: Optional[int] = None
    company: Optional[str] = None
    email: Optional[str] = None
    expire: Optional[int] = None
    expire_type: Optional[str] = None
    http_digest_realm: Optional[str] = None
    id: Optional[int] = None
    max_accounts: Optional[int] = None
    mobile_phone: Optional[str] = None
    multiple_guest_add: Optional[str] = None
    password: Optional[str] = None
    sms_custom_server: Optional[str] = None
    sms_server: Optional[str] = None
    sponsor: Optional[str] = None
    sso_attribute_value: Optional[str] = None
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    guests: List[FGUserGroupGuest] = Field(default_factory=list)
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


class FGSSLVPNPortalSplitDNS(BaseModel):
    id: int
    domains: Optional[str] = None
    dns_server1: Optional[str] = None
    dns_server2: Optional[str] = None
    ipv6_dns_server1: Optional[str] = None
    ipv6_dns_server2: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNPortalLandingPageFormData(BaseModel):
    name: str
    value_configured: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNPortalLandingPage(BaseModel):
    name: str
    heading: Optional[str] = None
    title: Optional[str] = None
    theme: Optional[str] = None
    url: Optional[str] = None
    sso: Optional[str] = None
    sso_credential: Optional[str] = None
    sso_username: Optional[str] = None
    has_sso_password: bool = False
    form_data: List[FGSSLVPNPortalLandingPageFormData] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNPortalMACAddressRule(BaseModel):
    id: Optional[int] = None
    mac_addr: Optional[str] = None
    mac_addr_list: List[str] = Field(default_factory=list)
    mac_addr_mask: Optional[int] = None
    action: Optional[str] = None
    status: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNPortalOSCheck(BaseModel):
    id: Optional[int] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    tolerance: Optional[int] = None
    latest_patch_level: Optional[str] = None
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
    allow_user_access: List[str] = Field(default_factory=list)
    auto_connect: Optional[str] = None
    exclusive_routing: Optional[str] = None
    ip_mode: Optional[str] = None
    service_restriction: Optional[str] = None
    split_tunneling_routing_address: List[str] = Field(default_factory=list)
    split_tunneling_routing_negate: Optional[str] = None
    client_src_range: Optional[str] = None
    clipboard: Optional[str] = None
    custom_lang: Optional[str] = None
    customize_forticlient_download_url: Optional[str] = None
    default_protocol: Optional[str] = None
    default_window_height: Optional[int] = None
    default_window_width: Optional[int] = None
    dhcp_ip_overlap: Optional[str] = None
    dhcp_ra_giaddr: Optional[str] = None
    dhcp6_ra_linkaddr: Optional[str] = None
    display_bookmark: Optional[str] = None
    display_connection_tools: Optional[str] = None
    display_history: Optional[str] = None
    display_status: Optional[str] = None
    dns_server1: Optional[str] = None
    dns_server2: Optional[str] = None
    dns_suffix: Optional[str] = None
    focus_bookmark: Optional[str] = None
    forticlient_download_method: Optional[str] = None
    heading: Optional[str] = None
    hide_sso_credential: Optional[str] = None
    ipv6_dns_server1: Optional[str] = None
    ipv6_dns_server2: Optional[str] = None
    ipv6_exclusive_routing: Optional[str] = None
    ipv6_service_restriction: Optional[str] = None
    ipv6_split_tunneling: Optional[str] = None
    ipv6_split_tunneling_routing_address: List[str] = Field(default_factory=list)
    ipv6_split_tunneling_routing_negate: Optional[str] = None
    ipv6_wins_server1: Optional[str] = None
    ipv6_wins_server2: Optional[str] = None
    keep_alive: Optional[str] = None
    landing_page_mode: Optional[str] = None
    mac_addr_action: Optional[str] = None
    mac_addr_check: Optional[str] = None
    macos_forticlient_download_url: Optional[str] = None
    os_check: Optional[str] = None
    prefer_ipv6_dns: Optional[str] = None
    redir_url: Optional[str] = None
    rewrite_ip_uri_ui: Optional[str] = None
    save_password: Optional[str] = None
    skip_check_for_browser: Optional[str] = None
    skip_check_for_unsupported_os: Optional[str] = None
    smb_max_version: Optional[str] = None
    smb_min_version: Optional[str] = None
    smb_ntlmv1_auth: Optional[str] = None
    smbv1: Optional[str] = None
    theme: Optional[str] = None
    use_sdwan: Optional[str] = None
    user_bookmark: Optional[str] = None
    user_group_bookmark: Optional[str] = None
    web_mode: Optional[str] = None
    windows_forticlient_download_url: Optional[str] = None
    wins_server1: Optional[str] = None
    wins_server2: Optional[str] = None
    landing_pages: List[FGSSLVPNPortalLandingPage] = Field(default_factory=list)
    mac_address_check_rules: List[FGSSLVPNPortalMACAddressRule] = Field(default_factory=list)
    os_check_list: List[FGSSLVPNPortalOSCheck] = Field(default_factory=list)
    split_dns: List[FGSSLVPNPortalSplitDNS] = Field(default_factory=list)
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
    auth_session_check_source_ip: Optional[str] = None
    auto_tunnel_static_route: Optional[str] = None
    browser_language_detection: Optional[str] = None
    check_referer: Optional[str] = None
    ciphersuite: List[str] = Field(default_factory=list)
    deflate_compression_level: Optional[int] = None
    deflate_min_data_size: Optional[int] = None
    dns_suffix: Optional[str] = None
    dtls_heartbeat_fail_count: Optional[int] = None
    dtls_heartbeat_idle_timeout: Optional[int] = None
    dtls_heartbeat_interval: Optional[int] = None
    dtls_hello_timeout: Optional[int] = None
    dtls_max_proto_ver: Optional[str] = None
    dtls_min_proto_ver: Optional[str] = None
    dual_stack_mode: Optional[str] = None
    encode_2f_sequence: Optional[str] = None
    encrypt_and_store_password: Optional[str] = None
    force_two_factor_auth: Optional[str] = None
    header_x_forwarded_for: Optional[str] = None
    hsts_include_subdomains: Optional[str] = None
    http_compression: Optional[str] = None
    http_only_cookie: Optional[str] = None
    http_request_body_timeout: Optional[int] = None
    http_request_header_timeout: Optional[int] = None
    https_redirect: Optional[str] = None
    ipv6_dns_server1: Optional[str] = None
    ipv6_dns_server2: Optional[str] = None
    ipv6_wins_server1: Optional[str] = None
    ipv6_wins_server2: Optional[str] = None
    login_timeout: Optional[int] = None
    port_precedence: Optional[str] = None
    saml_redirect_port: Optional[int] = None
    server_hostname: Optional[str] = None
    source_address_negate: Optional[str] = None
    source_address6: List[str] = Field(default_factory=list)
    source_address6_negate: Optional[str] = None
    ssl_client_renegotiation: Optional[str] = None
    ssl_insert_empty_fragment: Optional[str] = None
    transform_backward_slashes: Optional[str] = None
    tunnel_addr_assigned_method: Optional[str] = None
    tunnel_connect_without_reauth: Optional[str] = None
    tunnel_ipv6_pools: List[str] = Field(default_factory=list)
    tunnel_user_session_timeout: Optional[int] = None
    unsafe_legacy_renegotiation: Optional[str] = None
    url_obscuration: Optional[str] = None
    user_peer: Optional[str] = None
    x_content_type_options: Optional[str] = None
    ztna_trusted_client: Optional[str] = None
    default_portal: Optional[str] = None
    authentication_rules: List[FGSSLVPNAuthenticationRule] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDoSAnomaly(BaseModel):
    name: str
    status: Optional[str] = None
    log: Optional[str] = None
    action: Optional[str] = None
    quarantine: Optional[str] = None
    quarantine_expiry: Optional[str] = None
    quarantine_log: Optional[str] = None
    threshold: Optional[int] = None
    threshold_default: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDoSPolicy(BaseModel):
    id: int
    name: Optional[str] = None
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


class FGUserRADIUSAccountingServer(BaseModel):
    id: str
    status: Optional[str] = None
    server: Optional[str] = None
    port: Optional[int] = None
    source_ip: Optional[str] = None
    source_ip6: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    vrf_select: Optional[int] = None
    has_secret: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGUserRADIUS(FGContextualModel):
    name: str
    server: Optional[str] = None
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None
    auth_type: Optional[str] = None
    transport_protocol: Optional[str] = None
    tls_min_proto_version: Optional[str] = None
    ca_cert: Optional[str] = None
    client_cert: Optional[str] = None
    auth_port: Optional[int] = None
    acct_port: Optional[int] = None
    coa_port: Optional[int] = None
    timeout: Optional[int] = None
    retries: Optional[int] = None
    status_ttl: Optional[int] = None
    all_usergroup: Optional[str] = None
    acct_all_servers: Optional[str] = None
    username_case_sensitive: Optional[str] = None
    password_renewal: Optional[str] = None
    account_key_cert_field: Optional[str] = None
    account_key_processing: Optional[str] = None
    class_: List[str] = Field(default_factory=list)
    delimiter: Optional[str] = None
    group_override_attr_type: Optional[str] = None
    h3c_compatibility: Optional[str] = None
    switch_controller_nas_ip_dynamic: Optional[str] = None
    switch_controller_service_type: List[str] = Field(default_factory=list)
    use_management_vdom: Optional[str] = None
    vrf_select: Optional[int] = None
    nas_ip: Optional[str] = None
    nas_ip6: Optional[str] = None
    source_ip: Optional[str] = None
    source_ip6: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    radius_port: Optional[int] = None
    acct_interim_interval: Optional[int] = None
    accounting_servers: List[FGUserRADIUSAccountingServer] = Field(default_factory=list)
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
    source_ip6: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    timeout: Optional[int] = None
    retries: Optional[int] = None
    connect_timeout: Optional[int] = None
    status_ttl: Optional[int] = None
    vrf_select: Optional[int] = None
    has_secret: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGLinkMonitorServer(BaseModel):
    id: Optional[Union[int, str]] = None
    dst: Optional[str] = None
    server: Optional[str] = None
    protocol: List[str] = Field(default_factory=list)
    port: Optional[int] = None
    weight: Optional[int] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGLinkMonitor(FGContextualModel):
    name: str
    srcintf: List[str] = Field(default_factory=list)
    server: List[str] = Field(default_factory=list)
    protocol: List[str] = Field(default_factory=list)
    status: Optional[str] = None
    gateway_ip: Optional[str] = None
    gateway_ip6: Optional[str] = None
    source_ip: Optional[str] = None
    source_ip6: Optional[str] = None
    port: Optional[int] = None
    interval: Optional[int] = None
    timeout: Optional[int] = None
    failtime: Optional[int] = None
    recoverytime: Optional[int] = None
    ha_priority: Optional[int] = None
    http_agent: Optional[str] = None
    http_get: Optional[str] = None
    http_match: Optional[str] = None
    packet_size: Optional[int] = None
    diffservcode: Optional[str] = None
    probe_count: Optional[int] = None
    probe_timeout: Optional[int] = None
    service_detection: Optional[str] = None
    class_id: Optional[int] = None
    update_static_route: Optional[str] = None
    update_policy_route: Optional[str] = None
    update_cascade_interface: Optional[str] = None
    server_list: List[FGLinkMonitorServer] = Field(default_factory=list)
    vrf: Optional[int] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @property
    def servers(self) -> List[FGLinkMonitorServer]:
        return self.server_list


class FGVirtualWirePair(FGContextualModel):
    name: str
    members: List[str] = Field(default_factory=list)
    outer_vlan_id: List[int] = Field(default_factory=list)
    wildcard_vlan: Optional[str] = None
    vlan_filter: Optional[str] = None
    vlan_filtering: Optional[str] = None
    ingress_filtering: Optional[str] = None
    power_save: Optional[str] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGVDOMLink(FGContextualModel):
    name: str
    vdom: Optional[str] = None
    peer: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
    interface: Optional[str] = None
    vcluster: Optional[str] = None
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGProfileNestedSection(BaseModel):
    """Typed, secret-safe representation of a profile's nested section."""
    name: str
    settings: Dict[str, Any] = Field(default_factory=dict)
    entries: List["FGProfileNestedSection"] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSecurityProfile(BaseModel):
    """Common typed container for FortiOS security-profile semantics."""
    name: str
    settings: Dict[str, Any] = Field(default_factory=dict)
    protocols: List[FGProfileNestedSection] = Field(default_factory=list)
    categories: List[FGProfileNestedSection] = Field(default_factory=list)
    overrides: List[FGProfileNestedSection] = Field(default_factory=list)
    url_filters: List[FGProfileNestedSection] = Field(default_factory=list)
    domain_filters: List[FGProfileNestedSection] = Field(default_factory=list)
    botnet_controls: List[FGProfileNestedSection] = Field(default_factory=list)
    exemptions: List[FGProfileNestedSection] = Field(default_factory=list)
    entries: List[FGProfileNestedSection] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAntivirusProfileConfig(BaseModel):
    name: str
    status: Optional[str] = None
    action: Optional[str] = None
    scan: Optional[str] = None
    log: Optional[str] = None
    comment: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAntivirusProtocol(BaseModel):
    name: str
    status: Optional[str] = None
    action: Optional[str] = None
    scan: Optional[str] = None
    comment: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    configs: List[FGAntivirusProfileConfig] = Field(default_factory=list)
    entries: List[FGProfileNestedSection] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAntivirusProfile(BaseModel):
    name: str
    source_context: str = "root"
    comment: Optional[str] = None
    status: Optional[str] = None
    inspection_mode: Optional[str] = None
    protocols: List[FGAntivirusProtocol] = Field(default_factory=list)
    configs: List[FGAntivirusProfileConfig] = Field(default_factory=list)
    entries: List[FGProfileNestedSection] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGWebFilterCategory(BaseModel):
    name: str
    category: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    log: Optional[str] = None
    override: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGWebFilterOverride(BaseModel):
    name: str
    category: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    authentication: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGWebFilterURLFilter(BaseModel):
    name: str
    url: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    type: Optional[str] = None
    auth_users: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGWebFilterProfile(BaseModel):
    name: str
    source_context: str = "root"
    comment: Optional[str] = None
    status: Optional[str] = None
    inspection_mode: Optional[str] = None
    categories: List[FGWebFilterCategory] = Field(default_factory=list)
    overrides: List[FGWebFilterOverride] = Field(default_factory=list)
    url_filters: List[FGWebFilterURLFilter] = Field(default_factory=list)
    entries: List[FGProfileNestedSection] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDNSFilterAction(BaseModel):
    name: str
    action: Optional[str] = None
    redirect: Optional[str] = None
    status: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDNSFilterCategory(BaseModel):
    name: str
    category: Optional[str] = None
    action: Optional[str] = None
    redirect: Optional[str] = None
    status: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDNSFilterDomainFilter(BaseModel):
    name: str
    domain: Optional[str] = None
    action: Optional[str] = None
    redirect: Optional[str] = None
    status: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDNSFilterBotnet(BaseModel):
    name: str
    action: Optional[str] = None
    redirect: Optional[str] = None
    status: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGDNSFilterProfile(BaseModel):
    name: str
    source_context: str = "root"
    comment: Optional[str] = None
    status: Optional[str] = None
    categories: List[FGDNSFilterCategory] = Field(default_factory=list)
    domain_filters: List[FGDNSFilterDomainFilter] = Field(default_factory=list)
    botnet: List[FGDNSFilterBotnet] = Field(default_factory=list)
    actions: List[FGDNSFilterAction] = Field(default_factory=list)
    entries: List[FGProfileNestedSection] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGApplicationEntry(BaseModel):
    name: str
    application: List[int] = Field(default_factory=list)
    # Compatibility field; 'application' is the authoritative source field.
    application_id: Optional[int] = Field(
        default=None,
        description="Compatibility field. 'application' is the authoritative source field.",
    )
    category: List[int] = Field(default_factory=list)
    risk: List[int] = Field(default_factory=list)
    action: Optional[str] = None
    status: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("application", "category", "risk", mode="before")
    @classmethod
    def _coerce_int_collection(cls, v: Any) -> Any:
        if v is None:
            return []
        if isinstance(v, (int, str)):
            v = [v]
        result = []
        for item in v:
            if isinstance(item, str):
                for part in item.strip().split():
                    if part.isdigit():
                        result.append(int(part))
                    elif part:
                        result.append(part)
            else:
                result.append(item)
        return result

    @model_validator(mode="after")
    def _sync_application_id(self) -> "FGApplicationEntry":
        if self.application_id is None and self.application:
            self.application_id = self.application[0]
        return self


class FGApplicationFilter(BaseModel):
    name: str
    category: List[int] = Field(default_factory=list)
    risk: List[int] = Field(default_factory=list)
    action: Optional[str] = None
    status: Optional[str] = None
    entries: List[FGProfileNestedSection] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("category", "risk", mode="before")
    @classmethod
    def _coerce_int_collection(cls, v: Any) -> Any:
        if v is None:
            return []
        if isinstance(v, (int, str)):
            v = [v]
        result = []
        for item in v:
            if isinstance(item, str):
                for part in item.strip().split():
                    if part.isdigit():
                        result.append(int(part))
                    elif part:
                        result.append(part)
            else:
                result.append(item)
        return result


class FGApplicationOverride(BaseModel):
    name: str
    application: List[int] = Field(default_factory=list)
    category: List[int] = Field(default_factory=list)
    action: Optional[str] = None
    status: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("application", "category", mode="before")
    @classmethod
    def _coerce_int_collection(cls, v: Any) -> Any:
        if v is None:
            return []
        if isinstance(v, (int, str)):
            v = [v]
        result = []
        for item in v:
            if isinstance(item, str):
                for part in item.strip().split():
                    if part.isdigit():
                        result.append(int(part))
                    elif part:
                        result.append(part)
            else:
                result.append(item)
        return result


class FGApplicationList(BaseModel):
    name: str
    source_context: str = "root"
    comment: Optional[str] = None
    entries: List[FGApplicationEntry] = Field(default_factory=list)
    filters: List[FGApplicationFilter] = Field(default_factory=list)
    overrides: List[FGApplicationOverride] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLSSHProtocolInspection(BaseModel):
    name: str
    status: Optional[str] = None
    ports: List[str] = Field(default_factory=list)
    action: Optional[str] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLSSHCertificate(BaseModel):
    name: str
    certificate: Optional[str] = None
    status: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLSSHExemption(BaseModel):
    name: str
    address: Optional[str] = None
    category: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLSSHProfile(BaseModel):
    name: str
    source_context: str = "root"
    comment: Optional[str] = None
    inspection_mode: Optional[str] = None
    protocols: List[FGSSLSSHProtocolInspection] = Field(default_factory=list)
    certificates: List[FGSSLSSHCertificate] = Field(default_factory=list)
    exemptions: List[FGSSLSSHExemption] = Field(default_factory=list)
    entries: List[FGProfileNestedSection] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSystemFSSOPolling(BaseModel):
    """Typed, source-only FortiOS ``config system fsso-polling`` settings."""

    source_context: str = "root"
    status: Optional[str] = None
    listening_port: Optional[int] = None
    authentication: Optional[str] = None
    has_auth_password: bool = False
    source_explicit_fields: Set[str] = Field(default_factory=set)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGConfig(BaseModel):
    """Root model for a parsed FortiGate configuration."""

    source_version: Optional[str] = None
    source_build: Optional[str] = None
    execution_contexts: List[FGExecutionContext] = Field(default_factory=list)

    dns: Optional[FGDns] = None

    system_zones: List[FGSystemZone] = Field(default_factory=list)
    interfaces: List[SerializeAsAny[FGInterface]] = Field(default_factory=list)

    addresses: List[SerializeAsAny[FGAddress]] = Field(default_factory=list)
    address_groups: List[FGAddressGroup] = Field(default_factory=list)
    wildcard_fqdns: List[FGWildcardFQDN] = Field(default_factory=list)

    services: List[SerializeAsAny[FGService]] = Field(default_factory=list)
    service_groups: List[FGServiceGroup] = Field(default_factory=list)

    schedules: List[FGSchedule] = Field(default_factory=list)
    schedule_groups: List[FGScheduleGroup] = Field(default_factory=list)

    ip_pools: List[FGIPPool] = Field(default_factory=list)
    ip_pools6: List[FGIPPool6] = Field(default_factory=list)
    ip_pool_groups: List[FGIPPoolGroup] = Field(default_factory=list)

    vips: List[SerializeAsAny[FGVIP]] = Field(default_factory=list)
    vips6: List[FGVIP6] = Field(default_factory=list)
    vip_groups: List[FGVIPGroup] = Field(default_factory=list)
    vip_groups6: List[FGVIPGroup6] = Field(default_factory=list)

    policies: List[SerializeAsAny[FGPolicy]] = Field(default_factory=list)
    central_snat_rules: List[FGCentralSNATRule] = Field(default_factory=list)
    ip_translations: List[FGIPTranslation] = Field(default_factory=list)
    security_policies: List[FGSecurityPolicy] = Field(default_factory=list)
    policy_routes: List[FGPolicyRoute] = Field(default_factory=list)
    phase1_policies: List[FGPhase1Policy] = Field(default_factory=list)
    phase2_policies: List[FGPhase2Policy] = Field(default_factory=list)
    profile_groups: List[FGProfileGroup] = Field(default_factory=list)

    phase1_interfaces: List[FGPhase1Interface] = Field(
        default_factory=list
    )
    phase2_interfaces: List[FGPhase2Interface] = Field(
        default_factory=list
    )

    certificates: List[FGCertificate] = Field(default_factory=list)

    static_routes: List[FGStaticRoute] = Field(default_factory=list)

    sdwans: List[FGSDWan] = Field(default_factory=list)

    user_ldap_servers: List[FGUserLDAP] = Field(default_factory=list)
    fsso_servers: List[FGFSSOServer] = Field(default_factory=list)
    fsso_polling: List[FGFSSOPolling] = Field(default_factory=list)
    system_fsso_polling: Optional[FGSystemFSSOPolling] = None
    ad_groups: List[FGADGroup] = Field(default_factory=list)
    user_saml_servers: List[FGUserSAML] = Field(default_factory=list)
    local_users: List[FGLocalUser] = Field(default_factory=list)
    user_groups: List[FGUserGroup] = Field(default_factory=list)
    user_authentication_settings: Optional[FGUserAuthenticationSettings] = None
    user_quarantine: Optional[FGUserQuarantine] = None
    ssl_vpn_portals: List[FGSSLVPNPortal] = Field(default_factory=list)
    ssl_vpn_settings: Optional[FGSSLVPNSettings] = None
    dos_policies: List[FGDoSPolicy] = Field(default_factory=list)
    antivirus_profiles: List[SerializeAsAny[FGAntivirusProfile]] = Field(default_factory=list)
    webfilter_profiles: List[SerializeAsAny[FGWebFilterProfile]] = Field(default_factory=list)
    dnsfilter_profiles: List[SerializeAsAny[FGDNSFilterProfile]] = Field(default_factory=list)
    application_lists: List[SerializeAsAny[FGApplicationList]] = Field(default_factory=list)
    ssl_ssh_profiles: List[FGSSLSSHProfile] = Field(default_factory=list)
    # Typed FortiGate parents whose nested/source-specific semantics remain
    # extraction-only. Their recursive counterparts remain parser-local and in
    # source inventory.
    radius_servers: List[FGUserRADIUS] = Field(default_factory=list)
    tacacs_servers: List[FGUserTACACS] = Field(default_factory=list)
    link_monitors: List[FGLinkMonitor] = Field(default_factory=list)
    virtual_wire_pairs: List[FGVirtualWirePair] = Field(default_factory=list)
    vdom_links: List[FGVDOMLink] = Field(default_factory=list)

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
    def user_radius(self) -> List[FGUserRADIUS]:
        return self.radius_servers

    @property
    def user_tacacs(self) -> List[FGUserTACACS]:
        return self.tacacs_servers
