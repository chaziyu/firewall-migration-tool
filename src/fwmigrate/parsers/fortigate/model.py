from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from fwmigrate.parsers.fortigate.source_tree import FGSourceNode

class FGInterfaceSecondaryIP(BaseModel):
    id: int
    ip: Optional[str] = None
    allowaccess: List[str] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGInterface(BaseModel):
    name: str
    vdom: str = "root"

    ip: Optional[str] = None
    remote_ip: Optional[str] = None

    secondary_ip: Optional[str] = None
    secondary_ips: List[
        FGInterfaceSecondaryIP
    ] = Field(default_factory=list)

    allowaccess: List[str] = Field(default_factory=list)

    type: Optional[str] = None
    role: str = "undefined"
    alias: Optional[str] = None
    description: Optional[str] = None

    vlanid: Optional[int] = None
    interface: Optional[str] = None

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

    # Explicit top-level `set` values retained for
    # extraction/reporting only.
    source_attributes: Dict[str, Any] = Field(
        default_factory=dict
    )

class FGSystemZone(BaseModel):
    name: str
    interface: List[str] = Field(default_factory=list)
    tag: Optional[str] = None
    description: Optional[str] = None

class FGAddress(BaseModel):
    name: str
    uuid: Optional[str] = None
    type: str = "ipmask"  # ipmask, fqdn, iprange, dynamic
    sub_type: Optional[str] = None
    subnet: Optional[str] = None  # e.g. "192.168.1.0 255.255.255.0"
    ip6: Optional[str] = None
    fqdn: Optional[str] = None
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    country: Optional[str] = None
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
    is_ipv6: bool = False
    is_multicast: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGAddressGroup(BaseModel):
    name: str
    member: List[str] = Field(default_factory=list)
    comment: Optional[str] = None
    uuid: Optional[str] = None
    allow_routing: Optional[str] = None
    color: Optional[int] = None
    category: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGWildcardFQDN(BaseModel):
    name: str
    wildcard_fqdn: str
    comment: Optional[str] = None
    uuid: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGServiceCategory(BaseModel):
    name: str
    comment: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGService(BaseModel):
    name: str
    protocol: str = "tcp/udp/sctp"  # default
    tcp_portrange: Optional[str] = None
    udp_portrange: Optional[str] = None
    protocol_number: Optional[int] = None
    icmpcode: Optional[int] = None
    icmptype: Optional[int] = None
    comment: Optional[str] = None
    uuid: Optional[str] = None
    category: Optional[str] = None
    proxy: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGServiceGroup(BaseModel):
    name: str
    member: List[str] = Field(default_factory=list)
    comment: Optional[str] = None
    uuid: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGSchedule(BaseModel):
    name: str
    type: str = "recurring"
    start: Optional[str] = None
    end: Optional[str] = None
    day: List[str] = Field(default_factory=list)
    color: Optional[int] = None
    expiration_days: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGTrafficShaper(BaseModel):
    name: str
    guaranteed_bandwidth: Optional[int] = None
    maximum_bandwidth: Optional[int] = None
    bandwidth_unit: Optional[str] = None
    priority: Optional[str] = None
    per_policy: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGProxyAddress(BaseModel):
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

class FGIPPool(BaseModel):
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


class FGIPPool6(BaseModel):
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


class FGVIP(BaseModel):
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

class FGVIPGroup(BaseModel):
    name: str
    uuid: Optional[str] = None
    interface: Optional[str] = None
    color: Optional[int] = None
    member: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    comment: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGVIP6(BaseModel):
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


class FGVIPGroup6(BaseModel):
    name: str
    uuid: Optional[str] = None
    color: Optional[int] = None
    member: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGPolicy(BaseModel):
    id: int
    uuid: Optional[str] = None
    name: Optional[str] = None
    srcintf: List[str] = Field(default_factory=list)
    dstintf: List[str] = Field(default_factory=list)
    srcaddr: List[str] = Field(default_factory=list)
    dstaddr: List[str] = Field(default_factory=list)
    srcaddr_negate: Optional[str] = None
    dstaddr_negate: Optional[str] = None
    srcaddr6: List[str] = Field(default_factory=list)
    dstaddr6: List[str] = Field(default_factory=list)
    srcaddr6_negate: Optional[str] = None
    dstaddr6_negate: Optional[str] = None
    groups: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    action: str = "deny"
    schedule: str = "always"
    service: List[str] = Field(default_factory=list)
    service_negate: Optional[str] = None
    logtraffic: str = "utm"
    logtraffic_start: Optional[str] = None
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
    comments: Optional[str] = None
    status: str = "enable"
    # Security profiles
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
    internet_service_name: List[str] = Field(default_factory=list)
    inspection_mode: Optional[str] = None
    ztna_status: Optional[str] = None
    ztna_ems_tag: List[str] = Field(default_factory=list)
    vpntunnel: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGPhase1Interface(BaseModel):
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

class FGPhase2Interface(BaseModel):
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

class FGStaticRoute(BaseModel):
    id: int
    dst: Optional[str] = None
    gateway: Optional[str] = None
    device: Optional[str] = None
    distance: Optional[int] = None
    priority: Optional[int] = None
    comment: Optional[str] = None
    sdwan_zone: Optional[str] = None
    blackhole: str = "disable"
    status: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGSDWanZone(BaseModel):
    name: str
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGSDWanMember(BaseModel):
    id: int
    interface: str
    zone: str = "virtual-wan-link"
    gateway: Optional[str] = None
    weight: Optional[int] = None
    priority: Optional[int] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanSLA(BaseModel):
    id: int
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanHealthCheck(BaseModel):
    name: str
    server: Optional[str] = None
    members: List[int] = Field(default_factory=list)
    interval: Optional[int] = None
    sla: List[FGSDWanSLA] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSDWanService(BaseModel):
    id: int
    name: Optional[str] = None
    mode: Optional[str] = None
    src: List[str] = Field(default_factory=list)
    dst: List[str] = Field(default_factory=list)
    health_check: Optional[str] = None
    priority_members: List[int] = Field(default_factory=list)
    internet_service: Optional[str] = None
    internet_service_name: List[str] = Field(default_factory=list)
    internet_service_app_ctrl: List[int] = Field(default_factory=list)
    use_shortcut_sla: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGSDWan(BaseModel):
    status: str = "disable"
    load_balance_mode: Optional[str] = None
    zones: List[FGSDWanZone] = Field(default_factory=list)
    members: List[FGSDWanMember] = Field(default_factory=list)
    health_checks: List[FGSDWanHealthCheck] = Field(default_factory=list)
    services: List[FGSDWanService] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGDns(BaseModel):
    primary: Optional[str] = None
    secondary: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSystemGlobal(BaseModel):
    hostname: str
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


class FGDHCPServer(BaseModel):
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
    reserved_addresses: List[FGDHCPReservation] = Field(
        default_factory=list
    )

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


class FGIPSSensor(BaseModel):
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
    vdom: List[str] = Field(default_factory=list)
    trusthost1: Optional[str] = None
    trusthost2: Optional[str] = None
    two_factor: Optional[str] = None
    fortitoken: Optional[str] = None
    email_to: Optional[str] = None
    remote_auth: Optional[str] = None
    remote_group: Optional[str] = None
    credential_configured: bool = False
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGAdminProfile(BaseModel):
    name: str
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGFortiToken(BaseModel):
    serial: str
    status: Optional[str] = None
    comments: Optional[str] = None
    assigned_user: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNHostCheckSoftware(BaseModel):
    name: str
    type: Optional[str] = None
    guid: Optional[str] = None
    version: Optional[str] = None
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
    host_checks: List[FGSSLVPNHostCheckSoftware] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNAuthenticationRule(BaseModel):
    id: int
    groups: List[str] = Field(default_factory=list)
    portal: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)


class FGSSLVPNSettings(BaseModel):
    status: Optional[str] = None
    ssl_min_proto_ver: Optional[str] = None
    banned_cipher: List[str] = Field(default_factory=list)
    servercert: Optional[str] = None
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
    status: Optional[str] = None
    interface: Optional[str] = None
    srcaddr: List[str] = Field(default_factory=list)
    dstaddr: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    anomalies: List[FGDoSAnomaly] = Field(default_factory=list)
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

    sdwan: Optional[FGSDWan] = None

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

    dhcp_servers: List[FGDHCPServer] = Field(
        default_factory=list
    )
    user_ldap_servers: List[FGUserLDAP] = Field(default_factory=list)
    fsso_servers: List[FGFSSOServer] = Field(default_factory=list)
    ad_groups: List[FGADGroup] = Field(default_factory=list)
    user_saml_servers: List[FGUserSAML] = Field(default_factory=list)
    local_users: List[FGLocalUser] = Field(default_factory=list)
    user_groups: List[FGUserGroup] = Field(default_factory=list)
    administrators: List[FGAdministrator] = Field(default_factory=list)
    admin_profiles: List[FGAdminProfile] = Field(default_factory=list)
    fortitokens: List[FGFortiToken] = Field(default_factory=list)
    ssl_vpn_portals: List[FGSSLVPNPortal] = Field(default_factory=list)
    ssl_vpn_settings: Optional[FGSSLVPNSettings] = None
    dos_policies: List[FGDoSPolicy] = Field(default_factory=list)
    firewall_sniffers: List[FGFirewallSniffer] = Field(default_factory=list)
    authentication_schemes: List[FGAuthenticationScheme] = Field(default_factory=list)
    authentication_rules: List[FGAuthenticationRule] = Field(default_factory=list)
