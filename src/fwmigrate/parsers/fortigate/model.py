from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class FGInterface(BaseModel):
    name: str
    vdom: str = "root"
    ip: Optional[str] = None
    remote_ip: Optional[str] = None
    allowaccess: List[str] = Field(default_factory=list)
    type: str = "physical"
    role: str = "undefined"
    alias: Optional[str] = None
    description: Optional[str] = None
    vlanid: Optional[int] = None
    interface: Optional[str] = None  # Parent interface for VLANs
    status: str = "up"
    mode: str = "static"
    username: Optional[str] = None
    # Explicit ``set`` values retained for extraction/reporting only.
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

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

    comments: Optional[str] = None

class FGVIPRealServer(BaseModel):
    id: int
    ip: Optional[str] = None
    port: Optional[int] = None
    status: Optional[str] = None
    weight: Optional[int] = None
    holddown_interval: Optional[int] = None


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
    interface: str
    member: List[str] = Field(default_factory=list)

class FGPolicy(BaseModel):
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
    schedule: str = "always"
    service: List[str] = Field(default_factory=list)
    logtraffic: str = "utm"
    nat: str = "disable"
    ippool: str = "disable"
    poolname: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    status: str = "enable"
    # Security profiles
    utm_status: str = "disable"
    ssl_ssh_profile: Optional[str] = None
    av_profile: Optional[str] = None
    webfilter_profile: Optional[str] = None
    ips_sensor: Optional[str] = None
    application_list: Optional[str] = None
    internet_service: str = "disable"
    internet_service_name: List[str] = Field(default_factory=list)
    inspection_mode: Optional[str] = None
    ztna_status: Optional[str] = None
    ztna_ems_tag: List[str] = Field(default_factory=list)
    extra_settings: Dict[str, Any] = Field(default_factory=dict)

class FGPhase1Interface(BaseModel):
    name: str
    interface: str
    ike_version: str = "1"
    peertype: str = "any"
    net_device: str = "disable"
    proposal: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    remote_gw: Optional[str] = None
    psksecret: Optional[str] = None

class FGPhase2Interface(BaseModel):
    name: str
    phase1name: str
    proposal: List[str] = Field(default_factory=list)
    src_subnet: Optional[str] = None
    dst_subnet: Optional[str] = None
    comments: Optional[str] = None

class FGStaticRoute(BaseModel):
    id: int
    dst: Optional[str] = None
    gateway: Optional[str] = None
    device: Optional[str] = None
    distance: int = 10
    comment: Optional[str] = None
    sdwan_zone: Optional[str] = None
    blackhole: str = "disable"

class FGSDWanZone(BaseModel):
    name: str

class FGSDWanMember(BaseModel):
    id: int
    interface: str
    zone: str = "virtual-wan-link"

class FGSDWan(BaseModel):
    status: str = "disable"
    zones: List[FGSDWanZone] = Field(default_factory=list)
    members: List[FGSDWanMember] = Field(default_factory=list)

class FGDns(BaseModel):
    primary: Optional[str] = None
    secondary: Optional[str] = None


class FGSystemGlobal(BaseModel):
    hostname: str
    admin_sport: Optional[int] = None
    timezone: Optional[str] = None


class FGInternetService(BaseModel):
    name: str
    id: Optional[int] = None
    comment: Optional[str] = None


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

class FGConfig(BaseModel):
    """Root model for a parsed FortiGate configuration."""

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

    ip_pools: List[FGIPPool] = Field(default_factory=list)

    vips: List[FGVIP] = Field(default_factory=list)
    vip_groups: List[FGVIPGroup] = Field(default_factory=list)

    policies: List[FGPolicy] = Field(default_factory=list)

    phase1_interfaces: List[FGPhase1Interface] = Field(
        default_factory=list
    )
    phase2_interfaces: List[FGPhase2Interface] = Field(
        default_factory=list
    )

    certificates: List[FGCertificate] = Field(default_factory=list)

    static_routes: List[FGStaticRoute] = Field(default_factory=list)

    sdwan: Optional[FGSDWan] = None

    internet_services: List[FGInternetService] = Field(
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
