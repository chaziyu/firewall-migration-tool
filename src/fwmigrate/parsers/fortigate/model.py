from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from fwmigrate.extraction.models import ExtractionReport, SourceObjectResult

class FGInterface(BaseModel):
    name: str
    vdom: str = "root"
    ip: Optional[str] = None
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
    type: str = "ipmask"  # ipmask, fqdn, iprange, dynamic
    subnet: Optional[str] = None  # e.g. "192.168.1.0 255.255.255.0"
    fqdn: Optional[str] = None
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    comment: Optional[str] = None
    macaddr: Optional[str] = None
    mac: Optional[str] = None
    # For dynamic addresses (e.g. EMS tags)
    sub_type: Optional[str] = None
    ems_tag_name: Optional[str] = None
    sdn: Optional[str] = None
    filter: Optional[str] = None
    is_ipv6: bool = False
    is_multicast: bool = False

class FGAddressGroup(BaseModel):
    name: str
    member: List[str] = Field(default_factory=list)
    comment: Optional[str] = None

class FGWildcardFQDN(BaseModel):
    name: str
    wildcard_fqdn: str
    comment: Optional[str] = None

class FGService(BaseModel):
    name: str
    protocol: str = "tcp/udp/sctp"  # default
    tcp_portrange: Optional[str] = None
    udp_portrange: Optional[str] = None
    protocol_number: Optional[int] = None
    icmpcode: Optional[int] = None
    icmptype: Optional[int] = None
    comment: Optional[str] = None

class FGServiceGroup(BaseModel):
    name: str
    member: List[str] = Field(default_factory=list)
    comment: Optional[str] = None

class FGSchedule(BaseModel):
    name: str
    type: str = "recurring"
    start: Optional[str] = None
    end: Optional[str] = None
    day: List[str] = Field(default_factory=list)

class FGNATSource(BaseModel):
    source_record: Optional[SourceObjectResult] = None

class FGIPPool(FGNATSource):
    name: str
    startip: str
    endip: str
    comments: Optional[str] = None
    type: str = "overload"

class FGVIP(FGNATSource):
    name: str
    extip: str
    mappedip: str
    extintf: str = "any"
    portforward: str = "disable"
    extport: Optional[str] = None
    mappedport: Optional[str] = None
    comment: Optional[str] = None
    protocol: str = "tcp"
    type: str = "static-nat"
    src_filter: List[str] = Field(default_factory=list)
    srcintf_filter: List[str] = Field(default_factory=list)
    status: str = "enable"

class FGVIPGroup(FGNATSource):
    name: str
    interface: str = "any"
    member: List[str] = Field(default_factory=list)

class FGPolicy(FGNATSource):
    id: int
    name: Optional[str] = None
    srcintf: List[str] = Field(default_factory=list)
    dstintf: List[str] = Field(default_factory=list)
    srcaddr: List[str] = Field(default_factory=list)
    dstaddr: List[str] = Field(default_factory=list)
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

class FGCentralSNAT(FGNATSource):
    id: int
    srcintf: List[str] = Field(default_factory=list)
    dstintf: List[str] = Field(default_factory=list)
    orig_addr: List[str] = Field(default_factory=list)
    dst_addr: List[str] = Field(default_factory=list)
    nat_ippool: List[str] = Field(default_factory=list)
    nat: str = "enable"
    status: str = "enable"
    type: str = "ipv4"
    protocol: int = Field(default=0, ge=0, le=255)
    orig_port: Optional[str] = None
    dst_port: Optional[str] = None
    nat_port: Optional[str] = None
    port_preserve: str = "enable"
    comments: Optional[str] = None

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

class FGConfig(BaseModel):
    """Root model for a parsed FortiGate configuration."""
    system_global: Optional[FGSystemGlobal] = None
    dns: Optional[FGDns] = None
    system_zones: List[FGSystemZone] = Field(default_factory=list)
    interfaces: List[FGInterface] = Field(default_factory=list)
    addresses: List[FGAddress] = Field(default_factory=list)
    address_groups: List[FGAddressGroup] = Field(default_factory=list)
    wildcard_fqdns: List[FGWildcardFQDN] = Field(default_factory=list)
    services: List[FGService] = Field(default_factory=list)
    service_groups: List[FGServiceGroup] = Field(default_factory=list)
    schedules: List[FGSchedule] = Field(default_factory=list)
    ip_pools: List[FGIPPool] = Field(default_factory=list)
    vips: List[FGVIP] = Field(default_factory=list)
    vip_groups: List[FGVIPGroup] = Field(default_factory=list)
    policies: List[FGPolicy] = Field(default_factory=list)
    phase1_interfaces: List[FGPhase1Interface] = Field(default_factory=list)
    phase2_interfaces: List[FGPhase2Interface] = Field(default_factory=list)
    static_routes: List[FGStaticRoute] = Field(default_factory=list)
    sdwan: Optional[FGSDWan] = None
    internet_services: List[FGInternetService] = Field(default_factory=list)
    central_snat: List[FGCentralSNAT] = Field(default_factory=list)
    settings_by_scope: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    scopes: List[str] = Field(default_factory=list)
    source_version: Optional[str] = None
    extraction: ExtractionReport = Field(default_factory=ExtractionReport)
