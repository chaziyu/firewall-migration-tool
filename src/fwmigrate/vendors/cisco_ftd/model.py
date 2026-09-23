from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CiscoFTDManagementSetting(BaseModel):
    name: str
    setting: str
    values: List[str] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDInterface(BaseModel):
    name: str
    interface_type: Optional[str] = None
    parent_interface: Optional[str] = None
    vlan_id: Optional[int] = None
    etherchannel_id: Optional[int] = None
    etherchannel_mode: Optional[str] = None
    bridge_group: Optional[int] = None
    nameif: Optional[str] = None
    management_only: bool = False
    security_level: Optional[int] = None
    ip: Optional[str] = None
    mask: Optional[str] = None
    standby_ip: Optional[str] = None
    ipv6_addresses: List["CiscoFTDIPv6Address"] = Field(default_factory=list)
    description: Optional[str] = None
    mtu: Optional[int] = None
    shutdown: bool = False
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDIPv6Address(BaseModel):
    address: str
    prefix_length: Optional[int] = None
    standby: Optional[str] = None
    eui64: bool = False
    link_local: bool = False
    raw: str


class CiscoFTDStaticRoute(BaseModel):
    name: str
    interface: Optional[str] = None
    destination: Optional[str] = None
    mask: Optional[str] = None
    gateway: Optional[str] = None
    address_family: str = "ipv4"
    administrative_distance: Optional[int] = None
    raw_line: str
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDSourceRecord(BaseModel):
    """Vendor-native record retained from one authoritative FTD source plane."""

    name: str
    source_id: Optional[str] = None
    source_plane: str
    source_context: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    raw: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDObject(CiscoFTDSourceRecord):
    object_type: Optional[str] = None
    value: Optional[Any] = None
    members: List[str] = Field(default_factory=list)


class CiscoFTDService(CiscoFTDSourceRecord):
    protocol: Optional[str] = None
    ports: List[Any] = Field(default_factory=list)
    members: List[str] = Field(default_factory=list)


class CiscoFTDZone(CiscoFTDSourceRecord):
    interfaces: List[str] = Field(default_factory=list)


class CiscoFTDInterfaceSource(CiscoFTDSourceRecord):
    interface_type: Optional[str] = None
    address: Optional[str] = None
    zone: Optional[str] = None


class CiscoFTDRoute(CiscoFTDSourceRecord):
    interface: Optional[str] = None
    destination: Optional[str] = None
    gateway: Optional[str] = None
    address_family: Optional[str] = None
    metric: Optional[int] = None
    virtual_router: Optional[str] = None
    sla_monitor: Optional[str] = None
    device_id: Optional[str] = None


class CiscoFTDACPRule(CiscoFTDSourceRecord):
    policy: Optional[str] = None
    action: Optional[str] = None
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    source_zones: List[str] = Field(default_factory=list)
    destination_zones: List[str] = Field(default_factory=list)
    order: Optional[int] = None


class CiscoFTDACPolicy(CiscoFTDSourceRecord): pass


class CiscoFTDNATRule(CiscoFTDSourceRecord):
    policy: Optional[str] = None
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    original: Dict[str, Any] = Field(default_factory=dict)
    translated: Dict[str, Any] = Field(default_factory=dict)
    order: Optional[int] = None
    nat_type: Optional[str] = None
    enabled: Optional[bool] = None
    section: Optional[str] = None


class CiscoFTDTimeRange(CiscoFTDSourceRecord): pass
class CiscoFTDIntrusionPolicy(CiscoFTDSourceRecord): pass
class CiscoFTDIntrusionRuleOverride(CiscoFTDSourceRecord): pass
class CiscoFTDFilePolicy(CiscoFTDSourceRecord): pass
class CiscoFTDDecryptionPolicy(CiscoFTDSourceRecord): pass
class CiscoFTDDNSPolicy(CiscoFTDSourceRecord): pass
class CiscoFTDFMCUserRole(CiscoFTDSourceRecord): pass
class CiscoFTDFMCUser(CiscoFTDSourceRecord): pass
class CiscoFTDDHCPServer(CiscoFTDSourceRecord): pass
class CiscoFTDRealm(CiscoFTDSourceRecord): pass
class CiscoFTDRealmUserGroup(CiscoFTDSourceRecord): pass
class CiscoFTDRealmUser(CiscoFTDSourceRecord): pass
class CiscoFTDLocalRealmUser(CiscoFTDSourceRecord): pass
class CiscoFTDS2SVPNTopology(CiscoFTDSourceRecord): pass
class CiscoFTDS2SVPNEndpoint(CiscoFTDSourceRecord): pass
class CiscoFTDIKEPolicy(CiscoFTDSourceRecord): pass
class CiscoFTDIPsecProposal(CiscoFTDSourceRecord): pass
class CiscoFTDRAVPNPolicy(CiscoFTDSourceRecord): pass
class CiscoFTDRAVPNConnectionProfile(CiscoFTDSourceRecord): pass
class CiscoFTDNativeResource(CiscoFTDSourceRecord): pass


class CiscoFTDConfig(BaseModel):
    source_vendor: str = "cisco_ftd"
    source_product: str = "Cisco Firepower Threat Defense"
    version: Optional[str] = None
    cmi_enabled: Optional[bool] = None
    management_ipv4: Optional[str] = None
    management_netmask: Optional[str] = None
    management_gateway: Optional[str] = None
    management_dns_servers: List[str] = Field(default_factory=list)
    ssh_access_list: List[str] = Field(default_factory=list)
    diagnostic_interface: Optional[str] = None
    interfaces: List[CiscoFTDInterface] = Field(default_factory=list)
    static_routes: List[CiscoFTDStaticRoute] = Field(default_factory=list)
    management_settings: List[CiscoFTDManagementSetting] = Field(default_factory=list)
    input_source_type: str = "ftd-text-evidence"
    source_plane: str = "ftd-cli"
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    managed_objects: List[CiscoFTDObject] = Field(default_factory=list)
    object_groups: List[CiscoFTDObject] = Field(default_factory=list)
    services: List[CiscoFTDService] = Field(default_factory=list)
    security_zones: List[CiscoFTDZone] = Field(default_factory=list)
    source_interfaces: List[CiscoFTDInterfaceSource] = Field(default_factory=list)
    routes: List[CiscoFTDRoute] = Field(default_factory=list)
    acp_rules: List[CiscoFTDACPRule] = Field(default_factory=list)
    acp_policies: List[CiscoFTDACPolicy] = Field(default_factory=list)
    nat_policies: List[CiscoFTDNATRule] = Field(default_factory=list)
    time_ranges: List[CiscoFTDTimeRange] = Field(default_factory=list)
    intrusion_policies: List[CiscoFTDIntrusionPolicy] = Field(default_factory=list)
    intrusion_rule_overrides: List[CiscoFTDIntrusionRuleOverride] = Field(default_factory=list)
    file_policies: List[CiscoFTDFilePolicy] = Field(default_factory=list)
    decryption_policies: List[CiscoFTDDecryptionPolicy] = Field(default_factory=list)
    dns_policies: List[CiscoFTDDNSPolicy] = Field(default_factory=list)
    fmc_user_roles: List[CiscoFTDFMCUserRole] = Field(default_factory=list)
    fmc_users: List[CiscoFTDFMCUser] = Field(default_factory=list)
    dhcp_servers: List[CiscoFTDDHCPServer] = Field(default_factory=list)
    realms: List[CiscoFTDRealm] = Field(default_factory=list)
    realm_user_groups: List[CiscoFTDRealmUserGroup] = Field(default_factory=list)
    realm_users: List[CiscoFTDRealmUser] = Field(default_factory=list)
    local_realm_users: List[CiscoFTDLocalRealmUser] = Field(default_factory=list)
    s2s_vpn_topologies: List[CiscoFTDS2SVPNTopology] = Field(default_factory=list)
    s2s_vpn_endpoints: List[CiscoFTDS2SVPNEndpoint] = Field(default_factory=list)
    ike_policies: List[CiscoFTDIKEPolicy] = Field(default_factory=list)
    ipsec_proposals: List[CiscoFTDIPsecProposal] = Field(default_factory=list)
    ra_vpn_policies: List[CiscoFTDRAVPNPolicy] = Field(default_factory=list)
    ra_vpn_connection_profiles: List[CiscoFTDRAVPNConnectionProfile] = Field(default_factory=list)
    native_resources: List[CiscoFTDNativeResource] = Field(default_factory=list)
    unsupported_evidence: List[Dict[str, Any]] = Field(default_factory=list)
