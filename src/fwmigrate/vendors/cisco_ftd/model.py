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
    management_only: Optional[bool] = None
    security_level: Optional[int] = None
    ip: Optional[str] = None
    mask: Optional[str] = None
    standby_ip: Optional[str] = None
    ipv6_addresses: List["CiscoFTDIPv6Address"] = Field(default_factory=list)
    description: Optional[str] = None
    mtu: Optional[int] = None
    shutdown: Optional[bool] = None
    explicit_fields: List[str] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDIPv6Address(BaseModel):
    address: str
    prefix_length: Optional[int] = None
    standby: Optional[str] = None
    eui64: Optional[bool] = None
    link_local: Optional[bool] = None
    raw: str


class CiscoFTDStaticRoute(BaseModel):
    name: str
    interface: Optional[str] = None
    destination: Optional[str] = None
    mask: Optional[str] = None
    gateway: Optional[str] = None
    address_family: Optional[str] = None
    administrative_distance: Optional[int] = None
    raw_line: str
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDSourceRecord(BaseModel):
    """Vendor-native record retained from one authoritative FTD source plane."""

    name: str
    source_id: Optional[str] = None
    source_plane: str
    source_context: Optional[str] = None
    domain_id: Optional[str] = None
    device_id: Optional[str] = None
    explicit_fields: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    raw_extra: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDReference(BaseModel):
    source_id: Optional[str] = None
    name: Optional[str] = None
    source_type: Optional[str] = None
    value: Optional[Any] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDNetworkAddress(CiscoFTDSourceRecord):
    address_type: Optional[str] = None
    value: Optional[Any] = None
    description: Optional[str] = None
    fqdn_lookup_type: Optional[str] = None
    address_family: Optional[str] = None
    override_metadata: Optional[Dict[str, Any]] = None


class CiscoFTDNetworkGroup(CiscoFTDSourceRecord):
    members: Optional[List[CiscoFTDReference]] = None
    literal_members: Optional[List[CiscoFTDReference]] = None
    description: Optional[str] = None
    override_metadata: Optional[Dict[str, Any]] = None


class CiscoFTDProtocolPortObject(CiscoFTDSourceRecord):
    protocol: Optional[str] = None
    ports: Optional[List[Any]] = None
    port: Optional[Any] = None
    end_port: Optional[Any] = None
    icmp_type: Optional[Any] = None
    icmp_code: Optional[Any] = None
    description: Optional[str] = None
    override_metadata: Optional[Dict[str, Any]] = None


class CiscoFTDPortObjectGroup(CiscoFTDSourceRecord):
    members: Optional[List[CiscoFTDReference]] = None
    description: Optional[str] = None
    override_metadata: Optional[Dict[str, Any]] = None


class CiscoFTDSecurityZone(CiscoFTDSourceRecord):
    interfaces: Optional[List[CiscoFTDReference]] = None


class CiscoFTDInterfaceGroup(CiscoFTDSourceRecord):
    interfaces: Optional[List[CiscoFTDReference]] = None


class CiscoFTDDeviceInterface(CiscoFTDSourceRecord):
    interface_type: Optional[str] = None
    address: Optional[str] = None
    zone: Optional[CiscoFTDReference] = None


class CiscoFTDInterfaceSource(CiscoFTDSourceRecord):
    interface_type: Optional[str] = None
    address: Optional[str] = None
    zone: Optional[str] = None
    management_only: Optional[bool] = None
    shutdown: Optional[bool] = None
    ipv6_addresses: Optional[List[CiscoFTDIPv6Address]] = None


class CiscoFTDRoute(CiscoFTDSourceRecord):
    interface: Optional[CiscoFTDReference] = None
    destination: Optional[CiscoFTDReference] = None
    gateway: Optional[CiscoFTDReference] = None
    address_family: Optional[str] = None
    metric: Optional[int] = None
    virtual_router: Optional[str] = None
    virtual_router_ref: Optional[CiscoFTDReference] = None
    sla_monitor: Optional[CiscoFTDReference] = None
    device_id: Optional[str] = None


class CiscoFTDApplication(CiscoFTDSourceRecord): pass
class CiscoFTDSLAMonitor(CiscoFTDSourceRecord): pass
class CiscoFTDVirtualRouter(CiscoFTDSourceRecord):
    interfaces: Optional[List[CiscoFTDReference]] = None


class CiscoFTDPolicyBasedRoute(CiscoFTDSourceRecord):
    virtual_router: Optional[CiscoFTDReference] = None
    ingress_interface: Optional[CiscoFTDReference] = None
    egress_interface: Optional[CiscoFTDReference] = None
    path_interface: Optional[CiscoFTDReference] = None
    networks: Optional[List[CiscoFTDReference]] = None
    sla_monitor: Optional[CiscoFTDReference] = None
    position: Optional[int] = None


class CiscoFTDECMPZone(CiscoFTDSourceRecord):
    interfaces: Optional[List[CiscoFTDReference]] = None


class CiscoFTDCertificate(CiscoFTDSourceRecord):
    certificate_type: Optional[str] = None
    source_collection: Optional[str] = None
    issuer: Optional[Any] = None
    subject: Optional[Any] = None
    validity: Optional[Dict[str, Any]] = None
    certificate_metadata: Optional[Dict[str, Any]] = None
    private_key_present: Optional[bool] = None


class CiscoFTDCertificateMap(CiscoFTDSourceRecord): pass
class CiscoFTDCertificateEnrollment(CiscoFTDSourceRecord): pass


class CiscoFTDAddressPool(CiscoFTDSourceRecord):
    address_family: Optional[str] = None
    source_representation: Optional[Any] = None
    start_address: Optional[str] = None
    end_address: Optional[str] = None
    override_metadata: Optional[Dict[str, Any]] = None


class CiscoFTDGroupPolicy(CiscoFTDSourceRecord):
    vpn_access: Optional[Any] = None
    realm: Optional[CiscoFTDReference] = None
    aaa_server_group: Optional[CiscoFTDReference] = None
    address_pools: Optional[List[CiscoFTDReference]] = None
    split_tunnel: Optional[List[CiscoFTDReference]] = None
    secure_client: Optional[List[CiscoFTDReference]] = None


class CiscoFTDS2SIKESettings(CiscoFTDSourceRecord):
    ike_policies: Optional[List[CiscoFTDReference]] = None
    certificates: Optional[List[CiscoFTDReference]] = None
    psk_present: Optional[bool] = None


class CiscoFTDS2SIPsecSettings(CiscoFTDSourceRecord):
    ipsec_proposals: Optional[List[CiscoFTDReference]] = None


class CiscoFTDS2SAdvancedSettings(CiscoFTDSourceRecord): pass
class CiscoFTDRAVPNIPsecSettings(CiscoFTDSourceRecord): pass
class CiscoFTDLDAPAttributeMap(CiscoFTDSourceRecord): pass
class CiscoFTDRAVPNLoadBalanceSettings(CiscoFTDSourceRecord): pass
class CiscoFTDRAVPNAddressAssignmentSettings(CiscoFTDSourceRecord):
    address_pools: Optional[List[CiscoFTDReference]] = None


class CiscoFTDSecureClientSettings(CiscoFTDSourceRecord): pass
class CiscoFTDRAVPNIPsecCryptoMap(CiscoFTDSourceRecord): pass
class CiscoFTDPrefilterPolicy(CiscoFTDSourceRecord): pass
class CiscoFTDPrefilterRule(CiscoFTDSourceRecord):
    position: Optional[int] = None
    action: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    references: Optional[List[CiscoFTDReference]] = None
class CiscoFTDPrefilterDefaultAction(CiscoFTDSourceRecord): pass
class CiscoFTDNetworkAnalysisPolicy(CiscoFTDSourceRecord): pass
class CiscoFTDInspectorConfig(CiscoFTDSourceRecord): pass
class CiscoFTDInspectorOverrideConfig(CiscoFTDSourceRecord): pass
class CiscoFTDFilePolicy(CiscoFTDSourceRecord): pass
class CiscoFTDVariableSet(CiscoFTDSourceRecord): pass
class CiscoFTDURLCategory(CiscoFTDSourceRecord): pass
class CiscoFTDVLANObject(CiscoFTDSourceRecord): pass


class CiscoFTDAccessControlRule(CiscoFTDSourceRecord):
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    enabled: Optional[bool] = None
    position: Optional[int] = None
    collection_order: Optional[int] = None
    section: Optional[str] = None
    category: Optional[str] = None
    action: Optional[str] = None
    comments: Optional[str] = None
    source_zones: Optional[List[CiscoFTDReference]] = None
    destination_zones: Optional[List[CiscoFTDReference]] = None
    source_networks: Optional[List[CiscoFTDReference]] = None
    destination_networks: Optional[List[CiscoFTDReference]] = None
    source_ports: Optional[List[CiscoFTDReference]] = None
    destination_ports: Optional[List[CiscoFTDReference]] = None
    source_dynamic_objects: Optional[List[CiscoFTDReference]] = None
    destination_dynamic_objects: Optional[List[CiscoFTDReference]] = None
    vlan_tags: Optional[List[CiscoFTDReference]] = None
    source_security_group_tags: Optional[List[CiscoFTDReference]] = None
    destination_security_group_tags: Optional[List[CiscoFTDReference]] = None
    realm: Optional[CiscoFTDReference] = None
    realm_users: Optional[List[CiscoFTDReference]] = None
    users: Optional[List[CiscoFTDReference]] = None
    user_groups: Optional[List[CiscoFTDReference]] = None
    applications: Optional[List[CiscoFTDReference]] = None
    application_filters: Optional[List[CiscoFTDReference]] = None
    inline_application_filters: Optional[List[CiscoFTDReference]] = None
    urls: Optional[Dict[str, Any]] = None
    url_categories: Optional[List[CiscoFTDReference]] = None
    time_range: Optional[CiscoFTDReference] = None
    intrusion_policy: Optional[CiscoFTDReference] = None
    variable_set: Optional[CiscoFTDReference] = None
    file_policy: Optional[CiscoFTDReference] = None
    log_begin: Optional[bool] = None
    log_end: Optional[bool] = None
    logging: Optional[Dict[str, Any]] = None


class CiscoFTDAccessControlPolicy(CiscoFTDSourceRecord):
    rules: Optional[List[CiscoFTDAccessControlRule]] = None
    prefilter_policy: Optional[CiscoFTDReference] = None
    network_analysis_policy: Optional[CiscoFTDReference] = None


class CiscoFTDFDMNATRule(CiscoFTDSourceRecord):
    """FDM-native NAT source record."""
    source_interface: Optional[CiscoFTDReference] = None
    destination_interface: Optional[CiscoFTDReference] = None
    original_source: Optional[CiscoFTDReference] = None
    translated_source: Optional[CiscoFTDReference] = None
    original_destination: Optional[CiscoFTDReference] = None
    translated_destination: Optional[CiscoFTDReference] = None
    service: Optional[CiscoFTDReference] = None
    rule_type: Optional[str] = None
    sequence: Optional[int] = None
    observed_collection_order: Optional[int] = None
    enabled: Optional[bool] = None
    source_translation_mode: Optional[str] = None
    destination_translation_mode: Optional[str] = None


class CiscoFTDManualNATRule(CiscoFTDSourceRecord):
    source_interface: Optional[CiscoFTDReference] = None
    destination_interface: Optional[CiscoFTDReference] = None
    original_source: Any = None
    translated_source: Any = None
    original_destination: Any = None
    translated_destination: Any = None
    original_source_port: Any = None
    translated_source_port: Any = None
    original_destination_port: Any = None
    translated_destination_port: Any = None
    original_source_service: Any = None
    translated_source_service: Any = None
    original_destination_service: Any = None
    translated_destination_service: Any = None
    nat_type: Optional[str] = None
    enabled: Optional[bool] = None
    section: Optional[str] = None
    position: Optional[int] = None
    observed_collection_order: Optional[int] = None
    identity_nat: Optional[bool] = None
    interface_pat: Optional[bool] = None
    dns: Optional[bool] = None
    route_lookup: Optional[bool] = None
    proxy_arp: Optional[bool] = None


class CiscoFTDAutoNATRule(CiscoFTDSourceRecord):
    source_interface: Optional[CiscoFTDReference] = None
    destination_interface: Optional[CiscoFTDReference] = None
    original_network: Any = None
    translated_network: Any = None
    owning_network: Any = None
    nat_type: Optional[str] = None
    enabled: Optional[bool] = None
    position: Optional[int] = None
    observed_collection_order: Optional[int] = None
    interface_pat: Optional[bool] = None
    dns: Optional[bool] = None
    route_lookup: Optional[bool] = None
    proxy_arp: Optional[bool] = None
    identity_nat: Optional[bool] = None


class CiscoFTDNATPolicy(CiscoFTDSourceRecord):
    manual_rules_before_auto: Optional[List[CiscoFTDManualNATRule]] = None
    auto_rules: Optional[List[CiscoFTDAutoNATRule]] = None
    manual_rules_after_auto: Optional[List[CiscoFTDManualNATRule]] = None
    unclassified_manual_rules: Optional[List[CiscoFTDManualNATRule]] = None
    # FDM exposes a different aggregate shape; keep it source-native and separate.
    rules: Optional[List[CiscoFTDFDMNATRule]] = None


class CiscoFTDTimeRange(CiscoFTDSourceRecord): pass
class CiscoFTDIntrusionPolicy(CiscoFTDSourceRecord): pass
class CiscoFTDIntrusionRuleOverride(CiscoFTDSourceRecord): pass
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
class CiscoFTDS2SVPNEndpoint(CiscoFTDSourceRecord):
    device: Optional[CiscoFTDReference] = None
    interface: Optional[CiscoFTDReference] = None
    vti: Optional[CiscoFTDReference] = None
    protected_networks: Optional[List[CiscoFTDReference]] = None
class CiscoFTDIKEPolicy(CiscoFTDSourceRecord):
    ike_version: Optional[str] = None


class CiscoFTDIPsecProposal(CiscoFTDSourceRecord):
    ike_version: Optional[str] = None
class CiscoFTDRAVPNPolicy(CiscoFTDSourceRecord):
    target_devices: Optional[List[CiscoFTDReference]] = None
    access_interfaces: Optional[List[CiscoFTDReference]] = None
    certificates: Optional[List[CiscoFTDReference]] = None
    connection_profiles: Optional[List[CiscoFTDReference]] = None
    group_policies: Optional[List[CiscoFTDReference]] = None
    address_pools: Optional[List[CiscoFTDReference]] = None
    realms: Optional[List[CiscoFTDReference]] = None


class CiscoFTDRAVPNConnectionProfile(CiscoFTDSourceRecord):
    parent_policy_id: Optional[str] = None
    realm: Optional[CiscoFTDReference] = None
    authorization: Optional[CiscoFTDReference] = None
    address_pools: Optional[List[CiscoFTDReference]] = None
    default_group_policy: Optional[CiscoFTDReference] = None
    certificates: Optional[List[CiscoFTDReference]] = None
    certificate_maps: Optional[List[CiscoFTDReference]] = None
class CiscoFTDNativeResource(CiscoFTDSourceRecord): pass


class CiscoFTDCollectionPart(BaseModel):
    name: str
    status: str
    complete: bool
    count: Optional[int] = None


class CiscoFTDCollectionMetadata(BaseModel):
    status: str = "UNKNOWN"
    provided: bool = False
    parts: List[CiscoFTDCollectionPart] = Field(default_factory=list)


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
    collection_metadata: CiscoFTDCollectionMetadata = Field(default_factory=CiscoFTDCollectionMetadata)
    network_addresses: List[CiscoFTDNetworkAddress] = Field(default_factory=list)
    network_groups: List[CiscoFTDNetworkGroup] = Field(default_factory=list)
    protocol_port_objects: List[CiscoFTDProtocolPortObject] = Field(default_factory=list)
    port_object_groups: List[CiscoFTDPortObjectGroup] = Field(default_factory=list)
    applications: List[CiscoFTDApplication] = Field(default_factory=list)
    sla_monitors: List[CiscoFTDSLAMonitor] = Field(default_factory=list)
    virtual_routers: List[CiscoFTDVirtualRouter] = Field(default_factory=list)
    policy_based_routes: List[CiscoFTDPolicyBasedRoute] = Field(default_factory=list)
    ecmp_zones: List[CiscoFTDECMPZone] = Field(default_factory=list)
    certificates: List[CiscoFTDCertificate] = Field(default_factory=list)
    certificate_maps: List[CiscoFTDCertificateMap] = Field(default_factory=list)
    certificate_enrollments: List[CiscoFTDCertificateEnrollment] = Field(default_factory=list)
    address_pools: List[CiscoFTDAddressPool] = Field(default_factory=list)
    group_policies: List[CiscoFTDGroupPolicy] = Field(default_factory=list)
    s2s_ike_settings: List[CiscoFTDS2SIKESettings] = Field(default_factory=list)
    s2s_ipsec_settings: List[CiscoFTDS2SIPsecSettings] = Field(default_factory=list)
    s2s_advanced_settings: List[CiscoFTDS2SAdvancedSettings] = Field(default_factory=list)
    ra_vpn_ipsec_settings: List[CiscoFTDRAVPNIPsecSettings] = Field(default_factory=list)
    ldap_attribute_maps: List[CiscoFTDLDAPAttributeMap] = Field(default_factory=list)
    ra_vpn_load_balance_settings: List[CiscoFTDRAVPNLoadBalanceSettings] = Field(default_factory=list)
    ra_vpn_address_assignment_settings: List[CiscoFTDRAVPNAddressAssignmentSettings] = Field(default_factory=list)
    secure_client_settings: List[CiscoFTDSecureClientSettings] = Field(default_factory=list)
    ra_vpn_ipsec_crypto_maps: List[CiscoFTDRAVPNIPsecCryptoMap] = Field(default_factory=list)
    prefilter_policies: List[CiscoFTDPrefilterPolicy] = Field(default_factory=list)
    prefilter_rules: List[CiscoFTDPrefilterRule] = Field(default_factory=list)
    prefilter_default_actions: List[CiscoFTDPrefilterDefaultAction] = Field(default_factory=list)
    network_analysis_policies: List[CiscoFTDNetworkAnalysisPolicy] = Field(default_factory=list)
    inspector_configs: List[CiscoFTDInspectorConfig] = Field(default_factory=list)
    inspector_override_configs: List[CiscoFTDInspectorOverrideConfig] = Field(default_factory=list)
    variable_sets: List[CiscoFTDVariableSet] = Field(default_factory=list)
    url_categories: List[CiscoFTDURLCategory] = Field(default_factory=list)
    vlan_objects: List[CiscoFTDVLANObject] = Field(default_factory=list)
    security_zones: List[CiscoFTDSecurityZone] = Field(default_factory=list)
    interface_groups: List[CiscoFTDInterfaceGroup] = Field(default_factory=list)
    device_interfaces: List[CiscoFTDDeviceInterface] = Field(default_factory=list)
    source_interfaces: List[CiscoFTDInterfaceSource] = Field(default_factory=list)
    routes: List[CiscoFTDRoute] = Field(default_factory=list)
    access_control_policies: List[CiscoFTDAccessControlPolicy] = Field(default_factory=list)
    nat_policies: List[CiscoFTDNATPolicy] = Field(default_factory=list)
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
