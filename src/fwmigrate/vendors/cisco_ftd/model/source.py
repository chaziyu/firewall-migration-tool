"""Vendor-native cisco_ftd source models."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .address import CiscoFTDNetworkAddress, CiscoFTDNetworkAddressOverride, CiscoFTDNetworkGroup
from .identity import CiscoFTDDHCPRelaySettings, CiscoFTDDHCPServer, CiscoFTDFMCUser, CiscoFTDFMCUserRole, CiscoFTDGroupPolicy, CiscoFTDLocalRealmUser, CiscoFTDRealm, CiscoFTDRealmUser, CiscoFTDRealmUserGroup
from .inspection import CiscoFTDDNSPolicy, CiscoFTDDecryptionPolicy, CiscoFTDIntrusionPolicy, CiscoFTDIntrusionRuleBehavior, CiscoFTDIntrusionRuleGroup, CiscoFTDIntrusionRuleOverride
from .interface import CiscoFTDDeviceInterface, CiscoFTDInterface, CiscoFTDInterfaceGroup, CiscoFTDInterfaceSource, CiscoFTDManagementSetting, CiscoFTDSecurityZone, CiscoFTDStaticRoute
from .nat import CiscoFTDNATPolicy
from .policy import CiscoFTDAccessControlDefaultAction, CiscoFTDAccessControlLoggingSetting, CiscoFTDAccessControlPolicy, CiscoFTDAccessPolicyInheritanceSettings, CiscoFTDFilePolicy, CiscoFTDIdentityPolicy, CiscoFTDInspectorConfig, CiscoFTDInspectorOverrideConfig, CiscoFTDNetworkAnalysisPolicy, CiscoFTDPolicyAssignment, CiscoFTDPrefilterDefaultAction, CiscoFTDPrefilterPolicy, CiscoFTDPrefilterRule, CiscoFTDSecurityIntelligencePolicy, CiscoFTDTimeRange, CiscoFTDURLCategory, CiscoFTDVLANObject, CiscoFTDVariableSet
from .routing import CiscoFTDApplication, CiscoFTDECMPZone, CiscoFTDPolicyBasedRoute, CiscoFTDRoute, CiscoFTDSLAMonitor, CiscoFTDVirtualRouter
from .service import CiscoFTDPortObjectGroup, CiscoFTDProtocolPortObject
from .vpn import CiscoFTDAddressPool, CiscoFTDCertificate, CiscoFTDCertificateEnrollment, CiscoFTDCertificateMap, CiscoFTDIKEPolicy, CiscoFTDIPsecProposal, CiscoFTDLDAPAttributeMap, CiscoFTDNativeResource, CiscoFTDRAVPNAddressAssignmentSettings, CiscoFTDRAVPNConnectionProfile, CiscoFTDRAVPNIPsecCryptoMap, CiscoFTDRAVPNIPsecSettings, CiscoFTDRAVPNLoadBalanceSettings, CiscoFTDRAVPNPolicy, CiscoFTDS2SAdvancedSettings, CiscoFTDS2SIKESettings, CiscoFTDS2SIPsecSettings, CiscoFTDS2SVPNEndpoint, CiscoFTDS2SVPNTopology, CiscoFTDSecureClientSettings


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
    network_address_overrides: List[CiscoFTDNetworkAddressOverride] = Field(default_factory=list)
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
    access_control_logging_settings: List[CiscoFTDAccessControlLoggingSetting] = Field(default_factory=list)
    security_intelligence_policies: List[CiscoFTDSecurityIntelligencePolicy] = Field(default_factory=list)
    identity_policies: List[CiscoFTDIdentityPolicy] = Field(default_factory=list)
    access_control_default_actions: List[CiscoFTDAccessControlDefaultAction] = Field(default_factory=list)
    access_policy_inheritance_settings: List[CiscoFTDAccessPolicyInheritanceSettings] = Field(default_factory=list)
    policy_assignments: List[CiscoFTDPolicyAssignment] = Field(default_factory=list)
    nat_policies: List[CiscoFTDNATPolicy] = Field(default_factory=list)
    time_ranges: List[CiscoFTDTimeRange] = Field(default_factory=list)
    intrusion_policies: List[CiscoFTDIntrusionPolicy] = Field(default_factory=list)
    intrusion_rule_groups: List[CiscoFTDIntrusionRuleGroup] = Field(default_factory=list)
    intrusion_rule_behaviors: List[CiscoFTDIntrusionRuleBehavior] = Field(default_factory=list)
    intrusion_rule_overrides: List[CiscoFTDIntrusionRuleOverride] = Field(default_factory=list)
    file_policies: List[CiscoFTDFilePolicy] = Field(default_factory=list)
    decryption_policies: List[CiscoFTDDecryptionPolicy] = Field(default_factory=list)
    dns_policies: List[CiscoFTDDNSPolicy] = Field(default_factory=list)
    fmc_user_roles: List[CiscoFTDFMCUserRole] = Field(default_factory=list)
    fmc_users: List[CiscoFTDFMCUser] = Field(default_factory=list)
    dhcp_servers: List[CiscoFTDDHCPServer] = Field(default_factory=list)
    dhcp_relay_settings: List[CiscoFTDDHCPRelaySettings] = Field(default_factory=list)
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
