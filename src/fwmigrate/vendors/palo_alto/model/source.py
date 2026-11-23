from __future__ import annotations

from pydantic import BaseModel, Field

from ..source_model import PANExtractionIssue, PANScope, PANSourceRecord
from .administration import PANAdministrator, PANAdminRole
from .address import PANAddress, PANAddressGroup
from .dhcp import PANDHCPServer
from .globalprotect import PANGlobalProtectGateway, PANGlobalProtectPortal
from .identity import PANGroupMapping, PANLocalUser, PANLocalUserGroup
from .interface import PANInterface, PANInterfaceImport, PANInterfaceUnit
from .management_profile import PANInterfaceManagementProfile
from .nat import PANNATRule
from .policy import PANDefaultSecurityRule, PANSecurityRule
from .routing import PANLogicalRouter, PANVirtualRouter
from .schedule import PANSchedule
from .sdwan import (
    PANSDWANErrorCorrectionProfile,
    PANSDWANInterfaceProfile,
    PANSDWANPathQualityProfile,
    PANSDWANRule,
    PANSDWANSaaSQualityProfile,
    PANSDWANTrafficDistributionProfile,
)
from .security_profile import PANSecurityProfileGroup, PANVulnerabilityProfile
from .service import PANService, PANServiceGroup
from .tag import PANTag
from .vpn import PANIKECryptoProfile, PANIKEGateway, PANIPsecCryptoProfile, PANIPsecTunnel
from .zone import PANZone
from .extended_sections import (
    PANSystemSettings, PANHAConfig, PANDeviceSetupSetting,
    PANQoSRule, PANPBFRule, PANDecryptionRule, PANTunnelInspectRule,
    PANAppOverrideRule, PANAuthenticationRule, PANDoSRule,
    PANApplicationGroup, PANRegion, PANDynamicUserGroup,
    PANHIPObject, PANHIPProfile, PANExternalList, PANCustomURLCategory,
    PANDataPattern, PANCustomThreat,
    PANAntivirusProfile, PANAntiSpywareProfile, PANURLFilteringProfile,
    PANFileBlockingProfile, PANWildFireProfile, PANDataFilteringProfile,
    PANDoSProtectionProfile, PANDecryptionProfile, PANLogForwardingProfile,
    PANAuthenticationProfile, PANAuthenticationSequence,
    PANVLAN, PANVirtualWire, PANGRETunnel, PANDNSProxy,
    PANQoSInterface, PANQoSProfile,
    PANZoneProtectionProfile, PANMonitorProfile, PANLLDPProfile, PANBFDProfile,
    PANGlobalProtectClientlessApp, PANGlobalProtectClientlessAppGroup, PANGlobalProtectMDM,
    PANRadiusServerProfile, PANLDAPServerProfile, PANTACPlusServerProfile,
    PANKerberosServerProfile, PANSAMLIdPServerProfile, PANMFAServerProfile,
    PANCertificate, PANSSLTLSServiceProfile,
    PANSyslogServerProfile, PANEmailServerProfile, PANSNMPTrapServerProfile,
    PANHTTPServerProfile, PANNetflowServerProfile,
    PANPasswordComplexity, PANPasswordProfile, PANUserIDAgent,
    PANDeviceObject, PANSCPServerProfile, PANSSHServerProfile,
    PANUserIDSetting, PANLogSettingCategory,
)


class PANOSConfig(BaseModel):
    """Typed, explicit PAN-OS source state plus source inventory evidence."""

    hostname: str | None = None
    source_version: str | None = None
    source_format: str = "xml"
    scopes: list[PANScope] = Field(default_factory=list)

    tags: list[PANTag] = Field(default_factory=list)
    addresses: list[PANAddress] = Field(default_factory=list)
    address_groups: list[PANAddressGroup] = Field(default_factory=list)
    services: list[PANService] = Field(default_factory=list)
    service_groups: list[PANServiceGroup] = Field(default_factory=list)
    schedules: list[PANSchedule] = Field(default_factory=list)
    security_rules: list[PANSecurityRule] = Field(default_factory=list)
    default_security_rules: list[PANDefaultSecurityRule] = Field(default_factory=list)
    interfaces: list[PANInterface] = Field(default_factory=list)
    interface_imports: list[PANInterfaceImport] = Field(default_factory=list)
    interface_units: list[PANInterfaceUnit] = Field(default_factory=list)
    management_profiles: list[PANInterfaceManagementProfile] = Field(default_factory=list)
    nat_rules: list[PANNATRule] = Field(default_factory=list)
    vulnerability_profiles: list[PANVulnerabilityProfile] = Field(default_factory=list)
    security_profile_groups: list[PANSecurityProfileGroup] = Field(default_factory=list)
    zones: list[PANZone] = Field(default_factory=list)
    virtual_routers: list[PANVirtualRouter] = Field(default_factory=list)
    logical_routers: list[PANLogicalRouter] = Field(default_factory=list)
    dhcp_servers: list[PANDHCPServer] = Field(default_factory=list)
    sdwan_interface_profiles: list[PANSDWANInterfaceProfile] = Field(default_factory=list)
    sdwan_path_quality_profiles: list[PANSDWANPathQualityProfile] = Field(default_factory=list)
    sdwan_traffic_distribution_profiles: list[PANSDWANTrafficDistributionProfile] = Field(default_factory=list)
    sdwan_saas_quality_profiles: list[PANSDWANSaaSQualityProfile] = Field(default_factory=list)
    sdwan_error_correction_profiles: list[PANSDWANErrorCorrectionProfile] = Field(default_factory=list)
    sdwan_rules: list[PANSDWANRule] = Field(default_factory=list)
    local_users: list[PANLocalUser] = Field(default_factory=list)
    local_user_groups: list[PANLocalUserGroup] = Field(default_factory=list)
    group_mappings: list[PANGroupMapping] = Field(default_factory=list)
    administrators: list[PANAdministrator] = Field(default_factory=list)
    admin_roles: list[PANAdminRole] = Field(default_factory=list)
    ike_gateways: list[PANIKEGateway] = Field(default_factory=list)
    ike_crypto_profiles: list[PANIKECryptoProfile] = Field(default_factory=list)
    ipsec_crypto_profiles: list[PANIPsecCryptoProfile] = Field(default_factory=list)
    ipsec_tunnels: list[PANIPsecTunnel] = Field(default_factory=list)
    globalprotect_portals: list[PANGlobalProtectPortal] = Field(default_factory=list)
    globalprotect_gateways: list[PANGlobalProtectGateway] = Field(default_factory=list)

    # System / Setup / HA
    system_settings: list[PANSystemSettings] = Field(default_factory=list)
    ha_configs: list[PANHAConfig] = Field(default_factory=list)
    device_setup_settings: list[PANDeviceSetupSetting] = Field(default_factory=list)

    # Extended Policy Families
    qos_rules: list[PANQoSRule] = Field(default_factory=list)
    pbf_rules: list[PANPBFRule] = Field(default_factory=list)
    decryption_rules: list[PANDecryptionRule] = Field(default_factory=list)
    tunnel_inspect_rules: list[PANTunnelInspectRule] = Field(default_factory=list)
    app_override_rules: list[PANAppOverrideRule] = Field(default_factory=list)
    authentication_rules: list[PANAuthenticationRule] = Field(default_factory=list)
    dos_rules: list[PANDoSRule] = Field(default_factory=list)

    # Extended Objects & Security Profiles
    application_groups: list[PANApplicationGroup] = Field(default_factory=list)
    regions: list[PANRegion] = Field(default_factory=list)
    dynamic_user_groups: list[PANDynamicUserGroup] = Field(default_factory=list)
    hip_objects: list[PANHIPObject] = Field(default_factory=list)
    hip_profiles: list[PANHIPProfile] = Field(default_factory=list)
    external_lists: list[PANExternalList] = Field(default_factory=list)
    custom_url_categories: list[PANCustomURLCategory] = Field(default_factory=list)
    data_patterns: list[PANDataPattern] = Field(default_factory=list)
    custom_threats: list[PANCustomThreat] = Field(default_factory=list)
    antivirus_profiles: list[PANAntivirusProfile] = Field(default_factory=list)
    anti_spyware_profiles: list[PANAntiSpywareProfile] = Field(default_factory=list)
    url_filtering_profiles: list[PANURLFilteringProfile] = Field(default_factory=list)
    file_blocking_profiles: list[PANFileBlockingProfile] = Field(default_factory=list)
    wildfire_profiles: list[PANWildFireProfile] = Field(default_factory=list)
    data_filtering_profiles: list[PANDataFilteringProfile] = Field(default_factory=list)
    dos_protection_profiles: list[PANDoSProtectionProfile] = Field(default_factory=list)
    decryption_profiles: list[PANDecryptionProfile] = Field(default_factory=list)
    log_forwarding_profiles: list[PANLogForwardingProfile] = Field(default_factory=list)
    authentication_profiles: list[PANAuthenticationProfile] = Field(default_factory=list)
    authentication_sequences: list[PANAuthenticationSequence] = Field(default_factory=list)

    # Network Extensions
    vlans: list[PANVLAN] = Field(default_factory=list)
    virtual_wires: list[PANVirtualWire] = Field(default_factory=list)
    gre_tunnels: list[PANGRETunnel] = Field(default_factory=list)
    dns_proxies: list[PANDNSProxy] = Field(default_factory=list)
    qos_interfaces: list[PANQoSInterface] = Field(default_factory=list)
    qos_profiles: list[PANQoSProfile] = Field(default_factory=list)
    zone_protection_profiles: list[PANZoneProtectionProfile] = Field(default_factory=list)
    monitor_profiles: list[PANMonitorProfile] = Field(default_factory=list)
    lldp_profiles: list[PANLLDPProfile] = Field(default_factory=list)
    bfd_profiles: list[PANBFDProfile] = Field(default_factory=list)
    gp_clientless_apps: list[PANGlobalProtectClientlessApp] = Field(default_factory=list)
    gp_clientless_app_groups: list[PANGlobalProtectClientlessAppGroup] = Field(default_factory=list)
    gp_mdms: list[PANGlobalProtectMDM] = Field(default_factory=list)

    # Device, Auth Server, Certificate & Log Server Profiles
    radius_server_profiles: list[PANRadiusServerProfile] = Field(default_factory=list)
    ldap_server_profiles: list[PANLDAPServerProfile] = Field(default_factory=list)
    tacplus_server_profiles: list[PANTACPlusServerProfile] = Field(default_factory=list)
    kerberos_server_profiles: list[PANKerberosServerProfile] = Field(default_factory=list)
    saml_idp_server_profiles: list[PANSAMLIdPServerProfile] = Field(default_factory=list)
    mfa_server_profiles: list[PANMFAServerProfile] = Field(default_factory=list)
    certificates: list[PANCertificate] = Field(default_factory=list)
    ssl_tls_service_profiles: list[PANSSLTLSServiceProfile] = Field(default_factory=list)
    syslog_server_profiles: list[PANSyslogServerProfile] = Field(default_factory=list)
    email_server_profiles: list[PANEmailServerProfile] = Field(default_factory=list)
    snmptrap_server_profiles: list[PANSNMPTrapServerProfile] = Field(default_factory=list)
    http_server_profiles: list[PANHTTPServerProfile] = Field(default_factory=list)
    netflow_server_profiles: list[PANNetflowServerProfile] = Field(default_factory=list)
    password_complexities: list[PANPasswordComplexity] = Field(default_factory=list)
    password_profiles: list[PANPasswordProfile] = Field(default_factory=list)
    user_id_agents: list[PANUserIDAgent] = Field(default_factory=list)
    device_objects: list[PANDeviceObject] = Field(default_factory=list)
    scp_server_profiles: list[PANSCPServerProfile] = Field(default_factory=list)
    ssh_server_profiles: list[PANSSHServerProfile] = Field(default_factory=list)
    user_id_settings: list[PANUserIDSetting] = Field(default_factory=list)
    log_setting_categories: list[PANLogSettingCategory] = Field(default_factory=list)

    source_inventory: list[PANSourceRecord] = Field(default_factory=list)
    unknown_paths: list[str] = Field(default_factory=list)
    extraction_issues: list[PANExtractionIssue] = Field(default_factory=list)
