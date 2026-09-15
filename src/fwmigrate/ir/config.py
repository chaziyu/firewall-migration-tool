# Canonical IR aggregate root

from typing import Any, List, Optional
from pydantic import BaseModel, Field, model_validator
from .common import IRExecutionContext
from .metadata import IRAuditEntry, IRCheckpointManagementAccess, IRCheckpointPerformanceSettings, IRMetadata
from .network import IRCheckpointSICMetadata, IRDHCPServer, IRDNSSettings, IRHighAvailability, IRInterface, IRInterfaceGroup, IRNTPSettings, IRSystemSettings, IRZone
from .address import IRAddress, IRAddressGroup
from .service import IRApplication, IRApplicationCategory, IRApplicationGroup, IRInternetService, IRInternetServiceAddition, IRInternetServiceAppend, IRInternetServiceCustom, IRInternetServiceCustomGroup, IRInternetServiceDefinition, IRInternetServiceExtension, IRInternetServiceGroup, IRProxyAddress, IRSchedule, IRScheduleGroup, IRService, IRServiceCategory, IRServiceGroup, IRTrafficShaper, IRWebProxySettings
from .policy import IRCheckpointAccessLayer, IRCheckpointAccessRole, IRCheckpointAccessRule, IRCheckpointDomain, IRCheckpointGlobalAssignment, IRCheckpointIdentitySource, IRCheckpointPolicyPackage, IRCheckpointThreatPreventionProfile, IRCheckpointThreatPreventionRule, IRCustomURLCategory, IRDefaultSecurityRule, IRFirewallFilter, IRFortiGateSourceRule, IRHTTPSInspectionRule, IRIPSSensor, IRLocalDeviceAccessRule, IRMulticastPolicy, IRPolicy, IRSecurityProfileGroup, IRSessionHelper, IRSessionTTLOverride, IRSessionTTLSettings, IRZTNAProvider
from .nat import IRIPPool, IRNATRule, IRVirtualIP, IRVirtualIPGroup
from .routing import IRFortiGatePolicyRoute, IRManagementServiceRoute, IRPolicyBasedForwardingRule, IRPolicyRoute, IRRoute, IRSDWAN
from .vpn import IRVPNCommunity, IRVPNGateway, IRVPNPhase2, IRVPNTunnel
from .security_profiles import IRAdminProfile, IRAdministrator, IRAuthenticationRule, IRAuthenticationScheme, IRAuthenticationSequence, IRCertificate, IRDoSPolicy, IRFSSOADGroup, IRFSSOPolling, IRFSSOProvider, IRFirewallSniffer, IRFortiToken, IRGlobalProtectGateway, IRGlobalProtectNetworkGateway, IRGlobalProtectPortal, IRLocalUser, IRPANBotnetReportSettings, IRPANCustomReport, IRPANDNSProxy, IRPANDeviceOperationalSettings, IRPANHighAvailability, IRPANLogForwardingProfile, IRPANLogServerProfile, IRPANManagementLogSetting, IRPANMonitorProfile, IRPANQoSProfile, IRPANSDWANInterfaceProfile, IRPANSDWANLinkSettings, IRPANSDWANPathQualityProfile, IRPANSDWANRule, IRPANSDWANTrafficDistributionProfile, IRPANVirtualWire, IRPANVsysSettings, IRSSHKey, IRSSLTLSServiceProfile, IRSSLVPNHostCheck, IRSSLVPNPortal, IRSSLVPNSettings, IRSecurityProfileDefinition, IRUserAuthenticationSettings, IRUserGroup, IRUserLDAP, IRUserQuarantineSettings, IRUserRADIUS, IRUserSAML, IRUserTACACS


class IRConfig(BaseModel):
    generation_safe: bool = True
    generation_blocking_reasons: List[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    metadata: IRMetadata
    zones: List[IRZone] = Field(default_factory=list)
    interface_groups: List[IRInterfaceGroup] = Field(default_factory=list)
    interfaces: List[IRInterface] = Field(default_factory=list)
    high_availability: List[IRHighAvailability] = Field(default_factory=list)
    checkpoint_management_access: List[IRCheckpointManagementAccess] = Field(default_factory=list)
    checkpoint_performance: List[IRCheckpointPerformanceSettings] = Field(default_factory=list)
    checkpoint_policy_packages: List[IRCheckpointPolicyPackage] = Field(default_factory=list)
    checkpoint_access_layers: List[IRCheckpointAccessLayer] = Field(default_factory=list)
    checkpoint_domains: List[IRCheckpointDomain] = Field(default_factory=list)
    checkpoint_global_assignments: List[IRCheckpointGlobalAssignment] = Field(default_factory=list)
    addresses: List[IRAddress] = Field(default_factory=list)
    address_groups: List[IRAddressGroup] = Field(default_factory=list)
    service_categories: List[IRServiceCategory] = Field(default_factory=list)
    services: List[IRService] = Field(default_factory=list)
    service_groups: List[IRServiceGroup] = Field(default_factory=list)
    applications: List[IRApplication] = Field(default_factory=list)
    application_groups: List[IRApplicationGroup] = Field(default_factory=list)
    application_categories: List[IRApplicationCategory] = Field(default_factory=list)
    schedules: List[IRSchedule] = Field(default_factory=list)
    schedule_groups: List[IRScheduleGroup] = Field(default_factory=list)
    traffic_shapers: List[IRTrafficShaper] = Field(default_factory=list)
    proxy_addresses: List[IRProxyAddress] = Field(default_factory=list)
    web_proxy_settings: Optional[IRWebProxySettings] = None
    security_profile_groups: List[IRSecurityProfileGroup] = Field(default_factory=list)
    security_profile_definitions: List[IRSecurityProfileDefinition] = Field(default_factory=list)
    checkpoint_identity_sources: List[IRCheckpointIdentitySource] = Field(default_factory=list)
    checkpoint_access_roles: List[IRCheckpointAccessRole] = Field(default_factory=list)
    checkpoint_access_rules: List[IRCheckpointAccessRule] = Field(default_factory=list)
    checkpoint_threat_prevention_rules: List[IRCheckpointThreatPreventionRule] = Field(default_factory=list)
    checkpoint_threat_prevention_profiles: List[IRCheckpointThreatPreventionProfile] = Field(default_factory=list)
    https_inspection_rules: List[IRHTTPSInspectionRule] = Field(default_factory=list)
    custom_url_categories: List[IRCustomURLCategory] = Field(default_factory=list)
    ips_sensors: List[IRIPSSensor] = Field(default_factory=list)
    policies: List[IRPolicy] = Field(default_factory=list)
    default_security_rules: List[IRDefaultSecurityRule] = Field(default_factory=list)
    multicast_policies: List[IRMulticastPolicy] = Field(default_factory=list)
    ip_pools: List[IRIPPool] = Field(default_factory=list)
    virtual_ips: List[IRVirtualIP] = Field(default_factory=list)
    virtual_ip_groups: List[IRVirtualIPGroup] = Field(default_factory=list)
    nat_rules: List[IRNATRule] = Field(default_factory=list)
    pbf_rules: List[IRPolicyBasedForwardingRule] = Field(default_factory=list)
    policy_route_rules: List[IRPolicyRoute] = Field(default_factory=list)
    firewall_filters: List[IRFirewallFilter] = Field(default_factory=list)
    vpn_tunnels: List[IRVPNTunnel] = Field(default_factory=list)
    vpn_phase2: List[IRVPNPhase2] = Field(default_factory=list)
    vpn_communities: List[IRVPNCommunity] = Field(default_factory=list)
    vpn_gateways: List[IRVPNGateway] = Field(default_factory=list)
    certificates: List[IRCertificate] = Field(default_factory=list)
    checkpoint_sic_metadata: List[IRCheckpointSICMetadata] = Field(default_factory=list)
    ssh_keys: List[IRSSHKey] = Field(default_factory=list)
    system_settings: Optional[IRSystemSettings] = None
    dns_settings: Optional[IRDNSSettings] = None
    ntp_settings: Optional[IRNTPSettings] = None
    management_service_routes: List[IRManagementServiceRoute] = Field(default_factory=list)
    routes: List[IRRoute] = Field(default_factory=list)
    internet_services: List[IRInternetService] = Field(default_factory=list)
    internet_service_definitions: List[IRInternetServiceDefinition] = Field(default_factory=list)
    internet_service_additions: List[IRInternetServiceAddition] = Field(default_factory=list)
    internet_service_appends: List[IRInternetServiceAppend] = Field(default_factory=list)
    custom_internet_services: List[IRInternetServiceCustom] = Field(default_factory=list)
    custom_internet_service_groups: List[IRInternetServiceCustomGroup] = Field(default_factory=list)
    internet_service_extensions: List[IRInternetServiceExtension] = Field(default_factory=list)
    internet_service_groups: List[IRInternetServiceGroup] = Field(default_factory=list)
    audit_entries: List[IRAuditEntry] = Field(default_factory=list)
    ztna_providers: List[IRZTNAProvider] = Field(default_factory=list)
    session_helpers: List[IRSessionHelper] = Field(default_factory=list)
    session_ttl_overrides: List[IRSessionTTLOverride] = Field(default_factory=list)
    session_ttl_settings: Optional[IRSessionTTLSettings] = None
    execution_contexts: List[IRExecutionContext] = Field(default_factory=list)
    central_snat_rules: List[IRFortiGateSourceRule] = Field(default_factory=list)
    security_policies: List[IRFortiGateSourceRule] = Field(default_factory=list)
    policy_routes: List[IRFortiGatePolicyRoute] = Field(default_factory=list)
    local_in_policies: List[IRLocalDeviceAccessRule] = Field(default_factory=list)
    proxy_policies: List[IRFortiGateSourceRule] = Field(default_factory=list)
    shaping_policies: List[IRFortiGateSourceRule] = Field(default_factory=list)
    dhcp6_servers: List[IRFortiGateSourceRule] = Field(default_factory=list)
    source_only_rules: List[IRFortiGateSourceRule] = Field(default_factory=list)
    dhcp_servers: List[IRDHCPServer] = Field(default_factory=list)
    sdwans: List[IRSDWAN] = Field(default_factory=list)
    user_ldap_servers: List[IRUserLDAP] = Field(default_factory=list)
    user_radius_servers: List[IRUserRADIUS] = Field(default_factory=list)
    user_tacacs_servers: List[IRUserTACACS] = Field(default_factory=list)
    fsso_providers: List[IRFSSOProvider] = Field(default_factory=list)
    fsso_ad_groups: List[IRFSSOADGroup] = Field(default_factory=list)
    fsso_polling: List[IRFSSOPolling] = Field(default_factory=list)
    user_saml_servers: List[IRUserSAML] = Field(default_factory=list)
    local_users: List[IRLocalUser] = Field(default_factory=list)
    user_groups: List[IRUserGroup] = Field(default_factory=list)
    administrators: List[IRAdministrator] = Field(default_factory=list)
    admin_profiles: List[IRAdminProfile] = Field(default_factory=list)
    fortitokens: List[IRFortiToken] = Field(default_factory=list)
    ssl_vpn_portals: List[IRSSLVPNPortal] = Field(default_factory=list)
    ssl_vpn_host_checks: List[IRSSLVPNHostCheck] = Field(default_factory=list)
    ssl_vpn_settings: Optional[IRSSLVPNSettings] = None
    dos_policies: List[IRDoSPolicy] = Field(default_factory=list)
    firewall_sniffers: List[IRFirewallSniffer] = Field(default_factory=list)
    authentication_schemes: List[IRAuthenticationScheme] = Field(default_factory=list)
    authentication_sequences: List[IRAuthenticationSequence] = Field(default_factory=list)
    ssl_tls_service_profiles: List[IRSSLTLSServiceProfile] = Field(default_factory=list)
    authentication_rules: List[IRAuthenticationRule] = Field(default_factory=list)
    user_authentication_settings: Optional[IRUserAuthenticationSettings] = None
    user_quarantine_settings: Optional[IRUserQuarantineSettings] = None
    global_protect_portals: List[IRGlobalProtectPortal] = Field(default_factory=list)
    global_protect_gateways: List[IRGlobalProtectGateway] = Field(default_factory=list)
    global_protect_network_gateways: List[IRGlobalProtectNetworkGateway] = Field(default_factory=list)
    pan_log_server_profiles: List[IRPANLogServerProfile] = Field(default_factory=list)
    pan_log_forwarding_profiles: List[IRPANLogForwardingProfile] = Field(default_factory=list)
    pan_management_log_settings: List[IRPANManagementLogSetting] = Field(default_factory=list)
    pan_dns_proxies: List[IRPANDNSProxy] = Field(default_factory=list)
    pan_monitor_profiles: List[IRPANMonitorProfile] = Field(default_factory=list)
    pan_qos_profiles: List[IRPANQoSProfile] = Field(default_factory=list)
    pan_sdwan_interface_profiles: List[IRPANSDWANInterfaceProfile] = Field(default_factory=list)
    pan_sdwan_link_settings: List[IRPANSDWANLinkSettings] = Field(default_factory=list)
    pan_sdwan_path_quality_profiles: List[IRPANSDWANPathQualityProfile] = Field(default_factory=list)
    pan_sdwan_traffic_distribution_profiles: List[IRPANSDWANTrafficDistributionProfile] = Field(default_factory=list)
    pan_sdwan_rules: List[IRPANSDWANRule] = Field(default_factory=list)
    pan_high_availability: Optional[IRPANHighAvailability] = None
    pan_virtual_wires: List[IRPANVirtualWire] = Field(default_factory=list)
    pan_device_operational_settings: Optional[IRPANDeviceOperationalSettings] = None
    pan_vsys_settings: List[IRPANVsysSettings] = Field(default_factory=list)
    pan_botnet_report_settings: Optional[IRPANBotnetReportSettings] = None
    pan_custom_reports: List[IRPANCustomReport] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_sdwan_field(cls, value: Any) -> Any:
        """Accept the pre-VDOM single-SD-WAN field when constructing IRConfig."""
        if not isinstance(value, dict) or "sdwan" not in value:
            return value
        migrated = dict(value)
        legacy_sdwan = migrated.pop("sdwan")
        if "sdwans" not in migrated and legacy_sdwan is not None:
            migrated["sdwans"] = [legacy_sdwan]
        return migrated

    @property
    def sdwan(self) -> Optional[IRSDWAN]:
        """Backward-compatible access for unambiguous single-SD-WAN configs."""
        return self.sdwans[0] if len(self.sdwans) == 1 else None

    @property
    def identity_sources(self) -> List[IRCheckpointIdentitySource]:
        return self.checkpoint_identity_sources

    @property
    def access_roles(self) -> List[IRCheckpointAccessRole]:
        return self.checkpoint_access_roles

    @property
    def threat_prevention_rules(self) -> List[IRCheckpointThreatPreventionRule]:
        return self.checkpoint_threat_prevention_rules

    @property
    def threat_prevention_profiles(self) -> List[IRCheckpointThreatPreventionProfile]:
        return self.checkpoint_threat_prevention_profiles

__all__ = [
    "IRConfig",
]
