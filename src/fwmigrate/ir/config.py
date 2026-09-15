# Canonical IR aggregate root

from typing import Any, List, Literal, Optional
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
from .extensions import IRVendorExtensions
from .version import CURRENT_IR_SCHEMA_VERSION
from .common import IRVirtualFirewallContext
from .nat import IRNATPool, IRPublishedService, IRPublishedServiceGroup
from .policy import IRAccessRole, IREndpointContextProvider, IRIdentityMappingProvider, IRIdentitySource, IRManagementAccessPolicy, IRSecurityPolicy
from .routing import IRForwardingPolicy, IRPathMonitor
from .security_profiles import IRAuthenticationPolicy, IRAuthenticationProfile, IRDNSProxy, IRLogDestinationProfile, IRLogForwardingPolicy, IRMonitorProfile, IRQoSProfile, IRReportDefinition
from .service import IRProxyRequestMatch, IRWebProxy
from .vpn import IRRemoteAccessVPN


class IRConfig(BaseModel):
    schema_version: Literal[2] = CURRENT_IR_SCHEMA_VERSION
    generation_safe: bool = True
    generation_blocking_reasons: List[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    metadata: IRMetadata
    vendor_extensions: IRVendorExtensions = Field(default_factory=IRVendorExtensions)
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
    security_profile_groups: List[IRSecurityProfileGroup] = Field(default_factory=list)
    security_profile_definitions: List[IRSecurityProfileDefinition] = Field(default_factory=list)
    identity_sources: List[IRIdentitySource] = Field(default_factory=list)
    identity_mapping_providers: List[IRIdentityMappingProvider] = Field(default_factory=list)
    access_roles: List[IRAccessRole] = Field(default_factory=list)
    checkpoint_access_rules: List[IRCheckpointAccessRule] = Field(default_factory=list)
    checkpoint_threat_prevention_rules: List[IRCheckpointThreatPreventionRule] = Field(default_factory=list)
    checkpoint_threat_prevention_profiles: List[IRCheckpointThreatPreventionProfile] = Field(default_factory=list)
    https_inspection_rules: List[IRHTTPSInspectionRule] = Field(default_factory=list)
    custom_url_categories: List[IRCustomURLCategory] = Field(default_factory=list)
    ips_sensors: List[IRIPSSensor] = Field(default_factory=list)
    security_policies: List[IRPolicy] = Field(default_factory=list)
    default_security_rules: List[IRDefaultSecurityRule] = Field(default_factory=list)
    multicast_policies: List[IRMulticastPolicy] = Field(default_factory=list)
    nat_pools: List[IRNATPool] = Field(default_factory=list)
    published_services: List[IRPublishedService] = Field(default_factory=list)
    published_service_groups: List[IRPublishedServiceGroup] = Field(default_factory=list)
    nat_rules: List[IRNATRule] = Field(default_factory=list)
    forwarding_policies: List[IRForwardingPolicy] = Field(default_factory=list)
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
    endpoint_context_providers: List[IREndpointContextProvider] = Field(default_factory=list)
    session_helpers: List[IRSessionHelper] = Field(default_factory=list)
    session_ttl_overrides: List[IRSessionTTLOverride] = Field(default_factory=list)
    session_ttl_settings: Optional[IRSessionTTLSettings] = None
    virtual_firewall_contexts: List[IRVirtualFirewallContext] = Field(default_factory=list)
    central_snat_rules: List[IRFortiGateSourceRule] = Field(default_factory=list)
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
    authentication_profiles: List[IRAuthenticationProfile] = Field(default_factory=list)
    authentication_sequences: List[IRAuthenticationSequence] = Field(default_factory=list)
    ssl_tls_service_profiles: List[IRSSLTLSServiceProfile] = Field(default_factory=list)
    authentication_policies: List[IRAuthenticationPolicy] = Field(default_factory=list)
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
    path_monitors: List[IRPathMonitor] = Field(default_factory=list)
    remote_access_vpns: List[IRRemoteAccessVPN] = Field(default_factory=list)
    management_access_policies: List[IRManagementAccessPolicy] = Field(default_factory=list)
    proxy_request_matches: List[IRProxyRequestMatch] = Field(default_factory=list)
    web_proxies: List[IRWebProxy] = Field(default_factory=list)
    log_destination_profiles: List[IRLogDestinationProfile] = Field(default_factory=list)
    log_forwarding_policies: List[IRLogForwardingPolicy] = Field(default_factory=list)
    dns_proxies: List[IRDNSProxy] = Field(default_factory=list)
    monitor_profiles: List[IRMonitorProfile] = Field(default_factory=list)
    qos_profiles: List[IRQoSProfile] = Field(default_factory=list)
    report_definitions: List[IRReportDefinition] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_sdwan_field(cls, value: Any) -> Any:
        """Accept the pre-VDOM single-SD-WAN field when constructing IRConfig."""
        if not isinstance(value, dict):
            return value
        migrated = dict(value)
        aliases = {
            "execution_contexts": "virtual_firewall_contexts",
            "ip_pools": "nat_pools",
            "virtual_ips": "published_services",
            "virtual_ip_groups": "published_service_groups",
            "pbf_rules": "forwarding_policies",
            "checkpoint_identity_sources": "identity_sources",
            "checkpoint_access_roles": "access_roles",
            "authentication_schemes": "authentication_profiles",
            "authentication_rules": "authentication_policies",
            "proxy_addresses": "proxy_request_matches",
            "ztna_providers": "endpoint_context_providers",
        }
        for legacy, canonical in aliases.items():
            if legacy in migrated and canonical not in migrated:
                migrated[canonical] = migrated.pop(legacy)
        if "web_proxy_settings" in migrated and "web_proxies" not in migrated:
            web_proxy = migrated.pop("web_proxy_settings")
            migrated["web_proxies"] = [] if web_proxy is None else [web_proxy]
        if "policies" in migrated and "security_policies" not in migrated:
            migrated["security_policies"] = migrated.pop("policies")
        if "sdwan" in migrated:
            legacy_sdwan = migrated.pop("sdwan")
            if "sdwans" not in migrated and legacy_sdwan is not None:
                migrated["sdwans"] = [legacy_sdwan]
        return migrated

    @property
    def policies(self) -> List[IRPolicy]:
        return self.security_policies

    @property
    def execution_contexts(self) -> List[IRVirtualFirewallContext]:
        return self.virtual_firewall_contexts

    @property
    def ip_pools(self) -> List[IRNATPool]:
        return self.nat_pools

    @property
    def virtual_ips(self) -> List[IRPublishedService]:
        return self.published_services

    @property
    def virtual_ip_groups(self) -> List[IRPublishedServiceGroup]:
        return self.published_service_groups

    @property
    def pbf_rules(self) -> List[IRForwardingPolicy]:
        return self.forwarding_policies

    @property
    def checkpoint_identity_sources(self) -> List[IRIdentitySource]:
        return self.identity_sources

    @property
    def checkpoint_access_roles(self) -> List[IRAccessRole]:
        return self.access_roles

    @property
    def authentication_schemes(self) -> List[IRAuthenticationProfile]:
        return self.authentication_profiles

    @property
    def authentication_rules(self) -> List[IRAuthenticationPolicy]:
        return self.authentication_policies

    @property
    def proxy_addresses(self) -> List[IRProxyRequestMatch]:
        return self.proxy_request_matches

    @property
    def web_proxy_settings(self) -> Optional[IRWebProxy]:
        return self.web_proxies[0] if len(self.web_proxies) == 1 else None

    @property
    def ztna_providers(self) -> List[IREndpointContextProvider]:
        return self.endpoint_context_providers

    @property
    def sdwan(self) -> Optional[IRSDWAN]:
        """Backward-compatible access for unambiguous single-SD-WAN configs."""
        return self.sdwans[0] if len(self.sdwans) == 1 else None

    @property
    def threat_prevention_rules(self) -> List[IRCheckpointThreatPreventionRule]:
        return self.checkpoint_threat_prevention_rules

    @property
    def threat_prevention_profiles(self) -> List[IRCheckpointThreatPreventionProfile]:
        return self.checkpoint_threat_prevention_profiles

__all__ = [
    "IRConfig",
]
