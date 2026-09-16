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
from .extensions import (
    IRCheckPointInterfaceExtension,
    IRCheckPointNATPoolExtension,
    IRCheckPointNATRuleExtension,
    IRCheckPointObjectExtension,
    IRCheckPointPolicyExtension,
    IRFortiOSAddressExtension,
    IRFortiOSNATPoolExtension,
    IRFortiOSNATRuleExtension,
    IRFortiOSPolicyExtension,
    IRVendorExtensions,
    normalize_transitional_v2_payload,
)
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
    security_profile_groups: List[IRSecurityProfileGroup] = Field(default_factory=list)
    security_profile_definitions: List[IRSecurityProfileDefinition] = Field(default_factory=list)
    identity_sources: List[IRIdentitySource] = Field(default_factory=list)
    identity_mapping_providers: List[IRIdentityMappingProvider] = Field(default_factory=list)
    access_roles: List[IRAccessRole] = Field(default_factory=list)
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
    ssh_keys: List[IRSSHKey] = Field(default_factory=list)
    system_settings: Optional[IRSystemSettings] = None
    dns_settings: Optional[IRDNSSettings] = None
    ntp_settings: Optional[IRNTPSettings] = None
    management_service_routes: List[IRManagementServiceRoute] = Field(default_factory=list)
    routes: List[IRRoute] = Field(default_factory=list)
    audit_entries: List[IRAuditEntry] = Field(default_factory=list)
    endpoint_context_providers: List[IREndpointContextProvider] = Field(default_factory=list)
    virtual_firewall_contexts: List[IRVirtualFirewallContext] = Field(default_factory=list)
    dhcp_servers: List[IRDHCPServer] = Field(default_factory=list)
    authentication_profiles: List[IRAuthenticationProfile] = Field(default_factory=list)
    authentication_sequences: List[IRAuthenticationSequence] = Field(default_factory=list)
    authentication_policies: List[IRAuthenticationPolicy] = Field(default_factory=list)
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
        """Normalize legacy aliases and transitional vendor roots."""
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
        return normalize_transitional_v2_payload(migrated)

    def sync_vendor_extensions(self, *, clear_embedded: bool = False) -> None:
        """Promote embedded typed extensions into the aggregate extension store."""
        destinations = (
            ("addresses", "object_extensions", IRCheckPointObjectExtension),
            ("services", "object_extensions", IRCheckPointObjectExtension),
            ("applications", "object_extensions", IRCheckPointObjectExtension),
            ("application_groups", "object_extensions", IRCheckPointObjectExtension),
            ("application_categories", "object_extensions", IRCheckPointObjectExtension),
            ("schedules", "object_extensions", IRCheckPointObjectExtension),
            ("schedule_groups", "object_extensions", IRCheckPointObjectExtension),
            ("interfaces", "interface_extensions", IRCheckPointInterfaceExtension),
            ("security_policies", "policy_extensions", IRCheckPointPolicyExtension),
            ("nat_pools", "nat_pool_extensions", IRCheckPointNATPoolExtension),
            ("nat_rules", "nat_rule_extensions", IRCheckPointNATRuleExtension),
        )
        checkpoint = self.vendor_extensions.checkpoint
        for collection, destination, extension_type in destinations:
            records = getattr(checkpoint, destination)
            for item in getattr(self, collection):
                extension = getattr(item, "vendor_extension", None)
                if not isinstance(extension, extension_type):
                    continue
                if not any(
                    record.model_dump(mode="json") == extension.model_dump(mode="json")
                    for record in records
                ):
                    records.append(extension)
                if clear_embedded:
                    object.__setattr__(item, "vendor_extension", None)

        fortios = self.vendor_extensions.fortios
        for item in self.addresses:
            embedded = getattr(item, "vendor_extension", None)
            if isinstance(embedded, IRFortiOSAddressExtension):
                if not any(record.model_dump(mode="json") == embedded.model_dump(mode="json") for record in fortios.address_extensions):
                    fortios.address_extensions.append(embedded)
                if clear_embedded:
                    object.__setattr__(item, "vendor_extension", None)
                continue
            fsso_group = getattr(item, "source_fsso_group", None)
            effective_defaults = getattr(item, "source_effective_defaults", None)
            source_template = getattr(item, "source_template", None)
            source_fabric = getattr(item, "source_fabric_object_setting", None)
            template_resolved = getattr(item, "source_template_reference_resolved", None)
            if not (fsso_group or effective_defaults or source_template or source_fabric or template_resolved is not None):
                continue
            if isinstance(fsso_group, str):
                fsso_group = [fsso_group]
            extension = IRFortiOSAddressExtension(
                canonical_name=item.name,
                source_context=item.source_context,
                source_uuid=item.source_uuid,
                source_fsso_group=list(fsso_group or []),
                source_effective_defaults=dict(effective_defaults or {}),
                source_fabric_object_setting=source_fabric,
                source_template=source_template,
                source_template_reference_resolved=template_resolved,
            )
            if not any(record.model_dump(mode="json") == extension.model_dump(mode="json") for record in fortios.address_extensions):
                fortios.address_extensions.append(extension)
        for item in self.address_groups:
            extension = getattr(item, "vendor_extension", None)
            if not isinstance(extension, IRFortiOSAddressExtension):
                continue
            if not any(record.model_dump(mode="json") == extension.model_dump(mode="json") for record in fortios.address_group_extensions):
                fortios.address_group_extensions.append(extension)
            if clear_embedded:
                object.__setattr__(item, "vendor_extension", None)
        for item in self.security_policies:
            extension = getattr(item, "vendor_extension", None)
            if not isinstance(extension, IRFortiOSPolicyExtension):
                continue
            if not any(record.model_dump(mode="json") == extension.model_dump(mode="json") for record in fortios.policy_extensions):
                fortios.policy_extensions.append(extension)
            if clear_embedded:
                object.__setattr__(item, "vendor_extension", None)
        for item in self.nat_pools:
            extension = getattr(item, "vendor_extension", None)
            if not isinstance(extension, IRFortiOSNATPoolExtension):
                continue
            if not any(record.model_dump(mode="json") == extension.model_dump(mode="json") for record in fortios.nat_pool_extensions):
                fortios.nat_pool_extensions.append(extension)
            if clear_embedded:
                object.__setattr__(item, "vendor_extension", None)
        for item in self.nat_rules:
            embedded = getattr(item, "vendor_extension", None)
            if isinstance(embedded, IRFortiOSNATRuleExtension):
                if not any(record.model_dump(mode="json") == embedded.model_dump(mode="json") for record in fortios.nat_rule_extensions):
                    fortios.nat_rule_extensions.append(embedded)
                if clear_embedded:
                    object.__setattr__(item, "vendor_extension", None)
                continue
            references = list(getattr(item, "source_pool_group_references", []) or [])
            if not references:
                continue
            extension = IRFortiOSNATRuleExtension(
                canonical_name=item.name,
                source_context=item.source_context,
                source_uuid=item.source_policy_uuid,
                source_pool_group_references=references,
            )
            if not any(record.model_dump(mode="json") == extension.model_dump(mode="json") for record in fortios.nat_rule_extensions):
                fortios.nat_rule_extensions.append(extension)

        def bind_extensions(collection: list[Any], records: list[Any], extension_type: type[BaseModel]) -> None:
            for item in collection:
                extension = getattr(item, "vendor_extension", None)
                if extension is None:
                    item_uuid = getattr(item, "source_uuid", None) or getattr(item, "source_policy_uuid", None)
                    extension = next(
                        (
                            record for record in records
                            if isinstance(record, extension_type)
                            and record.canonical_name == getattr(item, "name", None)
                            and record.source_context == getattr(item, "source_context", None)
                            and (record.source_uuid is None or record.source_uuid == item_uuid)
                        ),
                        None,
                    )
                    if extension is not None:
                        object.__setattr__(item, "vendor_extension", extension)
                if clear_embedded and extension is not None:
                    object.__setattr__(item, "vendor_extension", None)

        bind_extensions(self.addresses, fortios.address_extensions, IRFortiOSAddressExtension)
        bind_extensions(self.address_groups, fortios.address_group_extensions, IRFortiOSAddressExtension)
        bind_extensions(self.security_policies, fortios.policy_extensions, IRFortiOSPolicyExtension)
        bind_extensions(self.nat_pools, fortios.nat_pool_extensions, IRFortiOSNATPoolExtension)
        bind_extensions(self.nat_rules, fortios.nat_rule_extensions, IRFortiOSNATRuleExtension)
        for collection, destination, extension_type in destinations:
            bind_extensions(getattr(self, collection), getattr(checkpoint, destination), extension_type)

    @model_validator(mode="after")
    def collect_embedded_vendor_extensions(self) -> "IRConfig":
        self.sync_vendor_extensions()
        return self

    def _vendor_collection(self, field: str) -> Any:
        vendor = self.metadata.source_vendor.casefold()
        if vendor in {"palo_alto", "panos", "palo-alto"} and hasattr(self.vendor_extensions.panos, field):
            return getattr(self.vendor_extensions.panos, field)
        if vendor in {"checkpoint", "check_point", "check-point"} and hasattr(self.vendor_extensions.checkpoint, field):
            return getattr(self.vendor_extensions.checkpoint, field)
        if hasattr(self.vendor_extensions.fortios, field):
            return getattr(self.vendor_extensions.fortios, field)
        if hasattr(self.vendor_extensions.checkpoint, field):
            return getattr(self.vendor_extensions.checkpoint, field)
        if hasattr(self.vendor_extensions.panos, field):
            return getattr(self.vendor_extensions.panos, field)
        raise AttributeError(field)

    def _set_vendor_collection(self, field: str, value: Any) -> None:
        vendor = self.metadata.source_vendor.casefold()
        container = (
            self.vendor_extensions.panos
            if vendor in {"palo_alto", "panos", "palo-alto"} and hasattr(self.vendor_extensions.panos, field)
            else self.vendor_extensions.checkpoint
            if vendor in {"checkpoint", "check_point", "check-point"} and hasattr(self.vendor_extensions.checkpoint, field)
            else self.vendor_extensions.fortios
            if hasattr(self.vendor_extensions.fortios, field)
            else self.vendor_extensions.checkpoint
            if hasattr(self.vendor_extensions.checkpoint, field)
            else self.vendor_extensions.panos
        )
        setattr(container, field, value)

    checkpoint_management_access = property(lambda self: self._vendor_collection("checkpoint_management_access"), lambda self, value: self._set_vendor_collection("checkpoint_management_access", value))
    checkpoint_performance = property(lambda self: self._vendor_collection("checkpoint_performance"), lambda self, value: self._set_vendor_collection("checkpoint_performance", value))
    checkpoint_policy_packages = property(lambda self: self._vendor_collection("checkpoint_policy_packages"), lambda self, value: self._set_vendor_collection("checkpoint_policy_packages", value))
    checkpoint_access_layers = property(lambda self: self._vendor_collection("checkpoint_access_layers"), lambda self, value: self._set_vendor_collection("checkpoint_access_layers", value))
    checkpoint_domains = property(lambda self: self._vendor_collection("checkpoint_domains"), lambda self, value: self._set_vendor_collection("checkpoint_domains", value))
    checkpoint_global_assignments = property(lambda self: self._vendor_collection("checkpoint_global_assignments"), lambda self, value: self._set_vendor_collection("checkpoint_global_assignments", value))
    checkpoint_access_rules = property(lambda self: self._vendor_collection("checkpoint_access_rules"), lambda self, value: self._set_vendor_collection("checkpoint_access_rules", value))
    checkpoint_threat_prevention_rules = property(lambda self: self._vendor_collection("checkpoint_threat_prevention_rules"), lambda self, value: self._set_vendor_collection("checkpoint_threat_prevention_rules", value))
    checkpoint_threat_prevention_profiles = property(lambda self: self._vendor_collection("checkpoint_threat_prevention_profiles"), lambda self, value: self._set_vendor_collection("checkpoint_threat_prevention_profiles", value))
    checkpoint_sic_metadata = property(lambda self: self._vendor_collection("checkpoint_sic_metadata"), lambda self, value: self._set_vendor_collection("checkpoint_sic_metadata", value))
    central_snat_rules = property(lambda self: self._vendor_collection("central_snat_rules"), lambda self, value: self._set_vendor_collection("central_snat_rules", value))
    policy_routes = property(lambda self: self._vendor_collection("policy_routes"), lambda self, value: self._set_vendor_collection("policy_routes", value))
    local_in_policies = property(lambda self: self._vendor_collection("local_in_policies"), lambda self, value: self._set_vendor_collection("local_in_policies", value))
    proxy_policies = property(lambda self: self._vendor_collection("proxy_policies"), lambda self, value: self._set_vendor_collection("proxy_policies", value))
    shaping_policies = property(lambda self: self._vendor_collection("shaping_policies"), lambda self, value: self._set_vendor_collection("shaping_policies", value))
    dhcp6_servers = property(lambda self: self._vendor_collection("dhcp6_servers"), lambda self, value: self._set_vendor_collection("dhcp6_servers", value))
    source_only_rules = property(lambda self: self._vendor_collection("source_only_rules"), lambda self, value: self._set_vendor_collection("source_only_rules", value))
    sdwans = property(lambda self: self._vendor_collection("sdwans"), lambda self, value: self._set_vendor_collection("sdwans", value))
    user_ldap_servers = property(lambda self: self._vendor_collection("user_ldap_servers"), lambda self, value: self._set_vendor_collection("user_ldap_servers", value))
    user_radius_servers = property(lambda self: self._vendor_collection("user_radius_servers"), lambda self, value: self._set_vendor_collection("user_radius_servers", value))
    user_tacacs_servers = property(lambda self: self._vendor_collection("user_tacacs_servers"), lambda self, value: self._set_vendor_collection("user_tacacs_servers", value))
    fsso_providers = property(lambda self: self._vendor_collection("fsso_providers"), lambda self, value: self._set_vendor_collection("fsso_providers", value))
    fsso_ad_groups = property(lambda self: self._vendor_collection("fsso_ad_groups"), lambda self, value: self._set_vendor_collection("fsso_ad_groups", value))
    fsso_polling = property(lambda self: self._vendor_collection("fsso_polling"), lambda self, value: self._set_vendor_collection("fsso_polling", value))
    user_saml_servers = property(lambda self: self._vendor_collection("user_saml_servers"), lambda self, value: self._set_vendor_collection("user_saml_servers", value))
    local_users = property(lambda self: self._vendor_collection("local_users"), lambda self, value: self._set_vendor_collection("local_users", value))
    user_groups = property(lambda self: self._vendor_collection("user_groups"), lambda self, value: self._set_vendor_collection("user_groups", value))
    administrators = property(lambda self: self._vendor_collection("administrators"), lambda self, value: self._set_vendor_collection("administrators", value))
    admin_profiles = property(lambda self: self._vendor_collection("admin_profiles"), lambda self, value: self._set_vendor_collection("admin_profiles", value))
    fortitokens = property(lambda self: self._vendor_collection("fortitokens"), lambda self, value: self._set_vendor_collection("fortitokens", value))
    ssl_vpn_portals = property(lambda self: self._vendor_collection("ssl_vpn_portals"), lambda self, value: self._set_vendor_collection("ssl_vpn_portals", value))
    ssl_vpn_host_checks = property(lambda self: self._vendor_collection("ssl_vpn_host_checks"), lambda self, value: self._set_vendor_collection("ssl_vpn_host_checks", value))
    ssl_vpn_settings = property(lambda self: self._vendor_collection("ssl_vpn_settings"), lambda self, value: self._set_vendor_collection("ssl_vpn_settings", value))
    dos_policies = property(lambda self: self._vendor_collection("dos_policies"), lambda self, value: self._set_vendor_collection("dos_policies", value))
    firewall_sniffers = property(lambda self: self._vendor_collection("firewall_sniffers"), lambda self, value: self._set_vendor_collection("firewall_sniffers", value))
    ssl_tls_service_profiles = property(lambda self: self._vendor_collection("ssl_tls_service_profiles"), lambda self, value: self._set_vendor_collection("ssl_tls_service_profiles", value))
    user_authentication_settings = property(lambda self: self._vendor_collection("user_authentication_settings"), lambda self, value: self._set_vendor_collection("user_authentication_settings", value))
    user_quarantine_settings = property(lambda self: self._vendor_collection("user_quarantine_settings"), lambda self, value: self._set_vendor_collection("user_quarantine_settings", value))
    traffic_shapers = property(lambda self: self._vendor_collection("traffic_shapers"), lambda self, value: self._set_vendor_collection("traffic_shapers", value))
    proxy_addresses = property(lambda self: self._vendor_collection("proxy_addresses"), lambda self, value: self._set_vendor_collection("proxy_addresses", value))
    internet_services = property(lambda self: self._vendor_collection("internet_services"), lambda self, value: self._set_vendor_collection("internet_services", value))
    internet_service_definitions = property(lambda self: self._vendor_collection("internet_service_definitions"), lambda self, value: self._set_vendor_collection("internet_service_definitions", value))
    internet_service_additions = property(lambda self: self._vendor_collection("internet_service_additions"), lambda self, value: self._set_vendor_collection("internet_service_additions", value))
    internet_service_appends = property(lambda self: self._vendor_collection("internet_service_appends"), lambda self, value: self._set_vendor_collection("internet_service_appends", value))
    custom_internet_services = property(lambda self: self._vendor_collection("custom_internet_services"), lambda self, value: self._set_vendor_collection("custom_internet_services", value))
    custom_internet_service_groups = property(lambda self: self._vendor_collection("custom_internet_service_groups"), lambda self, value: self._set_vendor_collection("custom_internet_service_groups", value))
    internet_service_extensions = property(lambda self: self._vendor_collection("internet_service_extensions"), lambda self, value: self._set_vendor_collection("internet_service_extensions", value))
    internet_service_groups = property(lambda self: self._vendor_collection("internet_service_groups"), lambda self, value: self._set_vendor_collection("internet_service_groups", value))
    session_helpers = property(lambda self: self._vendor_collection("session_helpers"), lambda self, value: self._set_vendor_collection("session_helpers", value))
    session_ttl_overrides = property(lambda self: self._vendor_collection("session_ttl_overrides"), lambda self, value: self._set_vendor_collection("session_ttl_overrides", value))
    session_ttl_settings = property(lambda self: self._vendor_collection("session_ttl_settings"), lambda self, value: self._set_vendor_collection("session_ttl_settings", value))
    address6_templates = property(lambda self: self._vendor_collection("address6_templates"), lambda self, value: self._set_vendor_collection("address6_templates", value))
    ip_pool_groups = property(lambda self: self._vendor_collection("ip_pool_groups"), lambda self, value: self._set_vendor_collection("ip_pool_groups", value))
    global_protect_portals = property(lambda self: self._vendor_collection("global_protect_portals"), lambda self, value: self._set_vendor_collection("global_protect_portals", value))
    global_protect_gateways = property(lambda self: self._vendor_collection("global_protect_gateways"), lambda self, value: self._set_vendor_collection("global_protect_gateways", value))
    global_protect_network_gateways = property(lambda self: self._vendor_collection("global_protect_network_gateways"), lambda self, value: self._set_vendor_collection("global_protect_network_gateways", value))
    pan_log_server_profiles = property(lambda self: self._vendor_collection("pan_log_server_profiles"), lambda self, value: self._set_vendor_collection("pan_log_server_profiles", value))
    pan_log_forwarding_profiles = property(lambda self: self._vendor_collection("pan_log_forwarding_profiles"), lambda self, value: self._set_vendor_collection("pan_log_forwarding_profiles", value))
    pan_management_log_settings = property(lambda self: self._vendor_collection("pan_management_log_settings"), lambda self, value: self._set_vendor_collection("pan_management_log_settings", value))
    pan_dns_proxies = property(lambda self: self._vendor_collection("pan_dns_proxies"), lambda self, value: self._set_vendor_collection("pan_dns_proxies", value))
    pan_monitor_profiles = property(lambda self: self._vendor_collection("pan_monitor_profiles"), lambda self, value: self._set_vendor_collection("pan_monitor_profiles", value))
    pan_qos_profiles = property(lambda self: self._vendor_collection("pan_qos_profiles"), lambda self, value: self._set_vendor_collection("pan_qos_profiles", value))
    pan_sdwan_interface_profiles = property(lambda self: self._vendor_collection("pan_sdwan_interface_profiles"), lambda self, value: self._set_vendor_collection("pan_sdwan_interface_profiles", value))
    pan_sdwan_link_settings = property(lambda self: self._vendor_collection("pan_sdwan_link_settings"), lambda self, value: self._set_vendor_collection("pan_sdwan_link_settings", value))
    pan_sdwan_path_quality_profiles = property(lambda self: self._vendor_collection("pan_sdwan_path_quality_profiles"), lambda self, value: self._set_vendor_collection("pan_sdwan_path_quality_profiles", value))
    pan_sdwan_traffic_distribution_profiles = property(lambda self: self._vendor_collection("pan_sdwan_traffic_distribution_profiles"), lambda self, value: self._set_vendor_collection("pan_sdwan_traffic_distribution_profiles", value))
    pan_sdwan_rules = property(lambda self: self._vendor_collection("pan_sdwan_rules"), lambda self, value: self._set_vendor_collection("pan_sdwan_rules", value))
    pan_high_availability = property(lambda self: self._vendor_collection("pan_high_availability"), lambda self, value: self._set_vendor_collection("pan_high_availability", value))
    pan_virtual_wires = property(lambda self: self._vendor_collection("pan_virtual_wires"), lambda self, value: self._set_vendor_collection("pan_virtual_wires", value))
    pan_device_operational_settings = property(lambda self: self._vendor_collection("pan_device_operational_settings"), lambda self, value: self._set_vendor_collection("pan_device_operational_settings", value))
    pan_vsys_settings = property(lambda self: self._vendor_collection("pan_vsys_settings"), lambda self, value: self._set_vendor_collection("pan_vsys_settings", value))
    pan_botnet_report_settings = property(lambda self: self._vendor_collection("pan_botnet_report_settings"), lambda self, value: self._set_vendor_collection("pan_botnet_report_settings", value))
    pan_custom_reports = property(lambda self: self._vendor_collection("pan_custom_reports"), lambda self, value: self._set_vendor_collection("pan_custom_reports", value))

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
