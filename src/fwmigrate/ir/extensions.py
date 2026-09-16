from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .extension_models import (
    IRCheckPointInterfaceExtension,
    IRCheckPointNATPoolExtension,
    IRCheckPointNATRuleExtension,
    IRCheckPointObjectExtension,
    IRCheckPointPolicyExtension,
    IRFortiOSAddressExtension,
    IRFortiOSNATPoolExtension,
    IRFortiOSNATRuleExtension,
    IRFortiOSPolicyExtension,
    IRAddress6Template,
    IRIPPoolGroup,
    IRVendorExtensionIdentity,
    _payload_value,
    move_object_extension,
)
from .metadata import IRCheckpointManagementAccess, IRCheckpointPerformanceSettings
from .network import IRCheckpointSICMetadata
from .policy import (
    IRCheckpointAccessLayer,
    IRCheckpointAccessRule,
    IRCheckpointDomain,
    IRCheckpointGlobalAssignment,
    IRCheckpointPolicyPackage,
    IRCheckpointThreatPreventionProfile,
    IRCheckpointThreatPreventionRule,
    IRFortiGateSourceRule,
    IRLocalDeviceAccessRule,
    IRSessionHelper,
    IRSessionTTLOverride,
    IRSessionTTLSettings,
)
from .routing import IRFortiGatePolicyRoute, IRSDWAN
from .security_profiles import (
    IRAdminProfile,
    IRAdministrator,
    IRAuthenticationProfile,
    IRAuthenticationPolicy,
    IRDoSPolicy,
    IRFirewallSniffer,
    IRFortiToken,
    IRFSSOADGroup,
    IRFSSOPolling,
    IRFSSOProvider,
    IRGlobalProtectGateway,
    IRGlobalProtectNetworkGateway,
    IRGlobalProtectPortal,
    IRLocalUser,
    IRPANBotnetReportSettings,
    IRPANCustomReport,
    IRPANDNSProxy,
    IRPANDeviceOperationalSettings,
    IRPANHighAvailability,
    IRPANLogForwardingProfile,
    IRPANLogServerProfile,
    IRPANManagementLogSetting,
    IRPANMonitorProfile,
    IRPANQoSProfile,
    IRPANSDWANInterfaceProfile,
    IRPANSDWANLinkSettings,
    IRPANSDWANPathQualityProfile,
    IRPANSDWANRule,
    IRPANSDWANTrafficDistributionProfile,
    IRPANVirtualWire,
    IRPANVsysSettings,
    IRSSLVPNHostCheck,
    IRSSLVPNPortal,
    IRSSLVPNSettings,
    IRUserGroup,
    IRUserLDAP,
    IRUserRADIUS,
    IRUserSAML,
    IRUserTACACS,
    IRSSLTLSServiceProfile,
    IRUserAuthenticationSettings,
    IRUserQuarantineSettings,
)
from .service import (
    IRInternetService,
    IRInternetServiceAddition,
    IRInternetServiceAppend,
    IRInternetServiceCustom,
    IRInternetServiceCustomGroup,
    IRInternetServiceDefinition,
    IRInternetServiceExtension,
    IRInternetServiceGroup,
    IRProxyRequestMatch,
    IRTrafficShaper,
    IRWebProxy,
)


class _VendorExtension(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IRFortiOSExtensions(_VendorExtension):
    address_extensions: list[IRFortiOSAddressExtension] = Field(default_factory=list)
    address_group_extensions: list[IRFortiOSAddressExtension] = Field(default_factory=list)
    nat_pool_extensions: list[IRFortiOSNATPoolExtension] = Field(default_factory=list)
    nat_rule_extensions: list[IRFortiOSNATRuleExtension] = Field(default_factory=list)
    policy_extensions: list[IRFortiOSPolicyExtension] = Field(default_factory=list)
    security_policies: list[IRFortiGateSourceRule] = Field(default_factory=list)
    central_snat_rules: list[IRFortiGateSourceRule] = Field(default_factory=list)
    policy_routes: list[IRFortiGatePolicyRoute] = Field(default_factory=list)
    local_in_policies: list[IRLocalDeviceAccessRule] = Field(default_factory=list)
    proxy_policies: list[IRFortiGateSourceRule] = Field(default_factory=list)
    shaping_policies: list[IRFortiGateSourceRule] = Field(default_factory=list)
    dhcp6_servers: list[IRFortiGateSourceRule] = Field(default_factory=list)
    source_only_rules: list[IRFortiGateSourceRule] = Field(default_factory=list)
    sdwans: list[IRSDWAN] = Field(default_factory=list)
    user_ldap_servers: list[IRUserLDAP] = Field(default_factory=list)
    user_radius_servers: list[IRUserRADIUS] = Field(default_factory=list)
    user_tacacs_servers: list[IRUserTACACS] = Field(default_factory=list)
    fsso_providers: list[IRFSSOProvider] = Field(default_factory=list)
    fsso_ad_groups: list[IRFSSOADGroup] = Field(default_factory=list)
    fsso_polling: list[IRFSSOPolling] = Field(default_factory=list)
    user_saml_servers: list[IRUserSAML] = Field(default_factory=list)
    local_users: list[IRLocalUser] = Field(default_factory=list)
    user_groups: list[IRUserGroup] = Field(default_factory=list)
    administrators: list[IRAdministrator] = Field(default_factory=list)
    admin_profiles: list[IRAdminProfile] = Field(default_factory=list)
    fortitokens: list[IRFortiToken] = Field(default_factory=list)
    ssl_vpn_portals: list[IRSSLVPNPortal] = Field(default_factory=list)
    ssl_vpn_host_checks: list[IRSSLVPNHostCheck] = Field(default_factory=list)
    ssl_vpn_settings: IRSSLVPNSettings | None = None
    dos_policies: list[IRDoSPolicy] = Field(default_factory=list)
    firewall_sniffers: list[IRFirewallSniffer] = Field(default_factory=list)
    authentication_profiles: list[IRAuthenticationProfile] = Field(default_factory=list)
    authentication_policies: list[IRAuthenticationPolicy] = Field(default_factory=list)
    user_authentication_settings: IRUserAuthenticationSettings | None = None
    user_quarantine_settings: IRUserQuarantineSettings | None = None
    ssl_tls_service_profiles: list[IRSSLTLSServiceProfile] = Field(default_factory=list)
    traffic_shapers: list[IRTrafficShaper] = Field(default_factory=list)
    proxy_addresses: list[IRProxyRequestMatch] = Field(default_factory=list)
    web_proxies: list[IRWebProxy] = Field(default_factory=list)
    internet_services: list[IRInternetService] = Field(default_factory=list)
    internet_service_definitions: list[IRInternetServiceDefinition] = Field(default_factory=list)
    internet_service_additions: list[IRInternetServiceAddition] = Field(default_factory=list)
    internet_service_appends: list[IRInternetServiceAppend] = Field(default_factory=list)
    custom_internet_services: list[IRInternetServiceCustom] = Field(default_factory=list)
    custom_internet_service_groups: list[IRInternetServiceCustomGroup] = Field(default_factory=list)
    internet_service_extensions: list[IRInternetServiceExtension] = Field(default_factory=list)
    internet_service_groups: list[IRInternetServiceGroup] = Field(default_factory=list)
    session_helpers: list[IRSessionHelper] = Field(default_factory=list)
    session_ttl_overrides: list[IRSessionTTLOverride] = Field(default_factory=list)
    session_ttl_settings: IRSessionTTLSettings | None = None
    address6_templates: list[IRAddress6Template] = Field(default_factory=list)
    ip_pool_groups: list[IRIPPoolGroup] = Field(default_factory=list)


class IRPANOSExtensions(_VendorExtension):
    global_protect_portals: list[IRGlobalProtectPortal] = Field(default_factory=list)
    global_protect_gateways: list[IRGlobalProtectGateway] = Field(default_factory=list)
    global_protect_network_gateways: list[IRGlobalProtectNetworkGateway] = Field(default_factory=list)
    pan_log_server_profiles: list[IRPANLogServerProfile] = Field(default_factory=list)
    pan_log_forwarding_profiles: list[IRPANLogForwardingProfile] = Field(default_factory=list)
    pan_management_log_settings: list[IRPANManagementLogSetting] = Field(default_factory=list)
    pan_dns_proxies: list[IRPANDNSProxy] = Field(default_factory=list)
    pan_monitor_profiles: list[IRPANMonitorProfile] = Field(default_factory=list)
    pan_qos_profiles: list[IRPANQoSProfile] = Field(default_factory=list)
    pan_sdwan_interface_profiles: list[IRPANSDWANInterfaceProfile] = Field(default_factory=list)
    pan_sdwan_link_settings: list[IRPANSDWANLinkSettings] = Field(default_factory=list)
    pan_sdwan_path_quality_profiles: list[IRPANSDWANPathQualityProfile] = Field(default_factory=list)
    pan_sdwan_traffic_distribution_profiles: list[IRPANSDWANTrafficDistributionProfile] = Field(default_factory=list)
    pan_sdwan_rules: list[IRPANSDWANRule] = Field(default_factory=list)
    pan_high_availability: IRPANHighAvailability | None = None
    pan_virtual_wires: list[IRPANVirtualWire] = Field(default_factory=list)
    pan_device_operational_settings: IRPANDeviceOperationalSettings | None = None
    pan_vsys_settings: list[IRPANVsysSettings] = Field(default_factory=list)
    pan_botnet_report_settings: IRPANBotnetReportSettings | None = None
    pan_custom_reports: list[IRPANCustomReport] = Field(default_factory=list)
    user_saml_servers: list[IRUserSAML] = Field(default_factory=list)
    administrators: list[IRAdministrator] = Field(default_factory=list)
    admin_profiles: list[IRAdminProfile] = Field(default_factory=list)
    user_authentication_settings: IRUserAuthenticationSettings | None = None


class IRCheckPointExtensions(_VendorExtension):
    checkpoint_management_access: list[IRCheckpointManagementAccess] = Field(default_factory=list)
    checkpoint_performance: list[IRCheckpointPerformanceSettings] = Field(default_factory=list)
    checkpoint_policy_packages: list[IRCheckpointPolicyPackage] = Field(default_factory=list)
    checkpoint_access_layers: list[IRCheckpointAccessLayer] = Field(default_factory=list)
    checkpoint_domains: list[IRCheckpointDomain] = Field(default_factory=list)
    checkpoint_global_assignments: list[IRCheckpointGlobalAssignment] = Field(default_factory=list)
    checkpoint_access_rules: list[IRCheckpointAccessRule] = Field(default_factory=list)
    checkpoint_threat_prevention_rules: list[IRCheckpointThreatPreventionRule] = Field(default_factory=list)
    checkpoint_threat_prevention_profiles: list[IRCheckpointThreatPreventionProfile] = Field(default_factory=list)
    checkpoint_sic_metadata: list[IRCheckpointSICMetadata] = Field(default_factory=list)
    user_ldap_servers: list[IRUserLDAP] = Field(default_factory=list)
    user_radius_servers: list[IRUserRADIUS] = Field(default_factory=list)
    user_tacacs_servers: list[IRUserTACACS] = Field(default_factory=list)
    user_saml_servers: list[IRUserSAML] = Field(default_factory=list)
    local_users: list[IRLocalUser] = Field(default_factory=list)
    user_groups: list[IRUserGroup] = Field(default_factory=list)
    administrators: list[IRAdministrator] = Field(default_factory=list)
    admin_profiles: list[IRAdminProfile] = Field(default_factory=list)
    object_extensions: list[IRCheckPointObjectExtension] = Field(default_factory=list)
    policy_extensions: list[IRCheckPointPolicyExtension] = Field(default_factory=list)
    nat_pool_extensions: list[IRCheckPointNATPoolExtension] = Field(default_factory=list)
    nat_rule_extensions: list[IRCheckPointNATRuleExtension] = Field(default_factory=list)
    interface_extensions: list[IRCheckPointInterfaceExtension] = Field(default_factory=list)


class IRCiscoASAExtensions(_VendorExtension):
    pass


class IRCiscoFTDExtensions(_VendorExtension):
    pass


class IRJunosExtensions(_VendorExtension):
    pass


class IRVendorExtensions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fortios: IRFortiOSExtensions = Field(default_factory=IRFortiOSExtensions)
    panos: IRPANOSExtensions = Field(default_factory=IRPANOSExtensions)
    checkpoint: IRCheckPointExtensions = Field(default_factory=IRCheckPointExtensions)
    cisco_asa: IRCiscoASAExtensions = Field(default_factory=IRCiscoASAExtensions)
    cisco_ftd: IRCiscoFTDExtensions = Field(default_factory=IRCiscoFTDExtensions)
    junos: IRJunosExtensions = Field(default_factory=IRJunosExtensions)


_TRANSITIONAL_ROOTS = {
    "checkpoint_management_access": ("checkpoint", "checkpoint_management_access"),
    "checkpoint_performance": ("checkpoint", "checkpoint_performance"),
    "checkpoint_policy_packages": ("checkpoint", "checkpoint_policy_packages"),
    "checkpoint_access_layers": ("checkpoint", "checkpoint_access_layers"),
    "checkpoint_domains": ("checkpoint", "checkpoint_domains"),
    "checkpoint_global_assignments": ("checkpoint", "checkpoint_global_assignments"),
    "checkpoint_access_rules": ("checkpoint", "checkpoint_access_rules"),
    "checkpoint_threat_prevention_rules": ("checkpoint", "checkpoint_threat_prevention_rules"),
    "checkpoint_threat_prevention_profiles": ("checkpoint", "checkpoint_threat_prevention_profiles"),
    "checkpoint_sic_metadata": ("checkpoint", "checkpoint_sic_metadata"),
    "central_snat_rules": ("fortios", "central_snat_rules"),
    "policy_routes": ("fortios", "policy_routes"),
    "local_in_policies": ("fortios", "local_in_policies"),
    "proxy_policies": ("fortios", "proxy_policies"),
    "shaping_policies": ("fortios", "shaping_policies"),
    "dhcp6_servers": ("fortios", "dhcp6_servers"),
    "source_only_rules": ("fortios", "source_only_rules"),
    "sdwans": ("fortios", "sdwans"),
    "user_ldap_servers": ("fortios", "user_ldap_servers"),
    "user_radius_servers": ("fortios", "user_radius_servers"),
    "user_tacacs_servers": ("fortios", "user_tacacs_servers"),
    "fsso_providers": ("fortios", "fsso_providers"),
    "fsso_ad_groups": ("fortios", "fsso_ad_groups"),
    "fsso_polling": ("fortios", "fsso_polling"),
    "user_saml_servers": ("fortios", "user_saml_servers"),
    "local_users": ("fortios", "local_users"),
    "user_groups": ("fortios", "user_groups"),
    "administrators": ("fortios", "administrators"),
    "admin_profiles": ("fortios", "admin_profiles"),
    "fortitokens": ("fortios", "fortitokens"),
    "ssl_vpn_portals": ("fortios", "ssl_vpn_portals"),
    "ssl_vpn_host_checks": ("fortios", "ssl_vpn_host_checks"),
    "ssl_vpn_settings": ("fortios", "ssl_vpn_settings"),
    "dos_policies": ("fortios", "dos_policies"),
    "firewall_sniffers": ("fortios", "firewall_sniffers"),
    "ssl_tls_service_profiles": ("fortios", "ssl_tls_service_profiles"),
    "user_authentication_settings": ("fortios", "user_authentication_settings"),
    "user_quarantine_settings": ("fortios", "user_quarantine_settings"),
    "traffic_shapers": ("fortios", "traffic_shapers"),
    "proxy_addresses": ("fortios", "proxy_addresses"),
    "internet_services": ("fortios", "internet_services"),
    "internet_service_definitions": ("fortios", "internet_service_definitions"),
    "internet_service_additions": ("fortios", "internet_service_additions"),
    "internet_service_appends": ("fortios", "internet_service_appends"),
    "custom_internet_services": ("fortios", "custom_internet_services"),
    "custom_internet_service_groups": ("fortios", "custom_internet_service_groups"),
    "internet_service_extensions": ("fortios", "internet_service_extensions"),
    "internet_service_groups": ("fortios", "internet_service_groups"),
    "session_helpers": ("fortios", "session_helpers"),
    "session_ttl_overrides": ("fortios", "session_ttl_overrides"),
    "session_ttl_settings": ("fortios", "session_ttl_settings"),
    "address6_templates": ("fortios", "address6_templates"),
    "ip_pool_groups": ("fortios", "ip_pool_groups"),
    "global_protect_portals": ("panos", "global_protect_portals"),
    "global_protect_gateways": ("panos", "global_protect_gateways"),
    "global_protect_network_gateways": ("panos", "global_protect_network_gateways"),
    "pan_log_server_profiles": ("panos", "pan_log_server_profiles"),
    "pan_log_forwarding_profiles": ("panos", "pan_log_forwarding_profiles"),
    "pan_management_log_settings": ("panos", "pan_management_log_settings"),
    "pan_dns_proxies": ("panos", "pan_dns_proxies"),
    "pan_monitor_profiles": ("panos", "pan_monitor_profiles"),
    "pan_qos_profiles": ("panos", "pan_qos_profiles"),
    "pan_sdwan_interface_profiles": ("panos", "pan_sdwan_interface_profiles"),
    "pan_sdwan_link_settings": ("panos", "pan_sdwan_link_settings"),
    "pan_sdwan_path_quality_profiles": ("panos", "pan_sdwan_path_quality_profiles"),
    "pan_sdwan_traffic_distribution_profiles": ("panos", "pan_sdwan_traffic_distribution_profiles"),
    "pan_sdwan_rules": ("panos", "pan_sdwan_rules"),
    "pan_high_availability": ("panos", "pan_high_availability"),
    "pan_virtual_wires": ("panos", "pan_virtual_wires"),
    "pan_device_operational_settings": ("panos", "pan_device_operational_settings"),
    "pan_vsys_settings": ("panos", "pan_vsys_settings"),
    "pan_botnet_report_settings": ("panos", "pan_botnet_report_settings"),
    "pan_custom_reports": ("panos", "pan_custom_reports"),
}

_CHECKPOINT_SHARED_ROOTS = {
    "user_ldap_servers", "user_radius_servers", "user_tacacs_servers",
    "user_saml_servers", "local_users", "user_groups", "administrators",
    "admin_profiles", "user_authentication_settings",
}
_PAN_SHARED_ROOTS = {
    "user_saml_servers", "administrators", "admin_profiles",
    "user_authentication_settings",
}


def _merge_extension_value(extensions: dict[str, Any], vendor: str, field: str, value: Any) -> None:
    vendor_payload = dict(extensions.get(vendor) or {})
    if field in vendor_payload and _payload_value(vendor_payload[field]) != _payload_value(value):
        raise ValueError(f"Conflicting transitional IR values for {vendor}.{field}.")
    vendor_payload.setdefault(field, value)
    extensions[vendor] = vendor_payload


def normalize_transitional_v2_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Move old authoritative roots into typed extension containers once."""
    migrated = dict(payload)
    extensions = dict(migrated.get("vendor_extensions") or {})
    metadata = migrated.get("metadata")
    source_vendor = (
        str(metadata.get("source_vendor", "")).casefold()
        if isinstance(metadata, dict)
        else ""
    )
    for root, (vendor, field) in _TRANSITIONAL_ROOTS.items():
        if root in migrated:
            if root in _CHECKPOINT_SHARED_ROOTS and source_vendor in {
                "checkpoint", "check_point", "check-point",
            }:
                vendor = "checkpoint"
            elif root in _PAN_SHARED_ROOTS and source_vendor in {
                "palo_alto", "panos", "palo-alto",
            }:
                vendor = "panos"
            value = migrated.pop(root)
            if value is not None:
                _merge_extension_value(extensions, vendor, field, value)

    policies = migrated.get("security_policies")
    if isinstance(policies, list):
        portable: list[Any] = []
        fortios: list[Any] = []
        for item in policies:
            raw = _payload_value(item)
            if isinstance(item, IRFortiGateSourceRule) or (
                isinstance(raw, dict) and "family" in raw and "action" not in raw
            ):
                fortios.append(item)
            else:
                portable.append(item)
        if fortios:
            _merge_extension_value(extensions, "fortios", "security_policies", fortios)
        migrated["security_policies"] = portable

    nat_rules = migrated.get("nat_rules")
    if isinstance(nat_rules, list):
        portable_nat: list[Any] = []
        service_nat: list[dict[str, Any]] = []
        for item in nat_rules:
            raw = _payload_value(item)
            if isinstance(raw, dict) and raw.get("type") == "central":
                raw["type"] = "source"
                raw["source_origin"] = raw.get("source_origin") or "central-snat-map"
            if isinstance(raw, dict) and raw.get("type") == "service":
                service_extension = {
                    "canonical_name": raw.get("name"),
                    "source_context": raw.get("source_context"),
                    "source_uuid": raw.get("source_policy_uuid"),
                    "translation_type": "service",
                    "original_services": raw.get("services") or [],
                    "translated_services": raw.get("translated_services") or [],
                    "migration_status": raw.get("migration_status", "EXTRACT_ONLY"),
                    "requires_manual_review": True,
                    "review_reasons": raw.get("review_reasons") or ["translated-service"],
                    "source_attributes": raw,
                }
                if source_vendor in {"checkpoint", "check_point", "check-point"}:
                    service_extension.update({
                        "checkpoint_domain_uid": raw.get("checkpoint_domain_uid"),
                        "checkpoint_domain_name": raw.get("checkpoint_domain_name"),
                        "checkpoint_package_uid": raw.get("checkpoint_package_uid"),
                        "checkpoint_package_name": raw.get("checkpoint_package_name"),
                    })
                service_nat.append(service_extension)
            else:
                portable_nat.append(raw)
        if service_nat:
            _merge_extension_value(
                extensions,
                "checkpoint" if source_vendor in {"checkpoint", "check_point", "check-point"} else "fortios",
                "nat_rule_extensions",
                service_nat,
            )
        migrated["nat_rules"] = portable_nat

    migrated["vendor_extensions"] = extensions
    return migrated


__all__ = [
    "IRVendorExtensionIdentity",
    "IRCheckPointObjectExtension",
    "IRCheckPointPolicyExtension",
    "IRCheckPointNATPoolExtension",
    "IRCheckPointNATRuleExtension",
    "IRCheckPointInterfaceExtension",
    "IRFortiOSAddressExtension",
    "IRFortiOSNATPoolExtension",
    "IRFortiOSNATRuleExtension",
    "IRFortiOSPolicyExtension",
    "IRFortiOSExtensions",
    "IRPANOSExtensions",
    "IRCheckPointExtensions",
    "IRCiscoASAExtensions",
    "IRCiscoFTDExtensions",
    "IRJunosExtensions",
    "IRVendorExtensions",
    "move_object_extension",
    "normalize_transitional_v2_payload",
]
