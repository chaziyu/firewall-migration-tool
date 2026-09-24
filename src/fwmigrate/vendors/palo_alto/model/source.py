from __future__ import annotations

from pydantic import BaseModel, Field

from ..source_model import PANScope, PANSourceRecord
from .administration import PANAdministrator, PANAdminRole
from .address import PANAddress, PANAddressGroup
from .dhcp import PANDHCPServer
from .globalprotect import PANGlobalProtectGateway, PANGlobalProtectPortal
from .identity import PANGroupMapping, PANLocalUser, PANLocalUserGroup
from .interface import PANInterface, PANInterfaceImport, PANInterfaceUnit
from .nat import PANNATRule
from .policy import PANDefaultSecurityRule, PANSecurityRule
from .routing import PANLogicalRouter, PANStaticRoute, PANVirtualRouter
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
    nat_rules: list[PANNATRule] = Field(default_factory=list)
    vulnerability_profiles: list[PANVulnerabilityProfile] = Field(default_factory=list)
    security_profile_groups: list[PANSecurityProfileGroup] = Field(default_factory=list)
    zones: list[PANZone] = Field(default_factory=list)
    static_routes: list[PANStaticRoute] = Field(default_factory=list)
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

    source_inventory: list[PANSourceRecord] = Field(default_factory=list)
    unknown_paths: list[str] = Field(default_factory=list)
