"""Typed Check Point source-state aggregate."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .address import (
    CPAddressRange, CPDNSDomain, CPDynamicAddress, CPGroup, CPGroupWithExclusion,
    CPHost, CPNetwork, CPUpdatableObject, CPWildcardAddress,
)
from .administration import CPAdministrator, CPPermissionProfile
from .common import CheckPointSourceObject
from .gateway import CPCluster, CPGateway, CPInteroperableDevice
from .gaia import (
    CPGaiaDHCPServer, CPGaiaInterface, CPGaiaRBAUserAssignment, CPGaiaRBARole,
    CPGaiaStaticRoute, CPGaiaUser, CPVTI,
)
from .identity import CPAccessRole, CPUser, CPUserGroup
from .policy import (
    CPAccessLayer, CPAccessRule, CPAccessSection, CPAutoNATRule, CPNATRule,
    CPNATSection, CPPolicyPackage,
)
from .schedule import CPTime, CPTimeGroup
from .service import CPService, CPServiceGroup
from .threat import (
    CPHTTPSInspectionRule, CPThreatLayer, CPThreatProfile, CPThreatRule,
    CPThreatRuleException, CPThreatSection,
)
from .vpn import CPVPNCommunity, CPVPNDomain
from .zone import CPSecurityZone


class CPDomain(CheckPointSourceObject):
    pass


class CPApplication(CheckPointSourceObject):
    members: list[str] = Field(default_factory=list)


class CheckPointConfig(BaseModel):
    """Explicit Check Point source configuration; no collection runtime state."""

    model_config = ConfigDict(extra="allow")

    domains: list[CPDomain] = Field(default_factory=list)
    hosts: list[CPHost] = Field(default_factory=list)
    networks: list[CPNetwork] = Field(default_factory=list)
    address_ranges: list[CPAddressRange] = Field(default_factory=list)
    dns_domains: list[CPDNSDomain] = Field(default_factory=list)
    wildcard_addresses: list[CPWildcardAddress] = Field(default_factory=list)
    dynamic_addresses: list[CPDynamicAddress] = Field(default_factory=list)
    updatable_objects: list[CPUpdatableObject] = Field(default_factory=list)
    groups: list[CPGroup] = Field(default_factory=list)
    groups_with_exclusion: list[CPGroupWithExclusion] = Field(default_factory=list)
    services: list[CPService] = Field(default_factory=list)
    service_groups: list[CPServiceGroup] = Field(default_factory=list)
    applications: list[CPApplication] = Field(default_factory=list)
    times: list[CPTime] = Field(default_factory=list)
    time_groups: list[CPTimeGroup] = Field(default_factory=list)
    security_zones: list[CPSecurityZone] = Field(default_factory=list)
    users: list[CPUser] = Field(default_factory=list)
    user_groups: list[CPUserGroup] = Field(default_factory=list)
    access_roles: list[CPAccessRole] = Field(default_factory=list)
    permission_profiles: list[CPPermissionProfile] = Field(default_factory=list)
    administrators: list[CPAdministrator] = Field(default_factory=list)
    gateways: list[CPGateway] = Field(default_factory=list)
    clusters: list[CPCluster] = Field(default_factory=list)
    interoperable_devices: list[CPInteroperableDevice] = Field(default_factory=list)
    vpn_communities: list[CPVPNCommunity] = Field(default_factory=list)
    vpn_domains: list[CPVPNDomain] = Field(default_factory=list)
    policy_packages: list[CPPolicyPackage] = Field(default_factory=list)
    access_layers: list[CPAccessLayer] = Field(default_factory=list)
    access_sections: list[CPAccessSection] = Field(default_factory=list)
    access_rules: list[CPAccessRule] = Field(default_factory=list)
    nat_sections: list[CPNATSection] = Field(default_factory=list)
    nat_rules: list[CPNATRule | CPAutoNATRule] = Field(default_factory=list)
    threat_profiles: list[CPThreatProfile] = Field(default_factory=list)
    threat_layers: list[CPThreatLayer] = Field(default_factory=list)
    threat_sections: list[CPThreatSection] = Field(default_factory=list)
    threat_rules: list[CPThreatRule] = Field(default_factory=list)
    threat_rule_exceptions: list[CPThreatRuleException] = Field(default_factory=list)
    https_inspection_rules: list[CPHTTPSInspectionRule] = Field(default_factory=list)
    gaia_interfaces: list[CPGaiaInterface] = Field(default_factory=list)
    gaia_static_routes: list[CPGaiaStaticRoute] = Field(default_factory=list)
    gaia_dhcp_servers: list[CPGaiaDHCPServer] = Field(default_factory=list)
    gaia_users: list[CPGaiaUser] = Field(default_factory=list)
    gaia_rba_roles: list[CPGaiaRBARole] = Field(default_factory=list)
    gaia_rba_user_assignments: list[CPGaiaRBAUserAssignment] = Field(default_factory=list)
    vtis: list[CPVTI] = Field(default_factory=list)

    @property
    def network_objects(self) -> list[CheckPointSourceObject]:
        return [
            *self.hosts, *self.networks, *self.address_ranges, *self.dns_domains,
            *self.wildcard_addresses, *self.dynamic_addresses, *self.updatable_objects,
            *self.security_zones,
        ]

    @property
    def schedules(self) -> list[CPTime]:
        return self.times

    @property
    def identity_objects(self) -> list[CheckPointSourceObject]:
        return [*self.users, *self.user_groups, *self.access_roles]

    @property
    def threat_prevention(self) -> list[CheckPointSourceObject]:
        return [*self.threat_rules, *self.threat_rule_exceptions]

    @property
    def https_inspection(self) -> list[CPHTTPSInspectionRule]:
        return self.https_inspection_rules

    @property
    def gaia_routes(self) -> list[CPGaiaStaticRoute]:
        return self.gaia_static_routes

    @property
    def packages(self) -> list[CPPolicyPackage]:
        return self.policy_packages


__all__ = ["CPApplication", "CPDomain", "CheckPointConfig"]
