"""Vendor-native juniper_srx context models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from .address import JuniperAddressBook
from .administration import JuniperAccessProfile, JuniperChassisCluster, JuniperDHCPConfig, JuniperScheduler, JuniperSecurityFlowSettings, JuniperSyslogSettings
from .application import JuniperApplication, JuniperApplicationSet
from .common import JuniperConfigContext, JuniperContextType, JuniperEffectiveCandidate, JuniperEffectiveModel, JuniperSourceHierarchyItem
from .interface import JuniperFirewallFilter, JuniperInterface, JuniperScreenProfile
from .nat import JuniperNATConfig
from .policy import JuniperAppSecureRuleSet, JuniperChassisItem, JuniperIDPPolicy, JuniperPolicer, JuniperPolicy, JuniperRPMProbe, JuniperSSLProxyProfile, JuniperSecurityIntelligenceFeed, JuniperSecurityIntelligenceProfile, JuniperUTMAntiSpamProfile, JuniperUTMAntivirusProfile, JuniperUTMContentFilteringProfile, JuniperUTMWebFilteringProfile
from .routing import JuniperAPBRConfig, JuniperCoSScheduler, JuniperPrefixList, JuniperRoute, JuniperRoutingInstance, JuniperVLAN
from .vpn import JuniperRemoteAccessConfig, JuniperVPNConfig


class JuniperZone(JuniperEffectiveModel):
    name: str
    description: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    screen: Optional[str] = None
    host_inbound_system_services: List[str] = Field(default_factory=list)
    host_inbound_system_services_exclusions: List[str] = Field(default_factory=list)
    host_inbound_protocols: List[str] = Field(default_factory=list)
    host_inbound_protocol_exclusions: List[str] = Field(default_factory=list)
    interface_host_inbound: Dict[str, Dict[str, List[str]]] = Field(default_factory=dict)
    disabled_host_inbound: Dict[str, List[str]] = Field(default_factory=dict)
    tcp_rst: Optional[bool] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperContextConfig(BaseModel):
    name: str = "root"
    context_type: str = "root"  # root, logical-system, tenant
    interfaces: Dict[str, JuniperInterface] = Field(default_factory=dict)
    vlans: Dict[str, "JuniperVLAN"] = Field(default_factory=dict)
    zones: Dict[str, JuniperZone] = Field(default_factory=dict)
    screens: Dict[str, JuniperScreenProfile] = Field(default_factory=dict)
    address_books: Dict[str, JuniperAddressBook] = Field(default_factory=dict)
    applications: Dict[str, JuniperApplication] = Field(default_factory=dict)
    application_sets: Dict[str, JuniperApplicationSet] = Field(default_factory=dict)
    policies: List[JuniperPolicy] = Field(default_factory=list)
    global_policies: List[JuniperPolicy] = Field(default_factory=list)
    schedulers: Dict[str, JuniperScheduler] = Field(default_factory=dict)
    routes: List[JuniperRoute] = Field(default_factory=list)
    routing_instances: Dict[str, JuniperRoutingInstance] = Field(default_factory=dict)
    firewall_filters: Dict[str, JuniperFirewallFilter] = Field(default_factory=dict)
    policers: Dict[str, JuniperPolicer] = Field(default_factory=dict)
    prefix_lists: Dict[str, JuniperPrefixList] = Field(default_factory=dict)
    cos_schedulers: Dict[str, JuniperCoSScheduler] = Field(default_factory=dict)
    dhcp: JuniperDHCPConfig = Field(default_factory=JuniperDHCPConfig)
    apbr: JuniperAPBRConfig = Field(default_factory=JuniperAPBRConfig)
    remote_access: JuniperRemoteAccessConfig = Field(default_factory=JuniperRemoteAccessConfig)
    nat: JuniperNATConfig = Field(default_factory=JuniperNATConfig)
    vpn: JuniperVPNConfig = Field(default_factory=JuniperVPNConfig)
    system_syslog: JuniperSyslogSettings = Field(default_factory=JuniperSyslogSettings)
    access_profiles: Dict[str, JuniperAccessProfile] = Field(default_factory=dict)
    dynamic_vpns: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    user_identification: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    utm_policies: Dict[str, JuniperSourceHierarchyItem] = Field(default_factory=dict)
    antivirus_profiles: Dict[str, JuniperUTMAntivirusProfile] = Field(default_factory=dict)
    web_filtering_profiles: Dict[str, JuniperUTMWebFilteringProfile] = Field(default_factory=dict)
    content_filtering_profiles: Dict[str, JuniperUTMContentFilteringProfile] = Field(default_factory=dict)
    anti_spam_profiles: Dict[str, JuniperUTMAntiSpamProfile] = Field(default_factory=dict)
    appsecure_rule_sets: Dict[str, JuniperAppSecureRuleSet] = Field(default_factory=dict)
    idp_policies: Dict[str, JuniperIDPPolicy] = Field(default_factory=dict)
    ssl_proxy_profiles: Dict[str, JuniperSSLProxyProfile] = Field(default_factory=dict)
    security_intelligence_feeds: Dict[str, JuniperSecurityIntelligenceFeed] = Field(default_factory=dict)
    security_intelligence_profiles: Dict[str, JuniperSecurityIntelligenceProfile] = Field(default_factory=dict)
    non_effective_candidate_history: Dict[str, List[JuniperEffectiveCandidate]] = Field(default_factory=dict)
    rpm_probes: Dict[str, JuniperRPMProbe] = Field(default_factory=dict)
    chassis: List[JuniperChassisItem] = Field(default_factory=list)
    security_flow: JuniperSecurityFlowSettings = Field(default_factory=JuniperSecurityFlowSettings)
    chassis_cluster: JuniperChassisCluster = Field(default_factory=JuniperChassisCluster)
    management_interfaces: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    security_profile: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @property
    def context(self) -> JuniperConfigContext:
        context_type = JuniperContextType(self.context_type)
        return JuniperConfigContext(
            context_type=context_type,
            name=None if context_type is JuniperContextType.ROOT else self.name,
        )
