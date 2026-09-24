from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import Field
from .acl import CiscoACLBinding, CiscoAccessRule
from .address import CiscoNetworkGroup, CiscoNetworkObject
from .base import CiscoSourceModel, CiscoSourceRecord
from .context import CiscoASAContext, CiscoMultiContextSystem
from .dhcp import CiscoDHCPRelay, CiscoDHCPServer
from .diagnostics import CiscoDiagnostic
from .failover import CiscoFailoverConfig, CiscoFailoverSetting
from .groups import CiscoNamedGroup
from .identity import CiscoAAAAccountingRule, CiscoAAAAuthenticationRule, CiscoAAAAuthorizationRule, CiscoAAARecord, CiscoAAAServerGroup, CiscoAAAServerHost, CiscoCommandPrivilege, CiscoLocalUser
from .interface import CiscoInterface
from .management import CiscoConnectionControl, CiscoDNSServerGroup, CiscoDNSSettings, CiscoEnableCredential, CiscoHTTPServerConfig, CiscoICMPManagementRule, CiscoLoggingSetting, CiscoManagementAccessRule, CiscoManagementSetting, CiscoNTPServer, CiscoSNMPSetting, CiscoSystemSettings
from .mpf import CiscoClassMap, CiscoPolicyMap, CiscoServicePolicy, CiscoTCPMap
from .nat import CiscoNATRule
from .routing import CiscoRouteMap, CiscoSLAMonitor, CiscoStaticRoute, CiscoTrack
from .schedule import CiscoTimeRange
from .service import CiscoNetworkServiceObject, CiscoServiceGroup, CiscoServiceObject
from .vpn import CiscoCryptoMap, CiscoGroupPolicy, CiscoIKEPolicy, CiscoIKEv2Proposal, CiscoIPsecProfile, CiscoIPsecTransformSet, CiscoTrustpointRecord, CiscoTunnelGroup, CiscoVPNAddressAssignment, CiscoVPNAddressPool, CiscoWebVPNConfig
from .zone import CiscoTrafficZone


class CiscoASAConfig(CiscoSourceModel):
    hostname: Optional[str] = None
    interfaces: List[CiscoInterface] = Field(default_factory=list)
    traffic_zones: List[CiscoTrafficZone] = Field(default_factory=list)
    network_objects: List[CiscoNetworkObject] = Field(default_factory=list)
    network_groups: List[CiscoNetworkGroup] = Field(default_factory=list)
    protocol_groups: List[CiscoNamedGroup] = Field(default_factory=list)
    icmp_type_groups: List[CiscoNamedGroup] = Field(default_factory=list)
    user_groups: List[CiscoNamedGroup] = Field(default_factory=list)
    security_groups: List[CiscoNamedGroup] = Field(default_factory=list)
    network_service_objects: List[CiscoNetworkServiceObject] = Field(default_factory=list)
    network_service_groups: List[CiscoNetworkServiceObject] = Field(default_factory=list)
    service_objects: List[CiscoServiceObject] = Field(default_factory=list)
    service_groups: List[CiscoServiceGroup] = Field(default_factory=list)
    access_rules: List[CiscoAccessRule] = Field(default_factory=list)
    acl_bindings: List[CiscoACLBinding] = Field(default_factory=list)
    nat_rules: List[CiscoNATRule] = Field(default_factory=list)
    static_routes: List[CiscoStaticRoute] = Field(default_factory=list)
    route_tracking_ids: List[int] = Field(default_factory=list)
    tracks: List[CiscoTrack] = Field(default_factory=list)
    sla_monitors: List[CiscoSLAMonitor] = Field(default_factory=list)
    dynamic_routing: List[CiscoSourceRecord] = Field(default_factory=list)
    route_maps: List[CiscoRouteMap] = Field(default_factory=list)
    time_ranges: List[CiscoTimeRange] = Field(default_factory=list)
    ike_policies: List[CiscoIKEPolicy] = Field(default_factory=list)
    ikev2_proposals: List[CiscoIKEv2Proposal] = Field(default_factory=list)
    ipsec_transform_sets: List[CiscoIPsecTransformSet] = Field(default_factory=list)
    ipsec_profiles: List[CiscoIPsecProfile] = Field(default_factory=list)
    vpn_address_pools: List[CiscoVPNAddressPool] = Field(default_factory=list)
    trustpoints: List[str] = Field(default_factory=list)
    crypto_maps: List[CiscoCryptoMap] = Field(default_factory=list)
    tunnel_groups: List[CiscoTunnelGroup] = Field(default_factory=list)
    group_policies: List[CiscoGroupPolicy] = Field(default_factory=list)
    webvpn: Optional[CiscoWebVPNConfig] = None
    webvpn_configs: List[CiscoWebVPNConfig] = Field(default_factory=list)
    vpn_address_assignment: Optional[CiscoVPNAddressAssignment] = None
    vpn_address_assignments: List[CiscoVPNAddressAssignment] = Field(default_factory=list)
    command_privileges: List[CiscoCommandPrivilege] = Field(default_factory=list)
    aaa_records: List[CiscoAAARecord] = Field(default_factory=list)
    aaa_server_groups: List[CiscoAAAServerGroup] = Field(default_factory=list)
    aaa_server_hosts: List[CiscoAAAServerHost] = Field(default_factory=list)
    local_users: List[CiscoLocalUser] = Field(default_factory=list)
    aaa_authentication_rules: List[CiscoAAAAuthenticationRule] = Field(default_factory=list)
    aaa_authorization_rules: List[CiscoAAAAuthorizationRule] = Field(default_factory=list)
    aaa_accounting_rules: List[CiscoAAAAccountingRule] = Field(default_factory=list)
    class_maps: List[CiscoClassMap] = Field(default_factory=list)
    policy_maps: List[CiscoPolicyMap] = Field(default_factory=list)
    service_policies: List[CiscoServicePolicy] = Field(default_factory=list)
    tcp_maps: List[CiscoTCPMap] = Field(default_factory=list)
    dhcp_servers: List[CiscoDHCPServer] = Field(default_factory=list)
    dhcp_relays: List[CiscoDHCPRelay] = Field(default_factory=list)
    dns_server_groups: List[CiscoDNSServerGroup] = Field(default_factory=list)
    dns_settings: CiscoDNSSettings = Field(default_factory=lambda: CiscoDNSSettings(name="system-dns"))
    connection_controls: List[CiscoConnectionControl] = Field(default_factory=list)
    management_settings: List[CiscoManagementSetting] = Field(default_factory=list)
    system_settings: CiscoSystemSettings = Field(default_factory=lambda: CiscoSystemSettings(name="system"))
    ntp_servers: List[CiscoNTPServer] = Field(default_factory=list)
    management_access_rules: List[CiscoManagementAccessRule] = Field(default_factory=list)
    icmp_management_rules: List[CiscoICMPManagementRule] = Field(default_factory=list)
    snmp_settings: List[CiscoSNMPSetting] = Field(default_factory=list)
    logging_settings: List[CiscoLoggingSetting] = Field(default_factory=list)
    enable_credentials: List[CiscoEnableCredential] = Field(default_factory=list)
    failover_settings: List[CiscoFailoverSetting] = Field(default_factory=list)
    failover_config: CiscoFailoverConfig = Field(default_factory=lambda: CiscoFailoverConfig(name="failover"))
    contexts: List[CiscoASAContext] = Field(default_factory=list)
    trustpoint_records: List[CiscoTrustpointRecord] = Field(default_factory=list)
    http_server: CiscoHTTPServerConfig = Field(default_factory=CiscoHTTPServerConfig)
    multi_context_system: CiscoMultiContextSystem = Field(default_factory=CiscoMultiContextSystem)
    acl_consumers: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)
    unsupported_commands: List[Dict[str, Any]] = Field(default_factory=list)
    parse_errors: List[Dict[str, Any]] = Field(default_factory=list)
    diagnostics: List[CiscoDiagnostic] = Field(default_factory=list)
