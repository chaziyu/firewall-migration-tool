"""Vendor-native juniper_srx administration models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from .common import JuniperEffectiveModel, JuniperSourceHierarchyItem, JuniperSourceProvenance


class JuniperScheduler(JuniperEffectiveModel):
    name: str
    description: Optional[str] = None
    start_date: Optional[str] = None
    stop_date: Optional[str] = None
    daily: List[str] = Field(default_factory=list)
    weekdays: Dict[str, str] = Field(default_factory=dict)
    daily_windows: List[Dict[str, Any]] = Field(default_factory=list)
    weekday_windows: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)
    exclusions: List[Dict[str, Any]] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: JuniperSourceProvenance = Field(default_factory=JuniperSourceProvenance)


class JuniperDNSNameServer(BaseModel):
    server: str
    routing_instance: Optional[str] = None
    source_interface: Optional[str] = None


class JuniperNTPServer(BaseModel):
    address: str
    role: str
    preferred: Optional[bool] = None
    routing_instance: Optional[str] = None
    authentication_key_reference: Optional[str] = None


class JuniperNTPSettings(BaseModel):
    servers: List[JuniperNTPServer] = Field(default_factory=list)
    source_address: Optional[str] = None
    source_interface: Optional[str] = None
    routing_instance: Optional[str] = None
    authentication_keys: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperLoginClass(JuniperSourceHierarchyItem):
    pass


class JuniperAdminUser(JuniperSourceHierarchyItem):
    login_class: Optional[str] = None


class JuniperSSHSettings(BaseModel):
    enabled: Optional[bool] = None
    options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperNETCONFSettings(BaseModel):
    enabled: Optional[bool] = None
    options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperWebManagementSettings(BaseModel):
    http_enabled: Optional[bool] = None
    https_enabled: Optional[bool] = None
    http_options: Dict[str, Any] = Field(default_factory=dict)
    https_options: Dict[str, Any] = Field(default_factory=dict)
    interfaces: List[str] = Field(default_factory=list)
    certificate_references: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSNMPSettings(BaseModel):
    communities: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    trap_groups: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSyslogSettings(BaseModel):
    destinations: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    files: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    source_address: Optional[str] = None
    source_interface: Optional[str] = None
    routing_instance: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperCertificate(BaseModel):
    name: str
    certificate_id: Optional[str] = None
    ca_profile: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperPKISettings(BaseModel):
    certificates: Dict[str, JuniperCertificate] = Field(default_factory=dict)
    ca_profiles: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    references: Dict[str, List[str]] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperSecurityFlowSettings(BaseModel):
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperClusterIPMonitorTarget(BaseModel):
    address: str
    weight: Optional[int] = None
    interface: Optional[str] = None
    secondary_ip_address: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperClusterIPMonitoring(BaseModel):
    global_threshold: Optional[int] = None
    global_weight: Optional[int] = None
    retry_count: Optional[int] = None
    retry_interval: Optional[int] = None
    targets: List[JuniperClusterIPMonitorTarget] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperClusterPreempt(BaseModel):
    delay: Optional[int] = None
    limit: Optional[int] = None
    period: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRedundancyGroup(BaseModel):
    group_id: str
    nodes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    interface_monitors: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    ip_monitoring: Optional[JuniperClusterIPMonitoring] = None
    preempt: Optional[JuniperClusterPreempt] = None
    hold_down_interval: Optional[int] = None
    gratuitous_arp_count: Optional[int] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperChassisCluster(BaseModel):
    cluster_id: Optional[str] = None
    nodes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    redundancy_groups: Dict[str, JuniperRedundancyGroup] = Field(default_factory=dict)
    fabric_interfaces: List[Dict[str, Any]] = Field(default_factory=list)
    control_links: List[Dict[str, Any]] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperDHCPRange(BaseModel):
    name: str
    low: Optional[str] = None
    high: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperDHCPHostReservation(BaseModel):
    name: str
    hardware_address: Optional[str] = None
    ip_address: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperDHCPAttributes(BaseModel):
    router: List[str] = Field(default_factory=list)
    name_servers: List[str] = Field(default_factory=list)
    lease_time: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAddressAssignmentFamily(BaseModel):
    name: str
    ranges: Dict[str, JuniperDHCPRange] = Field(default_factory=dict)
    hosts: Dict[str, JuniperDHCPHostReservation] = Field(default_factory=dict)
    dhcp_attributes: JuniperDHCPAttributes = Field(default_factory=JuniperDHCPAttributes)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAddressAssignmentPool(BaseModel):
    name: str
    routing_instance: Optional[str] = None
    families: Dict[str, JuniperAddressAssignmentFamily] = Field(default_factory=dict)
    linked_pool: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperDHCPLocalServerGroup(BaseModel):
    name: str
    routing_instance: Optional[str] = None
    family: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperDHCPRelayGroup(BaseModel):
    name: str
    routing_instance: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    server_groups: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperLegacyDHCPConfig(BaseModel):
    commands: List[Dict[str, Any]] = Field(default_factory=list)


class JuniperDHCPConfig(BaseModel):
    local_servers: Dict[str, JuniperDHCPLocalServerGroup] = Field(default_factory=dict)
    address_assignment_pools: Dict[str, JuniperAddressAssignmentPool] = Field(default_factory=dict)
    relay_groups: Dict[str, JuniperDHCPRelayGroup] = Field(default_factory=dict)
    legacy: JuniperLegacyDHCPConfig = Field(default_factory=JuniperLegacyDHCPConfig)


class JuniperAccessFirewallUser(BaseModel):
    name: str
    password_configured: Optional[bool] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAccessClient(BaseModel):
    name: str
    client_groups: List[str] = Field(default_factory=list)
    firewall_user: Optional[JuniperAccessFirewallUser] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAccessProfile(BaseModel):
    name: str
    clients: Dict[str, JuniperAccessClient] = Field(default_factory=dict)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
