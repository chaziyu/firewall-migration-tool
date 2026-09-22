from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CiscoFTDManagementSetting(BaseModel):
    name: str
    setting: str
    values: List[str] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDInterface(BaseModel):
    name: str
    interface_type: Optional[str] = None
    parent_interface: Optional[str] = None
    vlan_id: Optional[int] = None
    etherchannel_id: Optional[int] = None
    etherchannel_mode: Optional[str] = None
    bridge_group: Optional[int] = None
    nameif: Optional[str] = None
    management_only: bool = False
    security_level: Optional[int] = None
    ip: Optional[str] = None
    mask: Optional[str] = None
    standby_ip: Optional[str] = None
    ipv6_addresses: List["CiscoFTDIPv6Address"] = Field(default_factory=list)
    description: Optional[str] = None
    mtu: Optional[int] = None
    shutdown: bool = False
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDIPv6Address(BaseModel):
    address: str
    prefix_length: Optional[int] = None
    standby: Optional[str] = None
    eui64: bool = False
    link_local: bool = False
    raw: str


class CiscoFTDStaticRoute(BaseModel):
    name: str
    interface: Optional[str] = None
    destination: Optional[str] = None
    mask: Optional[str] = None
    gateway: Optional[str] = None
    address_family: str = "ipv4"
    administrative_distance: Optional[int] = None
    raw_line: str
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDSourceRecord(BaseModel):
    """Vendor-native record retained from one authoritative FTD source plane."""

    name: str
    source_id: Optional[str] = None
    source_plane: str
    source_context: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    raw: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDObject(CiscoFTDSourceRecord):
    object_type: Optional[str] = None
    value: Optional[Any] = None
    members: List[str] = Field(default_factory=list)


class CiscoFTDService(CiscoFTDSourceRecord):
    protocol: Optional[str] = None
    ports: List[Any] = Field(default_factory=list)
    members: List[str] = Field(default_factory=list)


class CiscoFTDZone(CiscoFTDSourceRecord):
    interfaces: List[str] = Field(default_factory=list)


class CiscoFTDInterfaceSource(CiscoFTDSourceRecord):
    interface_type: Optional[str] = None
    address: Optional[str] = None
    zone: Optional[str] = None


class CiscoFTDRoute(CiscoFTDSourceRecord):
    interface: Optional[str] = None
    destination: Optional[str] = None
    gateway: Optional[str] = None


class CiscoFTDACPRule(CiscoFTDSourceRecord):
    policy: Optional[str] = None
    action: Optional[str] = None
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    source_zones: List[str] = Field(default_factory=list)
    destination_zones: List[str] = Field(default_factory=list)
    order: Optional[int] = None


class CiscoFTDNATRule(CiscoFTDSourceRecord):
    policy: Optional[str] = None
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    original: Dict[str, Any] = Field(default_factory=dict)
    translated: Dict[str, Any] = Field(default_factory=dict)
    order: Optional[int] = None


class CiscoFTDConfig(BaseModel):
    source_vendor: str = "cisco_ftd"
    source_product: str = "Cisco Firepower Threat Defense"
    version: Optional[str] = None
    cmi_enabled: Optional[bool] = None
    management_ipv4: Optional[str] = None
    management_netmask: Optional[str] = None
    management_gateway: Optional[str] = None
    management_dns_servers: List[str] = Field(default_factory=list)
    ssh_access_list: List[str] = Field(default_factory=list)
    diagnostic_interface: Optional[str] = None
    interfaces: List[CiscoFTDInterface] = Field(default_factory=list)
    static_routes: List[CiscoFTDStaticRoute] = Field(default_factory=list)
    management_settings: List[CiscoFTDManagementSetting] = Field(default_factory=list)
    input_source_type: str = "ftd-text-evidence"
    source_plane: str = "ftd-cli"
    source_metadata: Dict[str, Any] = Field(default_factory=dict)
    managed_objects: List[CiscoFTDObject] = Field(default_factory=list)
    object_groups: List[CiscoFTDObject] = Field(default_factory=list)
    services: List[CiscoFTDService] = Field(default_factory=list)
    security_zones: List[CiscoFTDZone] = Field(default_factory=list)
    source_interfaces: List[CiscoFTDInterfaceSource] = Field(default_factory=list)
    routes: List[CiscoFTDRoute] = Field(default_factory=list)
    acp_rules: List[CiscoFTDACPRule] = Field(default_factory=list)
    nat_policies: List[CiscoFTDNATRule] = Field(default_factory=list)
    unsupported_evidence: List[Dict[str, Any]] = Field(default_factory=list)
