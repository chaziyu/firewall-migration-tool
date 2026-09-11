from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CiscoFTDManagementSetting(BaseModel):
    name: str
    setting: str
    values: List[str] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True


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
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)


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
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


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
