"""Vendor-native cisco_ftd interface models."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .base import CiscoFTDReference, CiscoFTDSourceRecord


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
    management_only: Optional[bool] = None
    security_level: Optional[int] = None
    ip: Optional[str] = None
    mask: Optional[str] = None
    standby_ip: Optional[str] = None
    ipv6_addresses: List["CiscoFTDIPv6Address"] = Field(default_factory=list)
    description: Optional[str] = None
    mtu: Optional[int] = None
    shutdown: Optional[bool] = None
    explicit_fields: List[str] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDIPv6Address(BaseModel):
    address: str
    prefix_length: Optional[int] = None
    standby: Optional[str] = None
    eui64: Optional[bool] = None
    link_local: Optional[bool] = None
    raw: str


class CiscoFTDStaticRoute(BaseModel):
    name: str
    interface: Optional[str] = None
    destination: Optional[str] = None
    mask: Optional[str] = None
    gateway: Optional[str] = None
    address_family: Optional[str] = None
    administrative_distance: Optional[int] = None
    raw_line: str
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFTDSecurityZone(CiscoFTDSourceRecord):
    interfaces: Optional[List[CiscoFTDReference]] = None


class CiscoFTDInterfaceGroup(CiscoFTDSourceRecord):
    interfaces: Optional[List[CiscoFTDReference]] = None


class CiscoFTDDeviceInterface(CiscoFTDSourceRecord):
    interface_type: Optional[str] = None
    address: Optional[str] = None
    zone: Optional[CiscoFTDReference] = None


class CiscoFTDInterfaceSource(CiscoFTDSourceRecord):
    interface_type: Optional[str] = None
    address: Optional[str] = None
    zone: Optional[str] = None
    management_only: Optional[bool] = None
    shutdown: Optional[bool] = None
    ipv6_addresses: Optional[List[CiscoFTDIPv6Address]] = None
