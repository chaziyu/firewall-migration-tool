from __future__ import annotations
from typing import Dict, List, Optional
from pydantic import Field
from .base import CiscoSourceRecord


class CiscoFailoverSetting(CiscoSourceRecord):
    setting: Optional[str] = None


class CiscoFailoverGroup(CiscoSourceRecord):
    preempt: Optional[bool] = None
    replication_http: Optional[bool] = None
    interface_policy: Optional[str] = None
    polltime: Optional[str] = None
    raw_children: List[str] = Field(default_factory=list)
    extraction_status: str = "PARTIAL"
    group_id: Optional[int] = None
    unit_role: Optional[str] = None
    priority: Optional[int] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoFailoverInterfaceIP(CiscoSourceRecord):
    extraction_status: str = "PARTIAL"
    logical_name: Optional[str] = None
    interface: Optional[str] = None
    active_ip: Optional[str] = None
    standby_ip: Optional[str] = None
    netmask_or_prefix: Optional[str] = None
    address_family: str = "ipv4"
    raw_line: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoFailoverMACAddress(CiscoSourceRecord):
    extraction_status: str = "PARTIAL"
    interface: Optional[str] = None
    active_mac: Optional[str] = None
    standby_mac: Optional[str] = None
    raw_line: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoFailoverConfig(CiscoSourceRecord):
    extraction_status: str = "PARTIAL"
    enabled: Optional[bool] = None
    unit_role: Optional[str] = None
    lan_interface_name: Optional[str] = None
    lan_interface: Optional[str] = None
    stateful_link_name: Optional[str] = None
    stateful_link_interface: Optional[str] = None
    state_link_name: Optional[str] = None
    state_link_interface: Optional[str] = None
    interface_ips: List[CiscoFailoverInterfaceIP] = Field(default_factory=list)
    interface_monitoring: Dict[str, bool] = Field(default_factory=dict)
    failover_groups: List[CiscoFailoverGroup] = Field(default_factory=list)
    mac_addresses: List[CiscoFailoverMACAddress] = Field(default_factory=list)
    replication_http: Optional[bool] = None
    polltime: Optional[str] = None
    holdtime: Optional[str] = None
    timeout: Optional[str] = None
    key_present: bool = False
    review_reasons: List[str] = Field(default_factory=list)
