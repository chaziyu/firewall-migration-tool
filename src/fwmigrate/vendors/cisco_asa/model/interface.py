from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .base import CiscoSourceModel


class CiscoInterface(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    interface_type: Optional[str] = None
    parent_interface: Optional[str] = None
    vlan_id: Optional[int] = None
    interface_suffix_vlan_id: Optional[int] = None
    secondary_vlan_ids: List[int] = Field(default_factory=list)
    secondary_vlan_ranges: List[str] = Field(default_factory=list)
    port_channel_id: Optional[int] = None
    channel_group: Optional[int] = None
    channel_group_mode: Optional[str] = None
    redundant_interface_members: List[str] = Field(default_factory=list)
    bridge_group: Optional[int] = None
    bvi_id: Optional[int] = None
    mtu: Optional[int] = None
    routing_context: Optional[str] = None
    vrf: Optional[str] = None
    administrative_state: Optional[str] = None
    nameif: Optional[str] = None
    ip: Optional[str] = None
    mask: Optional[str] = None
    ip_mode: Optional[str] = None
    standby_ip: Optional[str] = None
    dhcp_setroute: bool = False
    ipv6_addresses: List["CiscoIPv6Address"] = Field(default_factory=list)
    ipv6_autoconfig: bool = False
    ipv6_dhcp: bool = False
    ipv6_dhcp_setroute: bool = False
    management_only: bool = False
    security_level: Optional[int] = None
    description: Optional[str] = None
    shutdown: Optional[bool] = None
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "PARTIAL"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    policy_route_maps: List[str] = Field(default_factory=list)
    policy_route_cost: Optional[str] = None
    policy_route_path_monitors: List["CiscoPolicyRoutePathMonitor"] = Field(default_factory=list)
    tunnel_source: Optional[str] = None
    tunnel_destination: Optional[str] = None
    ipsec_profile: Optional[str] = None
    ipsec_policy_acl: Optional[str] = None
    traffic_zone_members: List[str] = Field(default_factory=list)


class CiscoIPv6Address(BaseModel):
    address: str
    standby: Optional[str] = None
    eui64: bool = False
    link_local: bool = False
    raw: str = ""


from .routing import CiscoPolicyRoutePathMonitor
