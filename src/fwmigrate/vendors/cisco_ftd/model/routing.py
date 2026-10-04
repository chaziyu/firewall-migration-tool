"""Vendor-native cisco_ftd routing models."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from .base import CiscoFTDReference, CiscoFTDSourceRecord


class CiscoFTDRoute(CiscoFTDSourceRecord):
    interface: Optional[CiscoFTDReference] = None
    destination: Optional[CiscoFTDReference] = None
    selected_networks: Optional[List[CiscoFTDReference]] = None
    gateway: Optional[CiscoFTDReference] = None
    address_family: Optional[str] = None
    metric: Optional[int] = None
    virtual_router: Optional[str] = None
    virtual_router_ref: Optional[CiscoFTDReference] = None
    sla_monitor: Optional[CiscoFTDReference] = None
    route_tracking: Optional[Dict[str, Any]] = None
    tunneled: Optional[bool] = None
    device_id: Optional[str] = None


class CiscoFTDApplication(CiscoFTDSourceRecord): pass


class CiscoFTDSLAMonitor(CiscoFTDSourceRecord): pass


class CiscoFTDVirtualRouter(CiscoFTDSourceRecord):
    interfaces: Optional[List[CiscoFTDReference]] = None


class CiscoFTDPolicyBasedRoute(CiscoFTDSourceRecord):
    virtual_router: Optional[CiscoFTDReference] = None
    ingress_interface: Optional[CiscoFTDReference] = None
    egress_interface: Optional[CiscoFTDReference] = None
    path_interface: Optional[CiscoFTDReference] = None
    networks: Optional[List[CiscoFTDReference]] = None
    sla_monitor: Optional[CiscoFTDReference] = None
    position: Optional[int] = None


class CiscoFTDECMPZone(CiscoFTDSourceRecord):
    interfaces: Optional[List[CiscoFTDReference]] = None
