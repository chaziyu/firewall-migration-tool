"""Vendor-native juniper_srx routing models."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand
from .common import JuniperEffectiveModel


class JuniperRouteNextHop(JuniperEffectiveModel):
    value: str
    qualified: bool
    preference: Optional[int] = None
    metric: Optional[int] = None
    tag: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRoute(JuniperEffectiveModel):
    destination: str
    routing_instance: Optional[str] = None
    next_hops: List[JuniperRouteNextHop] = Field(default_factory=list)
    next_table: Optional[str] = None
    preference: Optional[int] = None
    metric: Optional[int] = None
    tag: Optional[int] = None
    disabled: Optional[bool] = None
    retain: Optional[bool] = None
    installation: Optional[str] = None
    action: Optional[str] = None
    rib: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperPrefixList(BaseModel):
    name: str
    entries: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperCoSScheduler(BaseModel):
    name: str
    transmit_rate: Optional[str] = None
    shaping_rate: Optional[str] = None
    priority: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperVLAN(BaseModel):
    name: str
    vlan_id: Optional[int] = None
    l3_interface: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperRoutingInstance(JuniperEffectiveModel):
    name: str
    instance_type: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    route_distinguisher: Optional[str] = None
    import_policies: List[str] = Field(default_factory=list)
    export_policies: List[str] = Field(default_factory=list)
    routing_options: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAPBRMetricsProfile(BaseModel):
    name: str
    jitter: Optional[str] = None
    packet_loss: Optional[str] = None
    round_trip_delay: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAPBRProbeParams(BaseModel):
    name: str
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAPBRActiveProbeParams(JuniperAPBRProbeParams):
    pass


class JuniperAPBRPassiveProbeParams(JuniperAPBRProbeParams):
    pass


class JuniperAPBROverlayPath(BaseModel):
    name: str
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAPBRDestinationPathGroup(BaseModel):
    name: str
    probe_routing_instance: Optional[str] = None
    overlay_paths: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAPBRMultipathRule(BaseModel):
    name: str
    bandwidth_limit: Optional[str] = None
    applications: List[str] = Field(default_factory=list)
    application_groups: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAPBRSLARule(BaseModel):
    name: str
    metrics_profile: Optional[str] = None
    active_probe_params: Optional[str] = None
    passive_probe_params: Optional[str] = None
    multipath_rule: Optional[str] = None
    switch_idle_time: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class JuniperAPBRConfig(BaseModel):
    metrics_profiles: Dict[str, JuniperAPBRMetricsProfile] = Field(default_factory=dict)
    active_probe_params: Dict[str, JuniperAPBRActiveProbeParams] = Field(default_factory=dict)
    passive_probe_params: Dict[str, JuniperAPBRPassiveProbeParams] = Field(default_factory=dict)
    overlay_paths: Dict[str, JuniperAPBROverlayPath] = Field(default_factory=dict)
    destination_path_groups: Dict[str, JuniperAPBRDestinationPathGroup] = Field(default_factory=dict)
    multipath_rules: Dict[str, JuniperAPBRMultipathRule] = Field(default_factory=dict)
    sla_rules: Dict[str, JuniperAPBRSLARule] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
