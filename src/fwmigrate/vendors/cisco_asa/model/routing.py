from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import Field
from .base import CiscoSourceModel


class CiscoStaticRoute(CiscoSourceModel):
    source_context: Optional[str] = None
    interface: Optional[str] = None
    destination: Optional[str] = None
    mask: Optional[str] = None
    gateway: Optional[str] = None
    administrative_distance: Optional[int] = None
    address_family: str = "ipv4"
    routing_context: Optional[str] = None
    track_id: Optional[int] = None
    tunneled: bool = False
    raw_options: List[str] = Field(default_factory=list)
    raw_line: str = ""
    extraction_status: str = "EXTRACTED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoTrack(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "PARTIAL"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    track_id: int
    track_type: Optional[str] = None
    sla_id: Optional[int] = None
    target: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoSLAMonitor(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "SOURCE_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    sla_id: int
    operation: Optional[str] = None
    frequency: Optional[int] = None
    target: Optional[str] = None
    interface: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoRouteMapRule(CiscoSourceModel):
    name: str
    sequence: int
    action: Optional[str] = None
    match_acl: Optional[str] = None
    match_acls: List[str] = Field(default_factory=list)
    set_next_hop: Optional[str] = None
    next_hops: List[str] = Field(default_factory=list)
    set_interface: Optional[str] = None
    output_interfaces: List[str] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    raw_options: List[str] = Field(default_factory=list)
    extraction_status: str = "PARTIAL"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoRouteMap(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    rules: List[CiscoRouteMapRule] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)


class CiscoPolicyRoutePathMonitor(CiscoSourceModel):
    mode: str
    peer: Optional[str] = None
    raw: str = ""
    source_order: int = 0
