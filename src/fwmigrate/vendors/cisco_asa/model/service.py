from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .base import CiscoSourceModel


class CiscoNetworkServiceObject(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "PARTIAL"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoPortSpec(BaseModel):
    operator: str
    values: List[str] = Field(default_factory=list)
    object_name: Optional[str] = None
    raw: str = ""


class CiscoServicePort(BaseModel):
    protocol: str
    destination: Optional[CiscoPortSpec] = None
    source: Optional[CiscoPortSpec] = None
    icmp_type: Optional[str] = None
    icmp_code: Optional[int] = None
    raw: str = ""


class CiscoServiceGroupMember(CiscoSourceModel):
    type: str
    value: Optional[str] = None
    raw: str = ""
    protocol: Optional[str] = None
    destination: Optional[CiscoPortSpec] = None
    source: Optional[CiscoPortSpec] = None
    icmp_type: Optional[str] = None
    icmp_code: Optional[int] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoServiceObject(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    ports: List[CiscoServicePort] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "EXTRACTED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoServiceGroup(CiscoSourceModel):
    name: str
    source_context: Optional[str] = None
    protocol: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    service_objects: List[CiscoServicePort] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "EXTRACTED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    member_entries: List[CiscoServiceGroupMember] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
