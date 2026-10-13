from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .base import CiscoSourceModel
from .service import CiscoPortSpec


class CiscoACLEndpoint(BaseModel):
    type: str
    value: Optional[str] = None
    address_family: Optional[str] = None
    raw: str
    valid: bool = True


class CiscoACLBinding(CiscoSourceModel):
    acl_name: str
    source_context: Optional[str] = None
    interface: Optional[str] = None
    direction: Optional[str] = None
    control_plane: bool = False
    per_user_override: bool = False
    raw_line: str
    line_number: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    extraction_status: str = "EXTRACTED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoAccessRule(CiscoSourceModel):
    id: str
    acl_name: str
    source_context: Optional[str] = None
    acl_type: str = "extended"
    source_line_number: Optional[int] = None
    source_order: Optional[int] = None
    source_sequence: Optional[int] = None
    action: Optional[str] = None
    protocol: Optional[str] = None
    protocol_object: Optional[str] = None
    protocol_reference_type: Optional[str] = None
    source_endpoint: Optional[CiscoACLEndpoint] = None
    source_port: Optional[CiscoPortSpec] = None
    destination_endpoint: Optional[CiscoACLEndpoint] = None
    destination_port: Optional[CiscoPortSpec] = None
    service: Optional[str] = None
    icmp_type: Optional[str] = None
    icmp_code: Optional[int] = None
    time_range: Optional[str] = None
    log_enabled: Optional[bool] = None
    log_level: Optional[str] = None
    log_interval: Optional[int] = None
    log_raw: Optional[str] = None
    inactive: bool = False
    user: Optional[str] = None
    user_group: Optional[str] = None
    security_group: Optional[str] = None
    source_security_group_type: Optional[str] = None
    source_security_group_value: Optional[str] = None
    destination_security_group_type: Optional[str] = None
    destination_security_group_value: Optional[str] = None
    icmp_object_group: Optional[str] = None
    remark: Optional[str] = None
    raw_line: str = ""
    extraction_status: str = "EXTRACTED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoACLRemark(CiscoSourceModel):
    name: str
    acl_name: str
    source_context: Optional[str] = None
    sequence: Optional[int] = None
    source_order: Optional[int] = None
    remark: str = ""
    raw_line: str = ""
