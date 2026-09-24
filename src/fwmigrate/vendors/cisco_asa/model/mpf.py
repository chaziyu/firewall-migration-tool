from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .base import CiscoSourceModel, CiscoSourceRecord


class CiscoInspectionPolicySection(CiscoSourceModel):
    kind: str
    header: str
    source_order: int
    class_name: Optional[str] = None
    match_expression: Optional[str] = None
    negated: bool = False
    actions: List[str] = Field(default_factory=list)
    parameters: List[str] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoTCPMapSetting(CiscoSourceModel):
    key: str
    values: List[str] = Field(default_factory=list)
    negated: bool = False
    raw: str = ""
    source_order: int = 0
    supported: bool = True


class CiscoClassMapMatch(CiscoSourceModel):
    negated: bool = False
    expression: List[str] = Field(default_factory=list)
    inspection_expression: Optional[str] = None
    match_type: str
    value: Optional[str] = None
    acl_name: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[str] = None
    class_map_name: Optional[str] = None
    raw: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoClassMap(CiscoSourceRecord):
    class_map_type: Optional[str] = None
    inspection_protocol: Optional[str] = None
    typed: bool = False
    match_type: Optional[str] = None
    matches: List[CiscoClassMapMatch] = Field(default_factory=list)
    match_any: Optional[bool] = None
    match_all: Optional[bool] = None
    description: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)
    match_lines: List[str] = Field(default_factory=list)


class CiscoInspectAction(BaseModel):
    protocol: str
    policy_name: Optional[str] = None
    parameters: List[str] = Field(default_factory=list)
    raw: str = ""
    source_order: int = 0
    extraction_status: str = "EXTRACTED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoMPFConnectionAction(BaseModel):
    syn_cookie_mss: Optional[int] = None
    advanced_options: Optional[str] = None
    timeouts: Dict[str, str] = Field(default_factory=dict)
    negated: bool = False
    raw_options: List[str] = Field(default_factory=list)
    max_connections: Optional[int] = None
    max_embryonic: Optional[int] = None
    per_client_max: Optional[int] = None
    per_client_embryonic: Optional[int] = None
    random_sequence_number: Optional[str] = None
    tcp_intercept: Optional[str] = None
    timeout_embryonic: Optional[str] = None
    raw: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoMPFPoliceAction(BaseModel):
    direction: Optional[str] = None
    negated: bool = False
    raw_options: List[str] = Field(default_factory=list)
    rate: Optional[int] = None
    burst: Optional[int] = None
    conform_action: Optional[str] = None
    exceed_action: Optional[str] = None
    raw: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoPolicyMapClass(CiscoSourceModel):
    class_name: str
    source_order: int = 0
    inspect_actions: List[CiscoInspectAction] = Field(default_factory=list)
    connection_actions: List[CiscoMPFConnectionAction] = Field(default_factory=list)
    police_actions: List[CiscoMPFPoliceAction] = Field(default_factory=list)
    ips_actions: List["CiscoIPSAction"] = Field(default_factory=list)
    tcp_map: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    extraction_status: str = "PARTIAL"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoPolicyMap(CiscoSourceRecord):
    policy_map_type: Optional[str] = None
    inspection_protocol: Optional[str] = None
    typed: bool = False
    inspection_sections: List[CiscoInspectionPolicySection] = Field(default_factory=list)
    parameter_lines: List[str] = Field(default_factory=list)
    classes: List[CiscoPolicyMapClass] = Field(default_factory=list)
    description: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)
    class_sections: List[str] = Field(default_factory=list)


class CiscoTCPMap(CiscoSourceRecord):
    setting_entries: List[CiscoTCPMapSetting] = Field(default_factory=list)
    setting_history: Dict[str, List[str]] = Field(default_factory=dict)
    settings: Dict[str, Any] = Field(default_factory=dict)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoServicePolicy(CiscoSourceRecord):
    enabled: Optional[bool] = None
    negated: bool = False
    fail_close: bool = False
    attachment: Optional[str] = None
    policy_name: Optional[str] = None
    scope: Optional[str] = None
    global_attachment: bool = False
    interface: Optional[str] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoIPSAction(CiscoSourceModel):
    mode: str
    failure_mode: str
    sensor: Optional[str] = None
    raw: str = ""
    source_order: int = 0
