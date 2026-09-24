from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .base import CiscoSourceRecord


class CiscoHTTPServerConfig(BaseModel):
    enabled: Optional[bool] = None
    port: Optional[int] = None
    idle_timeout: Optional[int] = None
    session_timeout: Optional[int] = None
    raw_lines: List[str] = Field(default_factory=list)
    source_order: Optional[int] = None
    extraction_status: str = "PARTIAL"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoDNSServerGroup(CiscoSourceRecord):
    retries: Optional[int] = None
    timeout: Optional[int] = None
    expire_entry_timer: Optional[int] = None
    poll_timer: Optional[int] = None
    child_order: List[str] = Field(default_factory=list)
    raw_settings: List[Dict[str, Any]] = Field(default_factory=list)
    name_servers: List[str] = Field(default_factory=list)
    domain_name: Optional[str] = None
    interface_lookup: List[str] = Field(default_factory=list)
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoDNSSettings(CiscoSourceRecord):
    name_servers: List[str] = Field(default_factory=list)
    command_history: List[str] = Field(default_factory=list)
    domain_name: Optional[str] = None
    lookup_interfaces: List[str] = Field(default_factory=list)
    default_server_group: Optional[str] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoConnectionControl(CiscoSourceRecord):
    negated: bool = False
    statistics_target: Optional[str] = None
    number_of_rate: Optional[int] = None
    rate_interval: Optional[int] = None
    average_rate: Optional[int] = None
    burst_rate: Optional[int] = None
    raw_parameters: List[str] = Field(default_factory=list)
    setting: Optional[str] = None
    values: List[str] = Field(default_factory=list)
    control_type: Optional[str] = None
    max_connections: Optional[int] = None
    max_embryonic: Optional[int] = None
    per_client_max: Optional[int] = None
    per_client_embryonic: Optional[int] = None
    timeout_embryonic: Optional[str] = None
    timeout_half_closed: Optional[str] = None
    timeout_tcp: Optional[str] = None
    timeout_udp: Optional[str] = None
    timeout_icmp: Optional[str] = None
    timeout_xlate: Optional[str] = None
    timeout_pat_xlate: Optional[str] = None
    timeout_sunrpc: Optional[str] = None
    timeout_h225: Optional[str] = None
    timeout_h323: Optional[str] = None
    timeout_sip: Optional[str] = None
    timeout_sip_media: Optional[str] = None
    tcp_map: Optional[str] = None
    rate: Optional[int] = None
    burst: Optional[int] = None
    threat_detection_type: Optional[str] = None
    enabled: Optional[bool] = None
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoManagementSetting(CiscoSourceRecord):
    setting: Optional[str] = None
    enabled: Optional[bool] = None


class CiscoSystemSettings(CiscoSourceRecord):
    extraction_status: str = "PARTIAL"
    hostname: Optional[str] = None
    domain_name: Optional[str] = None
    timezone_name: Optional[str] = None
    timezone_offset: Optional[int] = None
    dst_name: Optional[str] = None
    management_access_interface: Optional[str] = None
    same_security_inter: Optional[bool] = None
    same_security_intra: Optional[bool] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoNTPServer(CiscoSourceRecord):
    negated: bool = False
    extraction_status: str = "PARTIAL"
    server: Optional[str] = None
    interface: Optional[str] = None
    prefer: bool = False
    key_id: Optional[str] = None
    source_order: int = 0
    raw_line: str = ""
    review_reasons: List[str] = Field(default_factory=list)


class CiscoManagementAccessRule(CiscoSourceRecord):
    address_family: Optional[str] = None
    negated: bool = False
    extraction_status: str = "PARTIAL"
    protocol: str
    source: Optional[str] = None
    mask_or_prefix: Optional[str] = None
    interface: Optional[str] = None
    port: Optional[int] = None
    raw_line: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoICMPManagementRule(CiscoSourceRecord):
    action: str
    source: Optional[str] = None
    interface: Optional[str] = None
    icmp_type: Optional[str] = None
    raw_line: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)


class CiscoSNMPSetting(CiscoSourceRecord):
    extraction_status: str = "PARTIAL"
    setting_type: str
    host: Optional[str] = None
    interface: Optional[str] = None
    community_present: bool = False
    version: Optional[str] = None
    username: Optional[str] = None
    trap_types: List[str] = Field(default_factory=list)
    location: Optional[str] = None
    contact: Optional[str] = None
    source_order: int = 0
    raw_line: str = ""
    review_reasons: List[str] = Field(default_factory=list)


class CiscoLoggingSetting(CiscoSourceRecord):
    extraction_status: str = "PARTIAL"
    setting_type: str
    enabled: Optional[bool] = None
    host: Optional[str] = None
    interface: Optional[str] = None
    severity: Optional[str] = None
    facility: Optional[str] = None
    buffer_size: Optional[int] = None
    timestamp: Optional[bool] = None
    source_order: int = 0
    raw_line: str = ""
    review_reasons: List[str] = Field(default_factory=list)


class CiscoEnableCredential(CiscoSourceRecord):
    extraction_status: str = "PARTIAL"
    password_present: bool = False
    secret_present: bool = False
    encrypted: bool = False
    raw_line: str = ""
    source_order: int = 0
    review_reasons: List[str] = Field(default_factory=list)
