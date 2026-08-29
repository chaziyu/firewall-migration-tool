from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class CiscoInterface(BaseModel):
    name: str
    nameif: Optional[str] = None
    ip: Optional[str] = None
    mask: Optional[str] = None
    ip_mode: Optional[str] = None
    security_level: Optional[int] = None
    description: Optional[str] = None
    shutdown: bool = False
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoNetworkObject(BaseModel):
    name: str
    type: Optional[str] = None
    value: Optional[str] = None
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    nat_lines: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoNetworkGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False


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


class CiscoServiceObject(BaseModel):
    name: str
    ports: List[CiscoServicePort] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False


class CiscoServiceGroup(BaseModel):
    name: str
    protocol: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    service_objects: List[CiscoServicePort] = Field(default_factory=list)
    description: Optional[str] = None
    raw_lines: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False


class CiscoACLEndpoint(BaseModel):
    type: str
    value: Optional[str] = None
    address_family: Optional[str] = None
    raw: str
    valid: bool = True


class CiscoACLBinding(BaseModel):
    acl_name: str
    interface: Optional[str] = None
    direction: Optional[str] = None
    control_plane: bool = False
    per_user_override: bool = False
    raw_line: str
    line_number: Optional[int] = None


class CiscoAccessRule(BaseModel):
    id: str
    acl_name: str
    source_line_number: Optional[int] = None
    source_sequence: Optional[int] = None
    action: Optional[str] = None
    protocol: Optional[str] = None
    protocol_object: Optional[str] = None
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
    remark: Optional[str] = None
    raw_line: str = ""
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoNATRule(BaseModel):
    name: str
    source_interface: Optional[str] = None
    destination_interface: Optional[str] = None
    section: str = "manual"
    sequence: Optional[int] = None
    type: str = "source"
    source_mode: Optional[str] = None
    real_source: Optional[str] = None
    mapped_source: Optional[str] = None
    destination_mode: Optional[str] = None
    real_destination: Optional[str] = None
    mapped_destination: Optional[str] = None
    original_service: Optional[str] = None
    translated_service: Optional[str] = None
    owning_object: Optional[str] = None
    options: List[str] = Field(default_factory=list)
    raw_line: str = ""
    description: Optional[str] = None
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoStaticRoute(BaseModel):
    interface: str
    destination: str
    mask: str
    gateway: str
    administrative_distance: Optional[int] = None
    raw_line: str = ""
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False


class CiscoASAConfig(BaseModel):
    hostname: str = "cisco-asa"
    interfaces: List[CiscoInterface] = Field(default_factory=list)
    network_objects: List[CiscoNetworkObject] = Field(default_factory=list)
    network_groups: List[CiscoNetworkGroup] = Field(default_factory=list)
    service_objects: List[CiscoServiceObject] = Field(default_factory=list)
    service_groups: List[CiscoServiceGroup] = Field(default_factory=list)
    access_rules: List[CiscoAccessRule] = Field(default_factory=list)
    acl_bindings: List[CiscoACLBinding] = Field(default_factory=list)
    nat_rules: List[CiscoNATRule] = Field(default_factory=list)
    static_routes: List[CiscoStaticRoute] = Field(default_factory=list)
    unsupported_commands: List[Dict[str, Any]] = Field(default_factory=list)
    parse_errors: List[Dict[str, Any]] = Field(default_factory=list)
