from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from fwmigrate.parsers.cisco_asa.model import (
    CiscoASAConfig,
    CiscoASAContext,
    CiscoClassMap,
    CiscoClassMapMatch,
    CiscoConnectionControl,
    CiscoDHCPRelay,
    CiscoDNSServerGroup,
    CiscoDNSSettings,
    CiscoFailoverGroup,
    CiscoManagementAccessRule,
    CiscoMPFConnectionAction,
    CiscoMPFPoliceAction,
    CiscoNTPServer,
    CiscoPolicyMap,
    CiscoPolicyMapClass,
    CiscoServicePolicy,
    CiscoTCPMap,
)


class CiscoClassMapMatchPhase10(CiscoClassMapMatch):
    """Extended MPF match preserving negation and application-specific syntax."""

    negated: bool = False
    expression: List[str] = Field(default_factory=list)
    inspection_expression: Optional[str] = None


class CiscoClassMapPhase10(CiscoClassMap):
    """Class-map header split into type, inspection protocol and matching mode."""

    class_map_type: Optional[str] = None
    inspection_protocol: Optional[str] = None
    typed: bool = False


class CiscoInspectionPolicySection(BaseModel):
    """One top-level child in a typed inspection policy map.

    Inspection policy maps have their own hierarchy.  They are deliberately not
    represented as ordinary CiscoPolicyMapClass actions.
    """

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


class CiscoMPFConnectionActionPhase11(CiscoMPFConnectionAction):
    syn_cookie_mss: Optional[int] = None
    advanced_options: Optional[str] = None
    timeouts: Dict[str, str] = Field(default_factory=dict)
    negated: bool = False
    raw_options: List[str] = Field(default_factory=list)


class CiscoMPFPoliceActionPhase11(CiscoMPFPoliceAction):
    direction: Optional[str] = None
    negated: bool = False
    raw_options: List[str] = Field(default_factory=list)


class CiscoPolicyMapClassPhase10(CiscoPolicyMapClass):
    connection_actions: List[CiscoMPFConnectionActionPhase11] = Field(default_factory=list)
    police_actions: List[CiscoMPFPoliceActionPhase11] = Field(default_factory=list)


class CiscoPolicyMapPhase10(CiscoPolicyMap):
    policy_map_type: Optional[str] = None
    inspection_protocol: Optional[str] = None
    typed: bool = False
    classes: List[CiscoPolicyMapClassPhase10] = Field(default_factory=list)
    inspection_sections: List[CiscoInspectionPolicySection] = Field(default_factory=list)
    parameter_lines: List[str] = Field(default_factory=list)


class CiscoTCPMapSetting(BaseModel):
    key: str
    values: List[str] = Field(default_factory=list)
    negated: bool = False
    raw: str = ""
    source_order: int = 0
    supported: bool = True


class CiscoTCPMapPhase11(CiscoTCPMap):
    setting_entries: List[CiscoTCPMapSetting] = Field(default_factory=list)
    setting_history: Dict[str, List[str]] = Field(default_factory=dict)


class CiscoServicePolicyPhase10(CiscoServicePolicy):
    enabled: Optional[bool] = None
    negated: bool = False
    fail_close: bool = False


class CiscoConnectionControlPhase11(CiscoConnectionControl):
    negated: bool = False
    statistics_target: Optional[str] = None
    number_of_rate: Optional[int] = None
    rate_interval: Optional[int] = None
    average_rate: Optional[int] = None
    burst_rate: Optional[int] = None
    raw_parameters: List[str] = Field(default_factory=list)


class CiscoDNSServerGroupPhase12(CiscoDNSServerGroup):
    retries: Optional[int] = None
    timeout: Optional[int] = None
    expire_entry_timer: Optional[int] = None
    poll_timer: Optional[int] = None
    child_order: List[str] = Field(default_factory=list)
    raw_settings: List[Dict[str, Any]] = Field(default_factory=list)


class CiscoDNSSettingsPhase12(CiscoDNSSettings):
    name_servers: List[str] = Field(default_factory=list)
    command_history: List[str] = Field(default_factory=list)


class CiscoHTTPServerConfig(BaseModel):
    enabled: Optional[bool] = None
    port: Optional[int] = None
    idle_timeout: Optional[int] = None
    session_timeout: Optional[int] = None
    raw_lines: List[str] = Field(default_factory=list)
    source_order: Optional[int] = None
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)


class CiscoManagementAccessRulePhase14(CiscoManagementAccessRule):
    address_family: Optional[str] = None
    negated: bool = False


class CiscoNTPServerPhase14(CiscoNTPServer):
    negated: bool = False


class CiscoTrustpointRecord(BaseModel):
    name: str
    source_context: Optional[str] = None
    enrollment: Optional[str] = None
    subject_name: Optional[str] = None
    keypair_reference: Optional[str] = None
    revocation_check: List[str] = Field(default_factory=list)
    validation_settings: List[str] = Field(default_factory=list)
    crl_settings: List[str] = Field(default_factory=list)
    ocsp_settings: List[str] = Field(default_factory=list)
    certificate_present: bool = False
    certificate_references: List[str] = Field(default_factory=list)
    raw_lines: List[str] = Field(default_factory=list)
    source_order: int = 0
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoFailoverGroupPhase15(CiscoFailoverGroup):
    preempt: Optional[bool] = None
    replication_http: Optional[bool] = None
    interface_policy: Optional[str] = None
    polltime: Optional[str] = None
    raw_children: List[str] = Field(default_factory=list)


class CiscoAllocatedInterface(BaseModel):
    physical_interface: str
    mapped_name: Optional[str] = None
    range_expression: Optional[str] = None
    source_order: int = 0
    raw: str = ""
    resolved: Optional[bool] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoASAContextPhase16(CiscoASAContext):
    allocated_interface_entries: List[CiscoAllocatedInterface] = Field(default_factory=list)


class CiscoMultiContextSystem(BaseModel):
    admin_context_name: Optional[str] = None
    admin_context_resolved: Optional[bool] = None
    raw_lines: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoASAConfigPhase10_17(CiscoASAConfig):
    class_maps: List[CiscoClassMapPhase10] = Field(default_factory=list)
    policy_maps: List[CiscoPolicyMapPhase10] = Field(default_factory=list)
    service_policies: List[CiscoServicePolicyPhase10] = Field(default_factory=list)
    tcp_maps: List[CiscoTCPMapPhase11] = Field(default_factory=list)
    connection_controls: List[CiscoConnectionControlPhase11] = Field(default_factory=list)
    dns_server_groups: List[CiscoDNSServerGroupPhase12] = Field(default_factory=list)
    dns_settings: CiscoDNSSettingsPhase12 = Field(default_factory=lambda: CiscoDNSSettingsPhase12(name="system-dns"))
    management_access_rules: List[CiscoManagementAccessRulePhase14] = Field(default_factory=list)
    ntp_servers: List[CiscoNTPServerPhase14] = Field(default_factory=list)
    contexts: List[CiscoASAContextPhase16] = Field(default_factory=list)
    trustpoint_records: List[CiscoTrustpointRecord] = Field(default_factory=list)
    http_server: CiscoHTTPServerConfig = Field(default_factory=CiscoHTTPServerConfig)
    multi_context_system: CiscoMultiContextSystem = Field(default_factory=CiscoMultiContextSystem)
