# Canonical IR service domain models

from datetime import timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
from fwmigrate.ir.enums import ServiceProtocol
from .extension_models import (
    IRCheckPointObjectExtension,
    get_object_extension_value,
    move_object_extension,
    set_object_extension_value,
)


class IRServicePort(BaseModel):
    protocol: ServiceProtocol
    port: str  # e.g., "443", "80-90"
    source_port: Optional[str] = None
    raw_source_value: Optional[str] = None
    icmptype: Optional[int] = None
    icmpcode: Optional[int] = None
class IRServiceCategory(BaseModel):
    name: str
    source_context: Optional[str] = None
    description: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_fabric_object: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRService(BaseModel):
    name: str
    source_context: Optional[str] = None
    ports: List[IRServicePort] = Field(default_factory=list)
    source_uuid: Optional[str] = None
    vendor_extension: Optional[IRCheckPointObjectExtension] = None
    source_category: Optional[str] = None
    source_protocol_configured: Optional[str] = None
    source_protocol: Optional[str] = None
    source_protocol_number: Optional[int] = None
    source_proxy: Optional[bool] = None
    source_color: Optional[int] = None
    source_fabric_object: Optional[str] = None
    source_unmodeled_semantic_settings: List[str] = Field(default_factory=list)
    match_for_any: Optional[bool] = None
    session_timeout: Optional[Any] = None
    use_default_session_timeout: Optional[bool] = None
    aggressive_aging: Optional[Any] = None
    sync_connections_on_cluster: Optional[bool] = None
    keep_connections_open_after_policy_installation: Optional[bool] = None
    protocol_signatures: List[Any] = Field(default_factory=list)
    match: Optional[Any] = None
    action: Optional[Any] = None
    accept_replies: Optional[bool] = None
    session_behavior: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None
    description: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def move_legacy_vendor_fields(cls, data: Any) -> Any:
        return move_object_extension(data, (
            "checkpoint_domain_uid", "checkpoint_domain_name", "checkpoint_origin_scope",
            "global_source_uid", "global_source_name", "local_override_uid", "assignment_uid",
        ))
class IRServiceGroup(BaseModel):
    name: str
    source_context: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    unsafe_members: List[str] = Field(default_factory=list)
    source_uuid: Optional[str] = None
    source_color: Optional[int] = None
    source_proxy: Optional[bool] = None
    source_fabric_object: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None
    description: Optional[str] = None
class IRSchedule(BaseModel):
    name: str
    source_context: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None
    days: List[str] = Field(default_factory=list)
    windows: List[Dict[str, Any]] = Field(default_factory=list)
    schedule_type: str = "recurring"
    source_color: Optional[int] = None
    vendor_extension: Optional[IRCheckPointObjectExtension] = None
    expiration_days: Optional[int] = None
    source_fabric_object: Optional[str] = None
    start_utc: Optional[str] = None
    end_utc: Optional[str] = None
    hours_ranges: List[Dict[str, Any]] = Field(default_factory=list)
    start_endpoint: Optional[Dict[str, Any]] = None
    end_endpoint: Optional[Dict[str, Any]] = None
    start_now: Optional[bool] = None
    end_never: Optional[bool] = None
    recurrence: Dict[str, Any] = Field(default_factory=dict)
    timezone: Optional[str] = None
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def move_legacy_vendor_fields(cls, data: Any) -> Any:
        return move_object_extension(data, (
            "checkpoint_domain_uid", "checkpoint_domain_name", "checkpoint_origin_scope",
            "global_source_uid", "global_source_name", "local_override_uid", "assignment_uid",
        ))
class IRTrafficShaper(BaseModel):
    name: str
    source_context: Optional[str] = None
    guaranteed_bandwidth: Optional[int] = None
    maximum_bandwidth: Optional[int] = None
    source_bandwidth_unit: Optional[str] = None
    priority: Optional[str] = None
    per_policy: Optional[bool] = None
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRProxyRequestMatch(BaseModel):
    name: str
    source_context: Optional[str] = None
    source_uuid: Optional[str] = None
    proxy_address_type: Optional[str] = None
    host: Optional[str] = None
    host_pattern: Optional[str] = None
    host_regex: Optional[str] = None
    path_pattern: Optional[str] = None
    path: Optional[str] = None
    query_pattern: Optional[str] = None
    query: Optional[str] = None
    method: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    url_category: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRWebProxy(BaseModel):
    name: str = "default"
    mode: Optional[str] = None
    listener_interfaces: List[str] = Field(default_factory=list)
    listener_address: Optional[str] = None
    listener_port: Optional[int] = None
    fqdn: Optional[str] = None
    authentication: Optional[str] = None
    upstream_proxy: Optional[str] = None
    dns: Optional[str] = None
    policy_refs: List[str] = Field(default_factory=list)
    proxy_fqdn: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRApplication(BaseModel):
    name: str
    source_uuid: Optional[str] = None
    vendor_extension: Optional[IRCheckPointObjectExtension] = None
    source_context: Optional[str] = None
    category: Optional[str] = None
    urls: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    risk: Optional[Any] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def move_legacy_vendor_fields(cls, data: Any) -> Any:
        return move_object_extension(data, (
            "checkpoint_domain_uid", "checkpoint_domain_name", "checkpoint_origin_scope",
            "global_source_uid", "global_source_name", "local_override_uid", "assignment_uid",
        ))
class IRApplicationGroup(IRApplication):
    members: List[str] = Field(default_factory=list)
class IRApplicationCategory(IRApplication):
    members: List[str] = Field(default_factory=list)
class IRInternetService(BaseModel):
    name: str
    source_id: Optional[int] = None
    city_id: Optional[int] = None
    country_id: Optional[int] = None
    region_id: Optional[int] = None
    service_type: Optional[str] = None
    description: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceDefinitionPortRange(BaseModel):
    source_id: Optional[int] = None
    start_port: Optional[int] = None
    end_port: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceDefinitionEntry(BaseModel):
    source_sequence: Optional[int] = None
    category_id: Optional[int] = None
    name: Optional[str] = None
    protocol_number: Optional[int] = None
    port_ranges: List[IRInternetServiceDefinitionPortRange] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceDefinition(BaseModel):
    source_id: Optional[int] = None
    entries: List[IRInternetServiceDefinitionEntry] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceCustomPortRange(BaseModel):
    source_id: Optional[int] = None
    start_port: Optional[int] = None
    end_port: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceCustomEntry(BaseModel):
    source_id: Optional[int] = None
    addr_mode: Optional[str] = None
    destination_ipv4: List[str] = Field(default_factory=list)
    destination_ipv6: List[str] = Field(default_factory=list)
    protocol: Optional[int] = None
    port_ranges: List[IRInternetServiceCustomPortRange] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceCustom(BaseModel):
    name: str
    source_context: str = "root"
    comment: Optional[str] = None
    reputation: Optional[int] = None
    entries: List[IRInternetServiceCustomEntry] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceCustomGroup(BaseModel):
    name: str
    source_context: str = "root"
    comment: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceAdditionPortRange(BaseModel):
    source_id: Optional[int] = None
    start_port: Optional[int] = None
    end_port: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceAdditionEntry(BaseModel):
    source_id: Optional[int] = None
    addr_mode: Optional[str] = None
    protocol: Optional[int] = None
    port_ranges: List[IRInternetServiceAdditionPortRange] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceAddition(BaseModel):
    source_id: Optional[int] = None
    source_context: str = "root"
    comment: Optional[str] = None
    entries: List[IRInternetServiceAdditionEntry] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceAppend(BaseModel):
    source_context: str = "root"
    addr_mode: Optional[str] = None
    append_port: Optional[int] = None
    match_port: Optional[int] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceExtensionIPv4Range(BaseModel):
    source_id: Optional[int] = None
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceExtensionIPv6Range(BaseModel):
    source_id: Optional[int] = None
    start_ip6: Optional[str] = None
    end_ip6: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceExtensionPortRange(BaseModel):
    source_id: Optional[int] = None
    start_port: Optional[int] = None
    end_port: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceExtensionDisableEntry(BaseModel):
    source_id: Optional[int] = None
    addr_mode: Optional[str] = None
    ipv4_ranges: List[IRInternetServiceExtensionIPv4Range] = Field(default_factory=list)
    ipv6_ranges: List[IRInternetServiceExtensionIPv6Range] = Field(default_factory=list)
    protocol: Optional[int] = None
    port_ranges: List[IRInternetServiceExtensionPortRange] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceExtensionEntry(BaseModel):
    source_id: Optional[int] = None
    addr_mode: Optional[str] = None
    destination_ipv4: List[str] = Field(default_factory=list)
    destination_ipv6: List[str] = Field(default_factory=list)
    protocol: Optional[int] = None
    port_ranges: List[IRInternetServiceExtensionPortRange] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceExtension(BaseModel):
    source_id: Optional[int] = None
    source_context: str = "root"
    comment: Optional[str] = None
    disable_entries: List[IRInternetServiceExtensionDisableEntry] = Field(default_factory=list)
    entries: List[IRInternetServiceExtensionEntry] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInternetServiceGroup(BaseModel):
    name: str
    source_context: str = "root"
    comment: Optional[str] = None
    direction: str = "both"
    members: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRScheduleGroup(BaseModel):
    name: str
    source_context: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    source_uuid: Optional[str] = None
    vendor_extension: Optional[IRCheckPointObjectExtension] = None
    description: Optional[str] = None
    unresolved_members: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def move_legacy_vendor_fields(cls, data: Any) -> Any:
        return move_object_extension(data, (
            "checkpoint_domain_uid", "checkpoint_domain_name", "checkpoint_origin_scope",
            "global_source_uid", "global_source_name", "local_override_uid", "assignment_uid",
        ))


IRProxyAddress = IRProxyRequestMatch
IRWebProxySettings = IRWebProxy


def _checkpoint_property(field: str):
    return property(
        lambda self: get_object_extension_value(self, field),
        lambda self, value: set_object_extension_value(
            self, IRCheckPointObjectExtension, field, value
        ),
    )


for _model in (IRService, IRSchedule, IRScheduleGroup, IRApplication):
    for _field in (
        "checkpoint_domain_uid", "checkpoint_domain_name", "checkpoint_origin_scope",
        "global_source_uid", "global_source_name", "local_override_uid", "assignment_uid",
    ):
        setattr(_model, _field, _checkpoint_property(_field))


__all__ = [
    "IRServicePort",
    "IRServiceCategory",
    "IRService",
    "IRServiceGroup",
    "IRSchedule",
    "IRScheduleGroup",
    "IRTrafficShaper",
    "IRProxyRequestMatch",
    "IRProxyAddress",
    "IRWebProxy",
    "IRWebProxySettings",
    "IRApplication",
    "IRApplicationGroup",
    "IRApplicationCategory",
    "IRInternetService",
    "IRInternetServiceDefinitionPortRange",
    "IRInternetServiceDefinitionEntry",
    "IRInternetServiceDefinition",
    "IRInternetServiceCustomPortRange",
    "IRInternetServiceCustomEntry",
    "IRInternetServiceCustom",
    "IRInternetServiceCustomGroup",
    "IRInternetServiceAdditionPortRange",
    "IRInternetServiceAdditionEntry",
    "IRInternetServiceAddition",
    "IRInternetServiceAppend",
    "IRInternetServiceExtensionIPv4Range",
    "IRInternetServiceExtensionIPv6Range",
    "IRInternetServiceExtensionPortRange",
    "IRInternetServiceExtensionDisableEntry",
    "IRInternetServiceExtensionEntry",
    "IRInternetServiceExtension",
    "IRInternetServiceGroup",
]
