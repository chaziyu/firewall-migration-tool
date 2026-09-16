from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IRVendorExtensionIdentity(BaseModel):
    """Small common identity used when extension records are correlated."""

    model_config = ConfigDict(extra="forbid")

    canonical_name: str | None = None
    source_context: str | None = None
    source_id: str | None = None
    source_uuid: str | None = None


class IRFortiOSAddressExtension(IRVendorExtensionIdentity):
    source_fsso_group: list[str] = Field(default_factory=list)
    source_fabric_object_setting: str | None = None
    source_effective_defaults: dict[str, Any] = Field(default_factory=dict)
    source_template: str | None = None
    source_template_reference_resolved: bool | None = None

    @field_validator("source_fsso_group", mode="before")
    @classmethod
    def normalize_fsso_group(cls, value: Any) -> Any:
        return [] if value is None else [value] if isinstance(value, str) else value


class IRFortiOSNATRuleExtension(IRVendorExtensionIdentity):
    source_pool_group_references: list[str] = Field(default_factory=list)
    source_pool_type: str | None = None
    source_pool_excluded_ips: list[str] = Field(default_factory=list)
    source_pool_permit_any_host: bool | None = None
    source_pool_original_start_ip: list[str] = Field(default_factory=list)
    source_pool_original_end_ip: list[str] = Field(default_factory=list)
    source_vip_reference: str | None = None
    source_vip_group_reference: str | None = None
    source_vip_type: str | None = None
    source_vip_enabled: bool | None = None
    source_vip_nat_source_vip: bool | None = None
    source_vip_filters: list[str] = Field(default_factory=list)
    source_vip_interface_filters: list[str] = Field(default_factory=list)
    source_vip_services: list[str] = Field(default_factory=list)
    source_vip_port_mapping_type: str | None = None
    source_policy_fixed_port: str | None = None
    source_policy_nat46: str | None = None
    source_policy_nat64: str | None = None
    source_policy_nat_inbound: str | None = None
    source_policy_nat_outbound: str | None = None
    source_policy_nat_ip: str | None = None
    source_policy_match_vip: str | None = None
    source_policy_match_vip_only: str | None = None
    source_policy_effective_match_vip: str | None = None
    source_policy_effective_match_vip_only: str | None = None
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRFortiOSNATPoolExtension(IRVendorExtensionIdentity):
    block_size: int | None = None
    blocks_per_user: int | None = None
    pba_timeout: int | None = None
    pba_interim_log: int | None = None
    ports_per_user: int | None = None
    privileged_port_use_pba: bool | None = None
    nat64: bool | None = None
    add_nat64_route: bool | None = None
    client_prefix_length: int | None = None
    include_subnet_broadcast: bool | None = None
    tcp_session_quota: int | None = None
    udp_session_quota: int | None = None
    icmp_session_quota: int | None = None
    cgn_block_size: int | None = None
    cgn_client_start_ip: str | None = None
    cgn_client_end_ip: str | None = None
    cgn_client_ipv6_shift: int | None = None
    cgn_fixed_allocation: bool | None = None
    cgn_overload: bool | None = None
    cgn_port_start: int | None = None
    cgn_port_end: int | None = None
    cgn_spa: bool | None = None
    utilization_alarm_clear: int | None = None
    utilization_alarm_raise: int | None = None
    nat46: bool | None = None
    add_nat46_route: bool | None = None
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRFortiOSPolicyExtension(IRVendorExtensionIdentity):
    source_utm_status: str | None = None
    source_inspection_mode: str | None = None
    source_timeout_send_rst: str | None = None
    source_auto_asic_offload: str | None = None
    source_np_acceleration: str | None = None
    source_port_preserve: str | None = None
    source_effective_utm_status: str | None = None
    source_effective_inspection_mode: str | None = None
    source_effective_ztna_status: str | None = None
    source_effective_timeout_send_rst: str | None = None
    source_effective_auto_asic_offload: str | None = None
    source_effective_np_acceleration: str | None = None
    source_effective_port_preserve: str | None = None
    source_policy_expiry: str | None = None
    source_effective_policy_expiry: str | None = None
    source_policy_expiry_date: str | None = None
    source_policy_expiry_date_utc: str | None = None
    source_schedule_timeout: str | None = None
    source_effective_schedule_timeout: str | None = None
    source_reputation_direction: str | None = None
    source_effective_reputation_direction: str | None = None
    source_reputation_direction6: str | None = None
    source_effective_reputation_direction6: str | None = None
    source_reputation_minimum: int | None = None
    source_effective_reputation_minimum: int | None = None
    source_reputation_minimum6: int | None = None
    source_effective_reputation_minimum6: int | None = None
    source_match_vip: str | None = None
    source_effective_match_vip: str | None = None
    source_match_vip_only: str | None = None
    source_effective_match_vip_only: str | None = None
    source_profile_type: str | None = None
    source_profile_group: str | None = None
    source_profile_protocol_options: str | None = None
    source_internet_service_status: str | None = None
    source_internet_service_settings: dict[str, Any] = Field(default_factory=dict)
    source_vpn_tunnel: str | None = None
    source_identity_based_route: str | None = None
    source_ztna_status: str | None = None
    source_ztna_ems_tags: list[str] = Field(default_factory=list)
    source_ztna_device_ownership: str | None = None
    source_ztna_ems_tags_secondary: list[str] = Field(default_factory=list)
    source_ztna_geo_tags: list[str] = Field(default_factory=list)
    source_ztna_policy_redirect: str | None = None
    source_ztna_tags_match_logic: str | None = None
    source_extra_settings: dict[str, Any] = Field(default_factory=dict)
    translation_type: str | None = None
    original_services: list[str] = Field(default_factory=list)
    translated_services: list[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: list[str] = Field(default_factory=list)
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRAddress6TemplateValue(BaseModel):
    source_id: str
    value: str | None = None
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRAddress6TemplateSegment(BaseModel):
    source_id: str
    bits: int | None = None
    exclusive: str | None = None
    name: str | None = None
    values: list[IRAddress6TemplateValue] = Field(default_factory=list)
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRAddress6Template(BaseModel):
    name: str
    source_context: str | None = None
    ip6: str | None = None
    subnet_segment_count: int | None = None
    subnet_segments: list[IRAddress6TemplateSegment] = Field(default_factory=list)
    source_fabric_object: str | None = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: list[str] = Field(default_factory=list)
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRIPPoolGroup(BaseModel):
    name: str
    source_context: str | None = None
    members: list[str] = Field(default_factory=list)
    unresolved_members: list[str] = Field(default_factory=list)
    source_explicit_fields: list[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: list[str] = Field(default_factory=list)
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRCheckPointObjectExtension(IRVendorExtensionIdentity):
    checkpoint_domain_uid: str | None = None
    checkpoint_domain_name: str | None = None
    checkpoint_origin_scope: str | None = None
    global_source_uid: str | None = None
    global_source_name: str | None = None
    local_override_uid: str | None = None
    assignment_uid: str | None = None


class IRCheckPointPolicyExtension(IRCheckPointObjectExtension):
    policy_package_uid: str | None = None
    policy_package_name: str | None = None
    access_layer_uid: str | None = None
    access_layer_name: str | None = None
    access_layer_inline: bool = False
    access_layer_parent_uid: str | None = None
    access_layer_parent_rule_uid: str | None = None
    checkpoint_package_uid: str | None = None
    checkpoint_package_name: str | None = None
    checkpoint_layer_uid: str | None = None
    checkpoint_layer_name: str | None = None
    checkpoint_parent_layer_uid: str | None = None
    checkpoint_parent_rule_uid: str | None = None
    checkpoint_section_path: list[str] = Field(default_factory=list)
    checkpoint_rule_number: int | None = None
    install_on: list[str] = Field(default_factory=list)


class IRCheckPointNATPoolExtension(IRCheckPointObjectExtension):
    checkpoint_pool_object_type: str | None = None
    checkpoint_network_references: list[str] = Field(default_factory=list)
    checkpoint_network_group_references: list[str] = Field(default_factory=list)
    checkpoint_address_range_references: list[str] = Field(default_factory=list)
    checkpoint_gateway_references: list[str] = Field(default_factory=list)
    checkpoint_member_assignments: dict[str, Any] = Field(default_factory=dict)
    checkpoint_applicability: list[str] = Field(default_factory=list)
    checkpoint_precedence: int | None = None
    checkpoint_vpn_scope: str | None = None
    checkpoint_mep: bool | None = None


class IRCheckPointNATRuleExtension(IRCheckPointObjectExtension):
    checkpoint_package_uid: str | None = None
    checkpoint_package_name: str | None = None
    translation_type: str | None = None
    original_services: list[str] = Field(default_factory=list)
    translated_services: list[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: list[str] = Field(default_factory=list)
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRCheckPointInterfaceExtension(IRVendorExtensionIdentity):
    checkpoint_context: Any = None


def _payload_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, list):
        return [_payload_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _payload_value(item) for key, item in value.items()}
    return value


def move_object_extension(data: Any, fields: tuple[str, ...]) -> Any:
    """Accept old embedded fields and store them in one typed object extension."""
    if not isinstance(data, dict):
        return data
    migrated = dict(data)
    values = {}
    for field in fields:
        if field in migrated:
            value = migrated.pop(field)
            if value is not None:
                values[field] = value
    if not values:
        return migrated
    existing = migrated.get("vendor_extension")
    extension = _payload_value(existing) if existing is not None else {}
    for field, value in values.items():
        if field in extension and _payload_value(extension[field]) != _payload_value(value):
            raise ValueError(f"Conflicting embedded IR values for vendor_extension.{field}.")
        extension.setdefault(field, value)
    extension.setdefault("canonical_name", migrated.get("name"))
    extension.setdefault("source_context", migrated.get("source_context"))
    extension.setdefault("source_id", migrated.get("source_id"))
    extension.setdefault("source_uuid", migrated.get("source_uuid"))
    migrated["vendor_extension"] = extension
    return migrated


def get_object_extension_value(obj: Any, field: str) -> Any:
    extension = getattr(obj, "vendor_extension", None)
    return getattr(extension, field, None) if extension is not None else None


def set_object_extension_value(obj: Any, extension_type: type[BaseModel], field: str, value: Any) -> None:
    extension = getattr(obj, "vendor_extension", None)
    if extension is None:
        extension = extension_type()
        object.__setattr__(obj, "vendor_extension", extension)
    setattr(extension, field, value)


__all__ = [
    "IRVendorExtensionIdentity",
    "IRFortiOSAddressExtension",
    "IRFortiOSNATPoolExtension",
    "IRFortiOSNATRuleExtension",
    "IRFortiOSPolicyExtension",
    "IRAddress6TemplateValue",
    "IRAddress6TemplateSegment",
    "IRAddress6Template",
    "IRIPPoolGroup",
    "IRCheckPointObjectExtension",
    "IRCheckPointPolicyExtension",
    "IRCheckPointNATPoolExtension",
    "IRCheckPointNATRuleExtension",
    "IRCheckPointInterfaceExtension",
    "move_object_extension",
    "get_object_extension_value",
    "set_object_extension_value",
]
