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


class IRFortiOSPublishedServiceGSLBPublicIP(BaseModel):
    index: int | None = None
    ip: str | None = None
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRFortiOSPublishedServiceQUICSettings(BaseModel):
    max_idle_timeout: int | None = None
    max_udp_payload_size: int | None = None
    active_connection_id_limit: int | None = None
    ack_delay_exponent: int | None = None
    max_ack_delay: int | None = None
    max_datagram_frame_size: int | None = None
    active_migration: str | None = None
    grease_quic_bit: str | None = None
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRFortiOSPublishedServiceSSLCipherSuite(BaseModel):
    priority: int | None = None
    cipher: str | None = None
    versions: list[str] = Field(default_factory=list)
    source_attributes: dict[str, Any] = Field(default_factory=dict)


class IRFortiOSAddressExtension(IRVendorExtensionIdentity):
    source_hw_model: str | None = None
    source_hw_vendor: str | None = None
    source_cache_ttl: int | None = None
    source_clearpass_spt: str | None = None
    source_epg_name: str | None = None
    source_organization: str | None = None
    source_os: str | None = None
    source_policy_group: str | None = None
    source_route_tag: int | None = None
    source_sdn: str | None = None
    source_sdn_addr_type: str | None = None
    source_sdn_tag: str | None = None
    source_node_ip_only: bool | None = None
    source_obj_id: str | None = None
    source_sub_type: str | None = None
    source_obj_tag: str | None = None
    source_tag_type: str | None = None
    source_obj_type: str | None = None
    source_dirty: str | None = None
    source_subnet_name: str | None = None
    source_sw_version: str | None = None
    source_tag_detection_level: str | None = None
    source_tenant: str | None = None
    source_group_type: str | None = None
    source_exclude_setting: str | None = None
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
    arp_reply: bool | None = None
    arp_interface: str | None = None
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


class IRFortiOSPublishedServiceExtension(IRVendorExtensionIdentity):
    source_id: int | str | None = None
    vip_type: str | None = None
    port_mapping_type: str | None = None
    arp_reply: bool | None = None
    gratuitous_arp_interval: int | None = None
    nat_source_vip: bool | None = None
    nat44: bool | None = None
    nat46: bool | None = None
    nat64: bool | None = None
    nat66: bool | None = None
    add_nat46_route: bool | None = None
    add_nat64_route: bool | None = None
    ndp_reply: bool | None = None
    ipv6_mapped_ip: str | None = None
    ipv6_mapped_port: str | None = None
    ipv4_mapped_ip: str | None = None
    ipv4_mapped_port: str | None = None
    embedded_ipv4_address: str | None = None
    server_type: str | None = None
    http_redirect: bool | None = None
    h2_support: str | None = None
    h3_support: str | None = None
    http_multiplex: str | None = None
    ssl_mode: str | None = None
    ssl_algorithm: str | None = None
    ssl_min_version: str | None = None
    ssl_max_version: str | None = None
    ssl_server_algorithm: str | None = None
    ssl_server_min_version: str | None = None
    ssl_server_max_version: str | None = None
    ssl_pfs: str | None = None
    gslb_domain_name: str | None = None
    gslb_hostname: str | None = None
    max_embryonic_connections: int | None = None
    source_gslb_public_ips: list[IRFortiOSPublishedServiceGSLBPublicIP] = Field(default_factory=list)
    source_quic: IRFortiOSPublishedServiceQUICSettings | None = None
    source_ssl_cipher_suites: list[IRFortiOSPublishedServiceSSLCipherSuite] = Field(default_factory=list)
    source_ssl_server_cipher_suites: list[IRFortiOSPublishedServiceSSLCipherSuite] = Field(default_factory=list)
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
        for extension_field, object_field in (
            ("canonical_name", "name"),
            ("source_context", "source_context"),
            ("source_id", "source_id"),
            ("source_uuid", "source_uuid"),
        ):
            object_value = getattr(obj, object_field, None)
            if object_value is None and extension_field == "source_uuid":
                object_value = getattr(obj, "source_policy_uuid", None)
            if object_value is not None and extension_field in type(extension).model_fields:
                setattr(extension, extension_field, object_value)
        object.__setattr__(obj, "vendor_extension", extension)
    setattr(extension, field, value)


class IRCheckPointObjectCompatibilityMixin:
    @property
    def checkpoint_domain_uid(self):
        return get_object_extension_value(self, "checkpoint_domain_uid")

    @checkpoint_domain_uid.setter
    def checkpoint_domain_uid(self, value):
        set_object_extension_value(self, IRCheckPointObjectExtension, "checkpoint_domain_uid", value)

    @property
    def checkpoint_domain_name(self):
        return get_object_extension_value(self, "checkpoint_domain_name")

    @checkpoint_domain_name.setter
    def checkpoint_domain_name(self, value):
        set_object_extension_value(self, IRCheckPointObjectExtension, "checkpoint_domain_name", value)

    @property
    def checkpoint_origin_scope(self):
        return get_object_extension_value(self, "checkpoint_origin_scope")

    @checkpoint_origin_scope.setter
    def checkpoint_origin_scope(self, value):
        set_object_extension_value(self, IRCheckPointObjectExtension, "checkpoint_origin_scope", value)

    @property
    def global_source_uid(self):
        return get_object_extension_value(self, "global_source_uid")

    @global_source_uid.setter
    def global_source_uid(self, value):
        set_object_extension_value(self, IRCheckPointObjectExtension, "global_source_uid", value)

    @property
    def global_source_name(self):
        return get_object_extension_value(self, "global_source_name")

    @global_source_name.setter
    def global_source_name(self, value):
        set_object_extension_value(self, IRCheckPointObjectExtension, "global_source_name", value)

    @property
    def local_override_uid(self):
        return get_object_extension_value(self, "local_override_uid")

    @local_override_uid.setter
    def local_override_uid(self, value):
        set_object_extension_value(self, IRCheckPointObjectExtension, "local_override_uid", value)

    @property
    def assignment_uid(self):
        return get_object_extension_value(self, "assignment_uid")

    @assignment_uid.setter
    def assignment_uid(self, value):
        set_object_extension_value(self, IRCheckPointObjectExtension, "assignment_uid", value)


class IRCheckPointPolicyCompatibilityMixin(IRCheckPointObjectCompatibilityMixin):
    _checkpoint_policy_fields = (
        "policy_package_uid", "policy_package_name", "access_layer_uid", "access_layer_name",
        "access_layer_inline", "access_layer_parent_uid", "access_layer_parent_rule_uid",
        "checkpoint_package_uid", "checkpoint_package_name", "checkpoint_layer_uid",
        "checkpoint_layer_name", "checkpoint_parent_layer_uid", "checkpoint_parent_rule_uid",
        "checkpoint_section_path", "checkpoint_rule_number", "install_on",
    )

    @property
    def policy_package_uid(self):
        return get_object_extension_value(self, "policy_package_uid")

    @policy_package_uid.setter
    def policy_package_uid(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "policy_package_uid", value)

    @property
    def policy_package_name(self):
        return get_object_extension_value(self, "policy_package_name")

    @policy_package_name.setter
    def policy_package_name(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "policy_package_name", value)

    @property
    def access_layer_uid(self):
        return get_object_extension_value(self, "access_layer_uid")

    @access_layer_uid.setter
    def access_layer_uid(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "access_layer_uid", value)

    @property
    def access_layer_name(self):
        return get_object_extension_value(self, "access_layer_name")

    @access_layer_name.setter
    def access_layer_name(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "access_layer_name", value)

    @property
    def access_layer_inline(self):
        return get_object_extension_value(self, "access_layer_inline")

    @access_layer_inline.setter
    def access_layer_inline(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "access_layer_inline", value)

    @property
    def access_layer_parent_uid(self):
        return get_object_extension_value(self, "access_layer_parent_uid")

    @access_layer_parent_uid.setter
    def access_layer_parent_uid(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "access_layer_parent_uid", value)

    @property
    def access_layer_parent_rule_uid(self):
        return get_object_extension_value(self, "access_layer_parent_rule_uid")

    @access_layer_parent_rule_uid.setter
    def access_layer_parent_rule_uid(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "access_layer_parent_rule_uid", value)

    @property
    def checkpoint_package_uid(self):
        return get_object_extension_value(self, "checkpoint_package_uid")

    @checkpoint_package_uid.setter
    def checkpoint_package_uid(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "checkpoint_package_uid", value)

    @property
    def checkpoint_package_name(self):
        return get_object_extension_value(self, "checkpoint_package_name")

    @checkpoint_package_name.setter
    def checkpoint_package_name(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "checkpoint_package_name", value)

    @property
    def checkpoint_layer_uid(self):
        return get_object_extension_value(self, "checkpoint_layer_uid")

    @checkpoint_layer_uid.setter
    def checkpoint_layer_uid(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "checkpoint_layer_uid", value)

    @property
    def checkpoint_layer_name(self):
        return get_object_extension_value(self, "checkpoint_layer_name")

    @checkpoint_layer_name.setter
    def checkpoint_layer_name(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "checkpoint_layer_name", value)

    @property
    def checkpoint_parent_layer_uid(self):
        return get_object_extension_value(self, "checkpoint_parent_layer_uid")

    @checkpoint_parent_layer_uid.setter
    def checkpoint_parent_layer_uid(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "checkpoint_parent_layer_uid", value)

    @property
    def checkpoint_parent_rule_uid(self):
        return get_object_extension_value(self, "checkpoint_parent_rule_uid")

    @checkpoint_parent_rule_uid.setter
    def checkpoint_parent_rule_uid(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "checkpoint_parent_rule_uid", value)

    @property
    def checkpoint_section_path(self):
        return get_object_extension_value(self, "checkpoint_section_path")

    @checkpoint_section_path.setter
    def checkpoint_section_path(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "checkpoint_section_path", value)

    @property
    def checkpoint_rule_number(self):
        return get_object_extension_value(self, "checkpoint_rule_number")

    @checkpoint_rule_number.setter
    def checkpoint_rule_number(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "checkpoint_rule_number", value)

    @property
    def install_on(self):
        return get_object_extension_value(self, "install_on")

    @install_on.setter
    def install_on(self, value):
        set_object_extension_value(self, IRCheckPointPolicyExtension, "install_on", value)


class IRFortiOSAddressCompatibilityMixin:
    @property
    def source_hw_model(self):
        return get_object_extension_value(self, "source_hw_model")

    @source_hw_model.setter
    def source_hw_model(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_hw_model", value)

    @property
    def source_hw_vendor(self):
        return get_object_extension_value(self, "source_hw_vendor")

    @source_hw_vendor.setter
    def source_hw_vendor(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_hw_vendor", value)

    @property
    def source_cache_ttl(self):
        return get_object_extension_value(self, "source_cache_ttl")

    @source_cache_ttl.setter
    def source_cache_ttl(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_cache_ttl", value)

    @property
    def source_clearpass_spt(self):
        return get_object_extension_value(self, "source_clearpass_spt")

    @source_clearpass_spt.setter
    def source_clearpass_spt(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_clearpass_spt", value)

    @property
    def source_epg_name(self):
        return get_object_extension_value(self, "source_epg_name")

    @source_epg_name.setter
    def source_epg_name(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_epg_name", value)

    @property
    def source_organization(self):
        return get_object_extension_value(self, "source_organization")

    @source_organization.setter
    def source_organization(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_organization", value)

    @property
    def source_os(self):
        return get_object_extension_value(self, "source_os")

    @source_os.setter
    def source_os(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_os", value)

    @property
    def source_policy_group(self):
        return get_object_extension_value(self, "source_policy_group")

    @source_policy_group.setter
    def source_policy_group(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_policy_group", value)

    @property
    def source_route_tag(self):
        return get_object_extension_value(self, "source_route_tag")

    @source_route_tag.setter
    def source_route_tag(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_route_tag", value)

    @property
    def source_sdn(self):
        return get_object_extension_value(self, "source_sdn")

    @source_sdn.setter
    def source_sdn(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_sdn", value)

    @property
    def source_sdn_addr_type(self):
        return get_object_extension_value(self, "source_sdn_addr_type")

    @source_sdn_addr_type.setter
    def source_sdn_addr_type(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_sdn_addr_type", value)

    @property
    def source_sdn_tag(self):
        return get_object_extension_value(self, "source_sdn_tag")

    @source_sdn_tag.setter
    def source_sdn_tag(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_sdn_tag", value)

    @property
    def source_node_ip_only(self):
        return get_object_extension_value(self, "source_node_ip_only")

    @source_node_ip_only.setter
    def source_node_ip_only(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_node_ip_only", value)

    @property
    def source_obj_id(self):
        return get_object_extension_value(self, "source_obj_id")

    @source_obj_id.setter
    def source_obj_id(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_obj_id", value)

    @property
    def source_sub_type(self):
        return get_object_extension_value(self, "source_sub_type")

    @source_sub_type.setter
    def source_sub_type(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_sub_type", value)

    @property
    def source_obj_tag(self):
        return get_object_extension_value(self, "source_obj_tag")

    @source_obj_tag.setter
    def source_obj_tag(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_obj_tag", value)

    @property
    def source_tag_type(self):
        return get_object_extension_value(self, "source_tag_type")

    @source_tag_type.setter
    def source_tag_type(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_tag_type", value)

    @property
    def source_obj_type(self):
        return get_object_extension_value(self, "source_obj_type")

    @source_obj_type.setter
    def source_obj_type(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_obj_type", value)

    @property
    def source_dirty(self):
        return get_object_extension_value(self, "source_dirty")

    @source_dirty.setter
    def source_dirty(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_dirty", value)

    @property
    def source_subnet_name(self):
        return get_object_extension_value(self, "source_subnet_name")

    @source_subnet_name.setter
    def source_subnet_name(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_subnet_name", value)

    @property
    def source_sw_version(self):
        return get_object_extension_value(self, "source_sw_version")

    @source_sw_version.setter
    def source_sw_version(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_sw_version", value)

    @property
    def source_tag_detection_level(self):
        return get_object_extension_value(self, "source_tag_detection_level")

    @source_tag_detection_level.setter
    def source_tag_detection_level(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_tag_detection_level", value)

    @property
    def source_tenant(self):
        return get_object_extension_value(self, "source_tenant")

    @source_tenant.setter
    def source_tenant(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_tenant", value)


    @property
    def source_fsso_group(self):
        return get_object_extension_value(self, "source_fsso_group")

    @source_fsso_group.setter
    def source_fsso_group(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_fsso_group", value)

    @property
    def source_fabric_object_setting(self):
        return get_object_extension_value(self, "source_fabric_object_setting")

    @source_fabric_object_setting.setter
    def source_fabric_object_setting(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_fabric_object_setting", value)

    @property
    def source_effective_defaults(self):
        return get_object_extension_value(self, "source_effective_defaults")

    @source_effective_defaults.setter
    def source_effective_defaults(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_effective_defaults", value)

    @property
    def source_template(self):
        return get_object_extension_value(self, "source_template")

    @source_template.setter
    def source_template(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_template", value)

    @property
    def source_template_reference_resolved(self):
        return get_object_extension_value(self, "source_template_reference_resolved")

    @source_template_reference_resolved.setter
    def source_template_reference_resolved(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_template_reference_resolved", value)


class IRFortiOSAddressGroupCompatibilityMixin:
    @property
    def source_fabric_object_setting(self):
        return get_object_extension_value(self, "source_fabric_object_setting")

    @source_fabric_object_setting.setter
    def source_fabric_object_setting(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_fabric_object_setting", value)

    @property
    def source_group_type(self):
        return get_object_extension_value(self, "source_group_type")

    @source_group_type.setter
    def source_group_type(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_group_type", value)

    @property
    def source_exclude_setting(self):
        return get_object_extension_value(self, "source_exclude_setting")

    @source_exclude_setting.setter
    def source_exclude_setting(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_exclude_setting", value)

    @property
    def source_sub_type(self):
        return get_object_extension_value(self, "source_sub_type")

    @source_sub_type.setter
    def source_sub_type(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_sub_type", value)

    @property
    def source_obj_tag(self):
        return get_object_extension_value(self, "source_obj_tag")

    @source_obj_tag.setter
    def source_obj_tag(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_obj_tag", value)

    @property
    def source_tag_type(self):
        return get_object_extension_value(self, "source_tag_type")

    @source_tag_type.setter
    def source_tag_type(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_tag_type", value)

    @property
    def source_obj_type(self):
        return get_object_extension_value(self, "source_obj_type")

    @source_obj_type.setter
    def source_obj_type(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_obj_type", value)

    @property
    def source_dirty(self):
        return get_object_extension_value(self, "source_dirty")

    @source_dirty.setter
    def source_dirty(self, value):
        set_object_extension_value(self, IRFortiOSAddressExtension, "source_dirty", value)


class IRFortiOSPolicyCompatibilityMixin:
    @property
    def source_utm_status(self):
        return get_object_extension_value(self, "source_utm_status")

    @source_utm_status.setter
    def source_utm_status(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_utm_status", value)

    @property
    def source_inspection_mode(self):
        return get_object_extension_value(self, "source_inspection_mode")

    @source_inspection_mode.setter
    def source_inspection_mode(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_inspection_mode", value)

    @property
    def source_timeout_send_rst(self):
        return get_object_extension_value(self, "source_timeout_send_rst")

    @source_timeout_send_rst.setter
    def source_timeout_send_rst(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_timeout_send_rst", value)

    @property
    def source_auto_asic_offload(self):
        return get_object_extension_value(self, "source_auto_asic_offload")

    @source_auto_asic_offload.setter
    def source_auto_asic_offload(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_auto_asic_offload", value)

    @property
    def source_np_acceleration(self):
        return get_object_extension_value(self, "source_np_acceleration")

    @source_np_acceleration.setter
    def source_np_acceleration(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_np_acceleration", value)

    @property
    def source_port_preserve(self):
        return get_object_extension_value(self, "source_port_preserve")

    @source_port_preserve.setter
    def source_port_preserve(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_port_preserve", value)

    @property
    def source_effective_utm_status(self):
        return get_object_extension_value(self, "source_effective_utm_status")

    @source_effective_utm_status.setter
    def source_effective_utm_status(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_utm_status", value)

    @property
    def source_effective_inspection_mode(self):
        return get_object_extension_value(self, "source_effective_inspection_mode")

    @source_effective_inspection_mode.setter
    def source_effective_inspection_mode(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_inspection_mode", value)

    @property
    def source_effective_ztna_status(self):
        return get_object_extension_value(self, "source_effective_ztna_status")

    @source_effective_ztna_status.setter
    def source_effective_ztna_status(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_ztna_status", value)

    @property
    def source_effective_timeout_send_rst(self):
        return get_object_extension_value(self, "source_effective_timeout_send_rst")

    @source_effective_timeout_send_rst.setter
    def source_effective_timeout_send_rst(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_timeout_send_rst", value)

    @property
    def source_effective_auto_asic_offload(self):
        return get_object_extension_value(self, "source_effective_auto_asic_offload")

    @source_effective_auto_asic_offload.setter
    def source_effective_auto_asic_offload(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_auto_asic_offload", value)

    @property
    def source_effective_np_acceleration(self):
        return get_object_extension_value(self, "source_effective_np_acceleration")

    @source_effective_np_acceleration.setter
    def source_effective_np_acceleration(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_np_acceleration", value)

    @property
    def source_effective_port_preserve(self):
        return get_object_extension_value(self, "source_effective_port_preserve")

    @source_effective_port_preserve.setter
    def source_effective_port_preserve(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_port_preserve", value)

    @property
    def source_policy_expiry(self):
        return get_object_extension_value(self, "source_policy_expiry")

    @source_policy_expiry.setter
    def source_policy_expiry(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_policy_expiry", value)

    @property
    def source_effective_policy_expiry(self):
        return get_object_extension_value(self, "source_effective_policy_expiry")

    @source_effective_policy_expiry.setter
    def source_effective_policy_expiry(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_policy_expiry", value)

    @property
    def source_policy_expiry_date(self):
        return get_object_extension_value(self, "source_policy_expiry_date")

    @source_policy_expiry_date.setter
    def source_policy_expiry_date(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_policy_expiry_date", value)

    @property
    def source_policy_expiry_date_utc(self):
        return get_object_extension_value(self, "source_policy_expiry_date_utc")

    @source_policy_expiry_date_utc.setter
    def source_policy_expiry_date_utc(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_policy_expiry_date_utc", value)

    @property
    def source_schedule_timeout(self):
        return get_object_extension_value(self, "source_schedule_timeout")

    @source_schedule_timeout.setter
    def source_schedule_timeout(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_schedule_timeout", value)

    @property
    def source_effective_schedule_timeout(self):
        return get_object_extension_value(self, "source_effective_schedule_timeout")

    @source_effective_schedule_timeout.setter
    def source_effective_schedule_timeout(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_schedule_timeout", value)

    @property
    def source_reputation_direction(self):
        return get_object_extension_value(self, "source_reputation_direction")

    @source_reputation_direction.setter
    def source_reputation_direction(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_reputation_direction", value)

    @property
    def source_effective_reputation_direction(self):
        return get_object_extension_value(self, "source_effective_reputation_direction")

    @source_effective_reputation_direction.setter
    def source_effective_reputation_direction(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_reputation_direction", value)

    @property
    def source_reputation_direction6(self):
        return get_object_extension_value(self, "source_reputation_direction6")

    @source_reputation_direction6.setter
    def source_reputation_direction6(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_reputation_direction6", value)

    @property
    def source_effective_reputation_direction6(self):
        return get_object_extension_value(self, "source_effective_reputation_direction6")

    @source_effective_reputation_direction6.setter
    def source_effective_reputation_direction6(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_reputation_direction6", value)

    @property
    def source_reputation_minimum(self):
        return get_object_extension_value(self, "source_reputation_minimum")

    @source_reputation_minimum.setter
    def source_reputation_minimum(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_reputation_minimum", value)

    @property
    def source_effective_reputation_minimum(self):
        return get_object_extension_value(self, "source_effective_reputation_minimum")

    @source_effective_reputation_minimum.setter
    def source_effective_reputation_minimum(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_reputation_minimum", value)

    @property
    def source_reputation_minimum6(self):
        return get_object_extension_value(self, "source_reputation_minimum6")

    @source_reputation_minimum6.setter
    def source_reputation_minimum6(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_reputation_minimum6", value)

    @property
    def source_effective_reputation_minimum6(self):
        return get_object_extension_value(self, "source_effective_reputation_minimum6")

    @source_effective_reputation_minimum6.setter
    def source_effective_reputation_minimum6(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_reputation_minimum6", value)

    @property
    def source_match_vip(self):
        return get_object_extension_value(self, "source_match_vip")

    @source_match_vip.setter
    def source_match_vip(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_match_vip", value)

    @property
    def source_effective_match_vip(self):
        return get_object_extension_value(self, "source_effective_match_vip")

    @source_effective_match_vip.setter
    def source_effective_match_vip(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_match_vip", value)

    @property
    def source_match_vip_only(self):
        return get_object_extension_value(self, "source_match_vip_only")

    @source_match_vip_only.setter
    def source_match_vip_only(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_match_vip_only", value)

    @property
    def source_effective_match_vip_only(self):
        return get_object_extension_value(self, "source_effective_match_vip_only")

    @source_effective_match_vip_only.setter
    def source_effective_match_vip_only(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_effective_match_vip_only", value)

    @property
    def source_internet_service_status(self):
        return get_object_extension_value(self, "source_internet_service_status")

    @source_internet_service_status.setter
    def source_internet_service_status(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_internet_service_status", value)

    @property
    def source_internet_service_settings(self):
        return get_object_extension_value(self, "source_internet_service_settings")

    @source_internet_service_settings.setter
    def source_internet_service_settings(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_internet_service_settings", value)

    @property
    def source_vpn_tunnel(self):
        return get_object_extension_value(self, "source_vpn_tunnel")

    @source_vpn_tunnel.setter
    def source_vpn_tunnel(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_vpn_tunnel", value)

    @property
    def source_identity_based_route(self):
        return get_object_extension_value(self, "source_identity_based_route")

    @source_identity_based_route.setter
    def source_identity_based_route(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_identity_based_route", value)

    @property
    def source_ztna_status(self):
        return get_object_extension_value(self, "source_ztna_status")

    @source_ztna_status.setter
    def source_ztna_status(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_ztna_status", value)

    @property
    def source_ztna_ems_tags(self):
        return get_object_extension_value(self, "source_ztna_ems_tags")

    @source_ztna_ems_tags.setter
    def source_ztna_ems_tags(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_ztna_ems_tags", value)

    @property
    def source_ztna_device_ownership(self):
        return get_object_extension_value(self, "source_ztna_device_ownership")

    @source_ztna_device_ownership.setter
    def source_ztna_device_ownership(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_ztna_device_ownership", value)

    @property
    def source_ztna_ems_tags_secondary(self):
        return get_object_extension_value(self, "source_ztna_ems_tags_secondary")

    @source_ztna_ems_tags_secondary.setter
    def source_ztna_ems_tags_secondary(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_ztna_ems_tags_secondary", value)

    @property
    def source_ztna_geo_tags(self):
        return get_object_extension_value(self, "source_ztna_geo_tags")

    @source_ztna_geo_tags.setter
    def source_ztna_geo_tags(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_ztna_geo_tags", value)

    @property
    def source_ztna_policy_redirect(self):
        return get_object_extension_value(self, "source_ztna_policy_redirect")

    @source_ztna_policy_redirect.setter
    def source_ztna_policy_redirect(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_ztna_policy_redirect", value)

    @property
    def source_ztna_tags_match_logic(self):
        return get_object_extension_value(self, "source_ztna_tags_match_logic")

    @source_ztna_tags_match_logic.setter
    def source_ztna_tags_match_logic(self, value):
        set_object_extension_value(self, IRFortiOSPolicyExtension, "source_ztna_tags_match_logic", value)


class IRFortiOSPublishedServiceCompatibilityMixin:
    @property
    def vip_type(self):
        return get_object_extension_value(self, "vip_type")

    @vip_type.setter
    def vip_type(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "vip_type", value)

    @property
    def port_mapping_type(self):
        return get_object_extension_value(self, "port_mapping_type")

    @port_mapping_type.setter
    def port_mapping_type(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "port_mapping_type", value)

    @property
    def arp_reply(self):
        return get_object_extension_value(self, "arp_reply")

    @arp_reply.setter
    def arp_reply(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "arp_reply", value)

    @property
    def gratuitous_arp_interval(self):
        return get_object_extension_value(self, "gratuitous_arp_interval")

    @gratuitous_arp_interval.setter
    def gratuitous_arp_interval(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "gratuitous_arp_interval", value)

    @property
    def nat_source_vip(self):
        return get_object_extension_value(self, "nat_source_vip")

    @nat_source_vip.setter
    def nat_source_vip(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "nat_source_vip", value)

    @property
    def nat44(self):
        return get_object_extension_value(self, "nat44")

    @nat44.setter
    def nat44(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "nat44", value)

    @property
    def nat46(self):
        return get_object_extension_value(self, "nat46")

    @nat46.setter
    def nat46(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "nat46", value)

    @property
    def nat64(self):
        return get_object_extension_value(self, "nat64")

    @nat64.setter
    def nat64(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "nat64", value)

    @property
    def nat66(self):
        return get_object_extension_value(self, "nat66")

    @nat66.setter
    def nat66(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "nat66", value)

    @property
    def add_nat46_route(self):
        return get_object_extension_value(self, "add_nat46_route")

    @add_nat46_route.setter
    def add_nat46_route(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "add_nat46_route", value)

    @property
    def add_nat64_route(self):
        return get_object_extension_value(self, "add_nat64_route")

    @add_nat64_route.setter
    def add_nat64_route(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "add_nat64_route", value)

    @property
    def ndp_reply(self):
        return get_object_extension_value(self, "ndp_reply")

    @ndp_reply.setter
    def ndp_reply(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ndp_reply", value)

    @property
    def ipv6_mapped_ip(self):
        return get_object_extension_value(self, "ipv6_mapped_ip")

    @ipv6_mapped_ip.setter
    def ipv6_mapped_ip(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ipv6_mapped_ip", value)

    @property
    def ipv6_mapped_port(self):
        return get_object_extension_value(self, "ipv6_mapped_port")

    @ipv6_mapped_port.setter
    def ipv6_mapped_port(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ipv6_mapped_port", value)

    @property
    def ipv4_mapped_ip(self):
        return get_object_extension_value(self, "ipv4_mapped_ip")

    @ipv4_mapped_ip.setter
    def ipv4_mapped_ip(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ipv4_mapped_ip", value)

    @property
    def ipv4_mapped_port(self):
        return get_object_extension_value(self, "ipv4_mapped_port")

    @ipv4_mapped_port.setter
    def ipv4_mapped_port(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ipv4_mapped_port", value)

    @property
    def embedded_ipv4_address(self):
        return get_object_extension_value(self, "embedded_ipv4_address")

    @embedded_ipv4_address.setter
    def embedded_ipv4_address(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "embedded_ipv4_address", value)

    @property
    def server_type(self):
        return get_object_extension_value(self, "server_type")

    @server_type.setter
    def server_type(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "server_type", value)

    @property
    def http_redirect(self):
        return get_object_extension_value(self, "http_redirect")

    @http_redirect.setter
    def http_redirect(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "http_redirect", value)

    @property
    def h2_support(self):
        return get_object_extension_value(self, "h2_support")

    @h2_support.setter
    def h2_support(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "h2_support", value)

    @property
    def h3_support(self):
        return get_object_extension_value(self, "h3_support")

    @h3_support.setter
    def h3_support(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "h3_support", value)

    @property
    def http_multiplex(self):
        return get_object_extension_value(self, "http_multiplex")

    @http_multiplex.setter
    def http_multiplex(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "http_multiplex", value)

    @property
    def ssl_mode(self):
        return get_object_extension_value(self, "ssl_mode")

    @ssl_mode.setter
    def ssl_mode(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ssl_mode", value)

    @property
    def ssl_algorithm(self):
        return get_object_extension_value(self, "ssl_algorithm")

    @ssl_algorithm.setter
    def ssl_algorithm(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ssl_algorithm", value)

    @property
    def ssl_min_version(self):
        return get_object_extension_value(self, "ssl_min_version")

    @ssl_min_version.setter
    def ssl_min_version(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ssl_min_version", value)

    @property
    def ssl_max_version(self):
        return get_object_extension_value(self, "ssl_max_version")

    @ssl_max_version.setter
    def ssl_max_version(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ssl_max_version", value)

    @property
    def ssl_server_algorithm(self):
        return get_object_extension_value(self, "ssl_server_algorithm")

    @ssl_server_algorithm.setter
    def ssl_server_algorithm(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ssl_server_algorithm", value)

    @property
    def ssl_server_min_version(self):
        return get_object_extension_value(self, "ssl_server_min_version")

    @ssl_server_min_version.setter
    def ssl_server_min_version(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ssl_server_min_version", value)

    @property
    def ssl_server_max_version(self):
        return get_object_extension_value(self, "ssl_server_max_version")

    @ssl_server_max_version.setter
    def ssl_server_max_version(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ssl_server_max_version", value)

    @property
    def ssl_pfs(self):
        return get_object_extension_value(self, "ssl_pfs")

    @ssl_pfs.setter
    def ssl_pfs(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "ssl_pfs", value)

    @property
    def gslb_domain_name(self):
        return get_object_extension_value(self, "gslb_domain_name")

    @gslb_domain_name.setter
    def gslb_domain_name(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "gslb_domain_name", value)

    @property
    def gslb_hostname(self):
        return get_object_extension_value(self, "gslb_hostname")

    @gslb_hostname.setter
    def gslb_hostname(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "gslb_hostname", value)

    @property
    def max_embryonic_connections(self):
        return get_object_extension_value(self, "max_embryonic_connections")

    @max_embryonic_connections.setter
    def max_embryonic_connections(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "max_embryonic_connections", value)

    @property
    def source_gslb_public_ips(self):
        return get_object_extension_value(self, "source_gslb_public_ips")

    @source_gslb_public_ips.setter
    def source_gslb_public_ips(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "source_gslb_public_ips", value)

    @property
    def source_quic(self):
        return get_object_extension_value(self, "source_quic")

    @source_quic.setter
    def source_quic(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "source_quic", value)

    @property
    def source_ssl_cipher_suites(self):
        return get_object_extension_value(self, "source_ssl_cipher_suites")

    @source_ssl_cipher_suites.setter
    def source_ssl_cipher_suites(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "source_ssl_cipher_suites", value)

    @property
    def source_ssl_server_cipher_suites(self):
        return get_object_extension_value(self, "source_ssl_server_cipher_suites")

    @source_ssl_server_cipher_suites.setter
    def source_ssl_server_cipher_suites(self, value):
        set_object_extension_value(self, IRFortiOSPublishedServiceExtension, "source_ssl_server_cipher_suites", value)


class IRFortiOSNATPoolCompatibilityMixin:
    @property
    def arp_reply(self):
        return get_object_extension_value(self, "arp_reply")

    @arp_reply.setter
    def arp_reply(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "arp_reply", value)

    @property
    def arp_interface(self):
        return get_object_extension_value(self, "arp_interface")

    @arp_interface.setter
    def arp_interface(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "arp_interface", value)

    @property
    def block_size(self):
        return get_object_extension_value(self, "block_size")

    @block_size.setter
    def block_size(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "block_size", value)

    @property
    def blocks_per_user(self):
        return get_object_extension_value(self, "blocks_per_user")

    @blocks_per_user.setter
    def blocks_per_user(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "blocks_per_user", value)

    @property
    def pba_timeout(self):
        return get_object_extension_value(self, "pba_timeout")

    @pba_timeout.setter
    def pba_timeout(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "pba_timeout", value)

    @property
    def pba_interim_log(self):
        return get_object_extension_value(self, "pba_interim_log")

    @pba_interim_log.setter
    def pba_interim_log(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "pba_interim_log", value)

    @property
    def ports_per_user(self):
        return get_object_extension_value(self, "ports_per_user")

    @ports_per_user.setter
    def ports_per_user(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "ports_per_user", value)

    @property
    def privileged_port_use_pba(self):
        return get_object_extension_value(self, "privileged_port_use_pba")

    @privileged_port_use_pba.setter
    def privileged_port_use_pba(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "privileged_port_use_pba", value)

    @property
    def nat64(self):
        return get_object_extension_value(self, "nat64")

    @nat64.setter
    def nat64(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "nat64", value)

    @property
    def add_nat64_route(self):
        return get_object_extension_value(self, "add_nat64_route")

    @add_nat64_route.setter
    def add_nat64_route(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "add_nat64_route", value)

    @property
    def client_prefix_length(self):
        return get_object_extension_value(self, "client_prefix_length")

    @client_prefix_length.setter
    def client_prefix_length(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "client_prefix_length", value)

    @property
    def include_subnet_broadcast(self):
        return get_object_extension_value(self, "include_subnet_broadcast")

    @include_subnet_broadcast.setter
    def include_subnet_broadcast(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "include_subnet_broadcast", value)

    @property
    def tcp_session_quota(self):
        return get_object_extension_value(self, "tcp_session_quota")

    @tcp_session_quota.setter
    def tcp_session_quota(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "tcp_session_quota", value)

    @property
    def udp_session_quota(self):
        return get_object_extension_value(self, "udp_session_quota")

    @udp_session_quota.setter
    def udp_session_quota(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "udp_session_quota", value)

    @property
    def icmp_session_quota(self):
        return get_object_extension_value(self, "icmp_session_quota")

    @icmp_session_quota.setter
    def icmp_session_quota(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "icmp_session_quota", value)

    @property
    def cgn_block_size(self):
        return get_object_extension_value(self, "cgn_block_size")

    @cgn_block_size.setter
    def cgn_block_size(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "cgn_block_size", value)

    @property
    def cgn_client_start_ip(self):
        return get_object_extension_value(self, "cgn_client_start_ip")

    @cgn_client_start_ip.setter
    def cgn_client_start_ip(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "cgn_client_start_ip", value)

    @property
    def cgn_client_end_ip(self):
        return get_object_extension_value(self, "cgn_client_end_ip")

    @cgn_client_end_ip.setter
    def cgn_client_end_ip(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "cgn_client_end_ip", value)

    @property
    def cgn_client_ipv6_shift(self):
        return get_object_extension_value(self, "cgn_client_ipv6_shift")

    @cgn_client_ipv6_shift.setter
    def cgn_client_ipv6_shift(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "cgn_client_ipv6_shift", value)

    @property
    def cgn_fixed_allocation(self):
        return get_object_extension_value(self, "cgn_fixed_allocation")

    @cgn_fixed_allocation.setter
    def cgn_fixed_allocation(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "cgn_fixed_allocation", value)

    @property
    def cgn_overload(self):
        return get_object_extension_value(self, "cgn_overload")

    @cgn_overload.setter
    def cgn_overload(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "cgn_overload", value)

    @property
    def cgn_port_start(self):
        return get_object_extension_value(self, "cgn_port_start")

    @cgn_port_start.setter
    def cgn_port_start(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "cgn_port_start", value)

    @property
    def cgn_port_end(self):
        return get_object_extension_value(self, "cgn_port_end")

    @cgn_port_end.setter
    def cgn_port_end(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "cgn_port_end", value)

    @property
    def cgn_spa(self):
        return get_object_extension_value(self, "cgn_spa")

    @cgn_spa.setter
    def cgn_spa(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "cgn_spa", value)

    @property
    def utilization_alarm_clear(self):
        return get_object_extension_value(self, "utilization_alarm_clear")

    @utilization_alarm_clear.setter
    def utilization_alarm_clear(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "utilization_alarm_clear", value)

    @property
    def utilization_alarm_raise(self):
        return get_object_extension_value(self, "utilization_alarm_raise")

    @utilization_alarm_raise.setter
    def utilization_alarm_raise(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "utilization_alarm_raise", value)

    @property
    def nat46(self):
        return get_object_extension_value(self, "nat46")

    @nat46.setter
    def nat46(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "nat46", value)

    @property
    def add_nat46_route(self):
        return get_object_extension_value(self, "add_nat46_route")

    @add_nat46_route.setter
    def add_nat46_route(self, value):
        set_object_extension_value(self, IRFortiOSNATPoolExtension, "add_nat46_route", value)


class IRFortiOSNATRuleCompatibilityMixin:
    @property
    def source_pool_group_references(self):
        return get_object_extension_value(self, "source_pool_group_references")

    @source_pool_group_references.setter
    def source_pool_group_references(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_pool_group_references", value)

    @property
    def source_pool_type(self):
        return get_object_extension_value(self, "source_pool_type")

    @source_pool_type.setter
    def source_pool_type(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_pool_type", value)

    @property
    def source_pool_excluded_ips(self):
        return get_object_extension_value(self, "source_pool_excluded_ips")

    @source_pool_excluded_ips.setter
    def source_pool_excluded_ips(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_pool_excluded_ips", value)

    @property
    def source_pool_permit_any_host(self):
        return get_object_extension_value(self, "source_pool_permit_any_host")

    @source_pool_permit_any_host.setter
    def source_pool_permit_any_host(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_pool_permit_any_host", value)

    @property
    def source_pool_original_start_ip(self):
        return get_object_extension_value(self, "source_pool_original_start_ip")

    @source_pool_original_start_ip.setter
    def source_pool_original_start_ip(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_pool_original_start_ip", value)

    @property
    def source_pool_original_end_ip(self):
        return get_object_extension_value(self, "source_pool_original_end_ip")

    @source_pool_original_end_ip.setter
    def source_pool_original_end_ip(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_pool_original_end_ip", value)

    @property
    def source_vip_reference(self):
        return get_object_extension_value(self, "source_vip_reference")

    @source_vip_reference.setter
    def source_vip_reference(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_vip_reference", value)

    @property
    def source_vip_group_reference(self):
        return get_object_extension_value(self, "source_vip_group_reference")

    @source_vip_group_reference.setter
    def source_vip_group_reference(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_vip_group_reference", value)

    @property
    def source_vip_type(self):
        return get_object_extension_value(self, "source_vip_type")

    @source_vip_type.setter
    def source_vip_type(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_vip_type", value)

    @property
    def source_vip_enabled(self):
        return get_object_extension_value(self, "source_vip_enabled")

    @source_vip_enabled.setter
    def source_vip_enabled(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_vip_enabled", value)

    @property
    def source_vip_nat_source_vip(self):
        return get_object_extension_value(self, "source_vip_nat_source_vip")

    @source_vip_nat_source_vip.setter
    def source_vip_nat_source_vip(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_vip_nat_source_vip", value)

    @property
    def source_vip_filters(self):
        return get_object_extension_value(self, "source_vip_filters")

    @source_vip_filters.setter
    def source_vip_filters(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_vip_filters", value)

    @property
    def source_vip_interface_filters(self):
        return get_object_extension_value(self, "source_vip_interface_filters")

    @source_vip_interface_filters.setter
    def source_vip_interface_filters(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_vip_interface_filters", value)

    @property
    def source_vip_services(self):
        return get_object_extension_value(self, "source_vip_services")

    @source_vip_services.setter
    def source_vip_services(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_vip_services", value)

    @property
    def source_vip_port_mapping_type(self):
        return get_object_extension_value(self, "source_vip_port_mapping_type")

    @source_vip_port_mapping_type.setter
    def source_vip_port_mapping_type(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_vip_port_mapping_type", value)

    @property
    def source_policy_fixed_port(self):
        return get_object_extension_value(self, "source_policy_fixed_port")

    @source_policy_fixed_port.setter
    def source_policy_fixed_port(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_policy_fixed_port", value)

    @property
    def source_policy_nat46(self):
        return get_object_extension_value(self, "source_policy_nat46")

    @source_policy_nat46.setter
    def source_policy_nat46(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_policy_nat46", value)

    @property
    def source_policy_nat64(self):
        return get_object_extension_value(self, "source_policy_nat64")

    @source_policy_nat64.setter
    def source_policy_nat64(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_policy_nat64", value)

    @property
    def source_policy_nat_inbound(self):
        return get_object_extension_value(self, "source_policy_nat_inbound")

    @source_policy_nat_inbound.setter
    def source_policy_nat_inbound(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_policy_nat_inbound", value)

    @property
    def source_policy_nat_outbound(self):
        return get_object_extension_value(self, "source_policy_nat_outbound")

    @source_policy_nat_outbound.setter
    def source_policy_nat_outbound(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_policy_nat_outbound", value)

    @property
    def source_policy_nat_ip(self):
        return get_object_extension_value(self, "source_policy_nat_ip")

    @source_policy_nat_ip.setter
    def source_policy_nat_ip(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_policy_nat_ip", value)

    @property
    def source_policy_match_vip(self):
        return get_object_extension_value(self, "source_policy_match_vip")

    @source_policy_match_vip.setter
    def source_policy_match_vip(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_policy_match_vip", value)

    @property
    def source_policy_match_vip_only(self):
        return get_object_extension_value(self, "source_policy_match_vip_only")

    @source_policy_match_vip_only.setter
    def source_policy_match_vip_only(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_policy_match_vip_only", value)

    @property
    def source_policy_effective_match_vip(self):
        return get_object_extension_value(self, "source_policy_effective_match_vip")

    @source_policy_effective_match_vip.setter
    def source_policy_effective_match_vip(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_policy_effective_match_vip", value)

    @property
    def source_policy_effective_match_vip_only(self):
        return get_object_extension_value(self, "source_policy_effective_match_vip_only")

    @source_policy_effective_match_vip_only.setter
    def source_policy_effective_match_vip_only(self, value):
        set_object_extension_value(self, IRFortiOSNATRuleExtension, "source_policy_effective_match_vip_only", value)


class IRCheckPointNATPoolCompatibilityMixin:
    @property
    def checkpoint_pool_object_type(self):
        return get_object_extension_value(self, "checkpoint_pool_object_type")

    @checkpoint_pool_object_type.setter
    def checkpoint_pool_object_type(self, value):
        set_object_extension_value(self, IRCheckPointNATPoolExtension, "checkpoint_pool_object_type", value)

    @property
    def checkpoint_network_references(self):
        return get_object_extension_value(self, "checkpoint_network_references")

    @checkpoint_network_references.setter
    def checkpoint_network_references(self, value):
        set_object_extension_value(self, IRCheckPointNATPoolExtension, "checkpoint_network_references", value)

    @property
    def checkpoint_network_group_references(self):
        return get_object_extension_value(self, "checkpoint_network_group_references")

    @checkpoint_network_group_references.setter
    def checkpoint_network_group_references(self, value):
        set_object_extension_value(self, IRCheckPointNATPoolExtension, "checkpoint_network_group_references", value)

    @property
    def checkpoint_address_range_references(self):
        return get_object_extension_value(self, "checkpoint_address_range_references")

    @checkpoint_address_range_references.setter
    def checkpoint_address_range_references(self, value):
        set_object_extension_value(self, IRCheckPointNATPoolExtension, "checkpoint_address_range_references", value)

    @property
    def checkpoint_gateway_references(self):
        return get_object_extension_value(self, "checkpoint_gateway_references")

    @checkpoint_gateway_references.setter
    def checkpoint_gateway_references(self, value):
        set_object_extension_value(self, IRCheckPointNATPoolExtension, "checkpoint_gateway_references", value)

    @property
    def checkpoint_member_assignments(self):
        return get_object_extension_value(self, "checkpoint_member_assignments")

    @checkpoint_member_assignments.setter
    def checkpoint_member_assignments(self, value):
        set_object_extension_value(self, IRCheckPointNATPoolExtension, "checkpoint_member_assignments", value)

    @property
    def checkpoint_applicability(self):
        return get_object_extension_value(self, "checkpoint_applicability")

    @checkpoint_applicability.setter
    def checkpoint_applicability(self, value):
        set_object_extension_value(self, IRCheckPointNATPoolExtension, "checkpoint_applicability", value)

    @property
    def checkpoint_precedence(self):
        return get_object_extension_value(self, "checkpoint_precedence")

    @checkpoint_precedence.setter
    def checkpoint_precedence(self, value):
        set_object_extension_value(self, IRCheckPointNATPoolExtension, "checkpoint_precedence", value)

    @property
    def checkpoint_vpn_scope(self):
        return get_object_extension_value(self, "checkpoint_vpn_scope")

    @checkpoint_vpn_scope.setter
    def checkpoint_vpn_scope(self, value):
        set_object_extension_value(self, IRCheckPointNATPoolExtension, "checkpoint_vpn_scope", value)

    @property
    def checkpoint_mep(self):
        return get_object_extension_value(self, "checkpoint_mep")

    @checkpoint_mep.setter
    def checkpoint_mep(self, value):
        set_object_extension_value(self, IRCheckPointNATPoolExtension, "checkpoint_mep", value)


class IRCheckPointNATRuleCompatibilityMixin:
    @property
    def checkpoint_domain_uid(self):
        return get_object_extension_value(self, "checkpoint_domain_uid")

    @checkpoint_domain_uid.setter
    def checkpoint_domain_uid(self, value):
        set_object_extension_value(self, IRCheckPointNATRuleExtension, "checkpoint_domain_uid", value)

    @property
    def checkpoint_domain_name(self):
        return get_object_extension_value(self, "checkpoint_domain_name")

    @checkpoint_domain_name.setter
    def checkpoint_domain_name(self, value):
        set_object_extension_value(self, IRCheckPointNATRuleExtension, "checkpoint_domain_name", value)

    @property
    def checkpoint_package_uid(self):
        return get_object_extension_value(self, "checkpoint_package_uid")

    @checkpoint_package_uid.setter
    def checkpoint_package_uid(self, value):
        set_object_extension_value(self, IRCheckPointNATRuleExtension, "checkpoint_package_uid", value)

    @property
    def checkpoint_package_name(self):
        return get_object_extension_value(self, "checkpoint_package_name")

    @checkpoint_package_name.setter
    def checkpoint_package_name(self, value):
        set_object_extension_value(self, IRCheckPointNATRuleExtension, "checkpoint_package_name", value)


class IRCheckPointInterfaceCompatibilityMixin:
    @property
    def checkpoint_context(self):
        return get_object_extension_value(self, "checkpoint_context")

    @checkpoint_context.setter
    def checkpoint_context(self, value):
        set_object_extension_value(self, IRCheckPointInterfaceExtension, "checkpoint_context", value)


__all__ = [
    "IRVendorExtensionIdentity",
    "IRFortiOSPublishedServiceGSLBPublicIP",
    "IRFortiOSPublishedServiceQUICSettings",
    "IRFortiOSPublishedServiceSSLCipherSuite",
    "IRFortiOSAddressExtension",
    "IRFortiOSNATPoolExtension",
    "IRFortiOSNATRuleExtension",
    "IRFortiOSPolicyExtension",
    "IRFortiOSPublishedServiceExtension",
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
    "IRCheckPointObjectCompatibilityMixin",
    "IRCheckPointPolicyCompatibilityMixin",
    "IRFortiOSAddressCompatibilityMixin",
    "IRFortiOSPolicyCompatibilityMixin",
    "IRFortiOSPublishedServiceCompatibilityMixin",
    "IRFortiOSNATPoolCompatibilityMixin",
    "IRFortiOSNATRuleCompatibilityMixin",
    "IRCheckPointNATPoolCompatibilityMixin",
    "IRCheckPointNATRuleCompatibilityMixin",
    "IRCheckPointInterfaceCompatibilityMixin",
]
