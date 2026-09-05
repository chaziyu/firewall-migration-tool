from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, model_validator

from fwmigrate.ir.version import IR_SCHEMA_VERSION
from fwmigrate.ir.enums import (
    AddressType, ServiceProtocol, PolicyAction, NATType, NATTranslationMode,
    NATFamily, NATSourcePortBehavior, MigrationConfidence,
)

class IRMetadata(BaseModel):
    hostname: Optional[str] = None
    source_vendor: str = "fortinet"
    target_vendor: Optional[str] = None
    input_type: str = "Unknown"
    source_version: Optional[str] = None
    source_context: Optional[str] = None
    migration_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class IRZoneTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRZone(BaseModel):
    name: str
    zone_type: str = "system"
    source_context: Optional[str] = None
    source_path: Optional[str] = None
    interfaces: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    source_intrazone: Optional[str] = None
    source_tagging_entries: List["IRZoneTaggingEntry"] = Field(default_factory=list)
    disabled: Optional[bool] = None
    source_log_setting: Optional[str] = None
    source_log_setting_resolved: Optional[str] = None
    resolved_source_log_setting: Optional[str] = None
    source_user_identification_enabled: Optional[bool] = None
    requires_manual_review: bool = False
    migration_status: str = "NORMALIZED"
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRInterfaceSecondaryIP(BaseModel):
    source_id: Optional[str] = None
    source_ip: Optional[str] = None
    ip: Optional[str] = None  # CIDR format: 192.168.1.1/24
    management_access: List[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    parse_error: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRSourceConfigCommand(BaseModel):
    """Sanitized source configuration command."""

    operation: str
    key: str
    values: List[str] = Field(
        default_factory=list
    )


class IRSourceConfigNode(BaseModel):
    node_type: str
    name: str

    commands: List[
        IRSourceConfigCommand
    ] = Field(default_factory=list)

    children: List[
        "IRSourceConfigNode"
    ] = Field(default_factory=list)

class IRInterfaceIPv6Address(BaseModel):
    address: Optional[str] = None
    source_address: str

class IRInterfaceIPv6PrefixAdvertisement(BaseModel):
    prefix: Optional[str] = None
    source_prefix: str
    autonomous_flag: Optional[str] = None
    dnssl: List[str] = Field(default_factory=list)
    onlink_flag: Optional[str] = None
    preferred_life_time: Optional[int] = None
    rdnss: List[str] = Field(default_factory=list)
    valid_life_time: Optional[int] = None

class IRInterfaceIPv6DelegatedPrefix(BaseModel):
    prefix_id: str
    autonomous_flag: Optional[str] = None
    delegated_prefix_iaid: Optional[int] = None
    onlink_flag: Optional[str] = None
    rdnss: List[str] = Field(default_factory=list)
    rdnss_service: Optional[str] = None
    subnet: Optional[str] = None
    source_subnet: Optional[str] = None
    upstream_interface: Optional[str] = None

class IRInterfaceDHCPv6IAPD(BaseModel):
    source_iaid: str
    iaid: Optional[int] = None
    prefix_hint: Optional[str] = None
    prefix_hint_plt: Optional[int] = None
    prefix_hint_vlt: Optional[int] = None

class IRInterfaceVRRP6(BaseModel):
    source_vrid: str
    vrid: Optional[int] = None
    accept_mode: Optional[str] = None
    adv_interval: Optional[int] = None
    ignore_default_route: Optional[str] = None
    preempt: Optional[str] = None
    priority: Optional[int] = None
    start_time: Optional[str] = None
    status: Optional[str] = None
    vrdst6: Optional[str] = None
    source_vrdst6: Optional[str] = None
    vrgrp: Optional[int] = None
    vrip6: Optional[str] = None
    source_vrip6: Optional[str] = None

class IRInterface(BaseModel):
    name: str
    source_context: Optional[str] = None
    zone: Optional[str] = None
    ip: Optional[str] = None
    # IPv6 interface addressing is kept separate from the legacy IPv4 scalar.
    # ``source_ipv6_address`` retains the exact FortiGate value while
    # ``ipv6_address`` contains a safe normalized interface prefix when one
    # can be parsed.
    ipv6_address: Optional[str] = None
    source_ipv6_address: Optional[str] = None
    source_ipv6_management_access: List[str] = Field(default_factory=list)
    source_ipv6_mode: Optional[str] = None
    source_ipv6_send_adv: Optional[str] = None
    source_ipv6_manage_flag: Optional[str] = None
    source_ipv6_other_flag: Optional[str] = None
    source_ipv6_autoconf: Optional[str] = None
    source_cli_conn6_status: Optional[int] = None
    source_dhcp6_client_options: List[str] = Field(default_factory=list)
    source_dhcp6_information_request: Optional[str] = None
    source_dhcp6_prefix_delegation: Optional[str] = None
    source_dhcp6_relay_interface_id: Optional[str] = None
    source_dhcp6_relay_ip: List[str] = Field(default_factory=list)
    source_dhcp6_relay_service: Optional[str] = None
    source_dhcp6_relay_source_interface: Optional[str] = None
    source_dhcp6_relay_source_ip: Optional[str] = None
    source_dhcp6_relay_type: Optional[str] = None
    source_icmp6_send_redirect: Optional[str] = None
    source_ipv6_interface_identifier: Optional[str] = None
    source_ip6_default_life: Optional[int] = None
    source_ip6_delegated_prefix_iaid: Optional[int] = None
    source_ip6_dns_server_override: Optional[str] = None
    source_ip6_hop_limit: Optional[int] = None
    source_ip6_link_mtu: Optional[int] = None
    source_ip6_max_interval: Optional[int] = None
    source_ip6_min_interval: Optional[int] = None
    source_ip6_prefix_mode: Optional[str] = None
    source_ip6_reachable_time: Optional[int] = None
    source_ip6_retrans_time: Optional[int] = None
    source_ip6_subnet: Optional[str] = None
    source_ip6_upstream_interface: Optional[str] = None
    additional_ipv6_addresses: List[IRInterfaceIPv6Address] = Field(default_factory=list)
    ipv6_prefix_advertisements: List[IRInterfaceIPv6PrefixAdvertisement] = Field(default_factory=list)
    ipv6_delegated_prefixes: List[IRInterfaceIPv6DelegatedPrefix] = Field(default_factory=list)
    dhcp6_iapd: List[IRInterfaceDHCPv6IAPD] = Field(default_factory=list)
    vrrp6: List[IRInterfaceVRRP6] = Field(default_factory=list)
    remote_ip: Optional[str] = None
    # FortiGate's parent secondary-IP enable state is distinct from the
    # configured child entries.  Keep it source-oriented so disabled or
    # ambiguous entries cannot be mistaken for active interface addresses.
    source_secondary_ip_status: Optional[str] = None
    secondary_ips: List[
        IRInterfaceSecondaryIP
    ] = Field(default_factory=list)
    inactive_secondary_ips: List[
        IRInterfaceSecondaryIP
    ] = Field(default_factory=list)
    description: Optional[str] = None
    mtu: Optional[int] = None
    management_profile: Optional[str] = None
    parent: Optional[str] = None
    tag: Optional[int] = None
    alias: Optional[str] = None
    status: bool = True
    vlanid: Optional[int] = None
    pppoe_mode: Optional[str] = None
    pppoe_username: Optional[str] = None
    # Safe PPPoE credential metadata; the credential itself is never serialized.
    has_pppoe_password: Optional[bool] = None
    pppoe_password_format: Optional[str] = None
    # Source-side interface DNS override behavior; not assumed portable.
    source_dns_server_override: Optional[bool] = None
    # Source-side dedicated interface purpose; not assumed portable.
    source_dedicated_to: Optional[str] = None
    # Source-side SAML server reference used for FortiGate IKE authentication.
    # This is a source semantic and is not assumed directly portable.
    source_ike_saml_server: Optional[str] = None
    source_ike_saml_server_resolved: Optional[bool] = None
    # Whether FortiGate source-IP checking is enabled on the interface.
    # This affects source packet validation and is not assumed directly portable.
    source_src_check: Optional[bool] = None
    source_vdom: Optional[str] = None
    # Source-preserved FortiGate VRF ID. This is intentionally source-scoped
    # until equivalent cross-vendor routing-instance semantics are defined.
    source_vrf: Optional[int] = None
    # PAN-OS routing-instance identity. This is separate from the
    # FortiGate-specific numeric VRF evidence above.
    source_routing_instance: Optional[str] = None
    source_routing_instance_type: Optional[str] = None
    # PAN-OS operational settings retained as source-oriented inventory data.
    # These fields are convenience projections and are not portable target
    # semantics.
    source_mtu: Optional[int] = None
    source_link_state: Optional[str] = None
    source_speed: Optional[str] = None
    source_duplex: Optional[str] = None
    # Structured source inventory; not portable target-vendor media semantics.
    source_media_type: Optional[str] = None
    # Source monitoring metadata; not portable packet-forwarding semantics.
    source_monitor_bandwidth: Optional[bool] = None
    # Source inventory only; this does not imply target-vendor portability.
    source_device_identification: Optional[str] = None
    source_netflow_profile: Optional[str] = None
    source_lldp_enabled: Optional[str] = None
    interface_type: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    source_lacp_mode: Optional[str] = None
    source_lacp_ha_secondary: Optional[str] = None
    source_lacp_system_id_type: Optional[str] = None
    source_lacp_system_id: Optional[str] = None
    source_lacp_speed: Optional[str] = None
    source_min_links: Optional[int] = None
    source_min_links_down: Optional[str] = None
    source_aggregate_algorithm: Optional[str] = None
    source_aggregate_type: Optional[str] = None
    source_priority_override: Optional[str] = None
    source_aggregate_parent: Optional[str] = None
    source_redundant_interface_parent: Optional[str] = None
    source_explicit_aggregate_fields: List[str] = Field(default_factory=list)
    role: Optional[str] = None
    addressing_mode: Optional[str] = None
    management_access: List[str] = Field(
        default_factory=list
    )
    dhcp_client: Optional[bool] = None
    requires_manual_review: bool = False
    migration_status: str = "NORMALIZED"
    review_reasons: List[str] = Field(default_factory=list)
    parse_errors: List[str] = Field(
        default_factory=list
    )
    nested_source_configs: List[
        IRSourceConfigNode
    ] = Field(default_factory=list)
    ipv6_source_settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(
        default_factory=dict
    )

class IRAddressTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRMACAddressEntry(BaseModel):
    start: str
    end: Optional[str] = None


class IRAddress(BaseModel):
    name: str
    type: AddressType
    source_context: Optional[str] = None

    # Source provenance and extraction-only metadata. Target generators must
    # not interpret source-only fields as portable address semantics.
    source_uuid: Optional[str] = None
    source_section: Optional[str] = None
    address_family: Optional[str] = None
    source_type: Optional[str] = None
    source_list_entries: List[str] = Field(default_factory=list)
    source_tagging_entries: List[IRAddressTaggingEntry] = Field(default_factory=list)
    associated_interface: Optional[str] = None
    allow_routing: Optional[bool] = None
    source_color: Optional[int] = None
    source_interface: Optional[str] = None
    resolved_interface_subnet: Optional[str] = None
    interface_reference_resolved: Optional[bool] = None
    source_fsso_group: Optional[str] = None
    source_hw_model: Optional[str] = None
    source_hw_vendor: Optional[str] = None
    source_cache_ttl: Optional[int] = None
    source_clearpass_spt: Optional[str] = None
    source_epg_name: Optional[str] = None
    source_fabric_object_setting: Optional[str] = None
    source_organization: Optional[str] = None
    source_os: Optional[str] = None
    source_policy_group: Optional[str] = None
    source_route_tag: Optional[int] = None
    source_sdn: Optional[str] = None
    source_sdn_addr_type: Optional[str] = None
    source_sdn_tag: Optional[str] = None
    source_node_ip_only: Optional[bool] = None
    source_obj_id: Optional[str] = None
    source_sub_type: Optional[str] = None
    source_obj_tag: Optional[str] = None
    source_tag_type: Optional[str] = None
    source_obj_type: Optional[str] = None
    source_dirty: Optional[str] = None
    source_subnet_name: Optional[str] = None
    source_sw_version: Optional[str] = None
    source_tag_detection_level: Optional[str] = None
    source_tenant: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None
    
    # Typed fields
    subnet: Optional[str] = None
    ip_range_start: Optional[str] = None
    ip_range_end: Optional[str] = None
    fqdn: Optional[str] = None
    mac: Optional[str] = None
    mac_entries: List[IRMACAddressEntry] = Field(default_factory=list)
    geo_code: Optional[str] = None
    wildcard_mask: Optional[str] = None
    dynamic_filter: Optional[str] = None
    tag_name: Optional[str] = None
    stub_value: Optional[str] = None
    
    # Stub & manual review fields
    original_type: Optional[str] = None
    original_value: Optional[str] = None
    
    @model_validator(mode="before")
    @classmethod
    def map_value_to_typed_field(cls, data: dict) -> dict:
        if isinstance(data, dict) and "value" in data and "type" in data:
            val = data.pop("value")
            t = data["type"]
            # Enums might be passed as strings or Enum members
            t_val = t.value if hasattr(t, "value") else t
            if t_val in ("network", "host"):
                data.setdefault("subnet", val)
            elif t_val in ("fqdn", "wildcard"):
                data.setdefault("fqdn", val)
            elif t_val == "range":
                if "-" in val:
                    start, end = val.split("-", 1)
                    data.setdefault("ip_range_start", start)
                    data.setdefault("ip_range_end", end)
            elif t_val == "mac":
                data.setdefault("mac", val)
            elif t_val == "geo":
                data.setdefault("geo_code", val)
            elif t_val == "wildcard_mask":
                data.setdefault("wildcard_mask", val)
            elif t_val == "dynamic":
                data.setdefault("dynamic_filter", val)
            elif t_val == "ems_tag":
                data.setdefault("tag_name", val)
            elif t_val == "special":
                data.setdefault("original_value", val)
            elif t_val == "stub_unsupported":
                data.setdefault("stub_value", val)
        return data
        
    # Graceful degradation fields
    parse_error: Optional[str] = None
    raw_value: Optional[str] = None
    
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    is_ipv6: bool = False
    is_multicast: bool = False

    @property
    def value(self) -> str:
        if self.parse_error is not None:
            return self.raw_value or ""
        
        if self.type in (AddressType.NETWORK, AddressType.HOST) and self.subnet:
            return self.subnet
        elif self.type == AddressType.RANGE and self.ip_range_start and self.ip_range_end:
            return f"{self.ip_range_start}-{self.ip_range_end}"
        elif self.type in (AddressType.FQDN, AddressType.WILDCARD_FQDN) and self.fqdn:
            return self.fqdn
        elif self.type == AddressType.MAC:
            if self.mac:
                return self.mac
            return "; ".join(
                f"{entry.start}-{entry.end}" if entry.end else entry.start
                for entry in self.mac_entries
            )
        elif self.type == AddressType.GEO and self.geo_code:
            return self.geo_code
        elif self.type == AddressType.WILDCARD_MASK and self.wildcard_mask:
            return self.wildcard_mask
        elif self.type == AddressType.DYNAMIC and self.dynamic_filter:
            return self.dynamic_filter
        elif self.type == AddressType.EMS_TAG and self.tag_name:
            return self.tag_name
        elif self.type == AddressType.SPECIAL:
            if self.original_value is not None:
                return self.original_value
            return self.name
        elif self.type == AddressType.STUB_UNSUPPORTED:
            return self.stub_value or self.subnet or ""
            
        return ""


    @model_validator(mode="after")
    def validate_type_fields(self):
        if self.parse_error is not None:
            return self

        if self.type in (AddressType.NETWORK, AddressType.HOST):
            if not self.subnet:
                raise ValueError(f"Address {self.name} of type {self.type} must have 'subnet' defined.")
        elif self.type == AddressType.RANGE:
            if not self.ip_range_start or not self.ip_range_end:
                raise ValueError(f"Address {self.name} of type RANGE must have 'ip_range_start' and 'ip_range_end'.")
        elif self.type in (AddressType.FQDN, AddressType.WILDCARD_FQDN):
            if not self.fqdn:
                raise ValueError(f"Address {self.name} of type {self.type} must have 'fqdn' defined.")
        elif self.type == AddressType.MAC:
            if not self.mac and not self.mac_entries:
                raise ValueError(f"Address {self.name} of type MAC must have 'mac' or 'mac_entries' defined.")
        elif self.type == AddressType.GEO:
            if not self.geo_code:
                raise ValueError(f"Address {self.name} of type GEO must have 'geo_code' defined.")
        elif self.type == AddressType.WILDCARD_MASK:
            if not self.wildcard_mask:
                raise ValueError(f"Address {self.name} of type WILDCARD_MASK must have 'wildcard_mask' defined.")
        elif self.type == AddressType.DYNAMIC:
            if not self.dynamic_filter and not any((
                self.source_sw_version,
                self.source_tag_detection_level,
                self.source_tenant,
                self.source_sdn,
                self.source_organization,
                self.source_os,
                self.source_policy_group,
            )):
                raise ValueError(f"Address {self.name} of type DYNAMIC must have a dynamic criterion defined.")
        elif self.type == AddressType.EMS_TAG:
            if not self.tag_name:
                raise ValueError(f"Address {self.name} of type EMS_TAG must have 'tag_name' defined.")
        elif self.type == AddressType.SPECIAL:
            pass
        elif self.type == AddressType.STUB_UNSUPPORTED:
            pass
                
        return self


class IRHighAvailability(BaseModel):
    """Source-preserved cluster topology; target generation is not implied."""
    source_uuid: Optional[str] = None
    name: str
    mode: Optional[str] = None
    member_references: List[str] = Field(default_factory=list)
    virtual_ips: List[str] = Field(default_factory=list)
    member_interface_ips: Dict[str, List[str]] = Field(default_factory=dict)
    sync_interfaces: List[str] = Field(default_factory=list)
    cluster_uid: Optional[str] = None
    cluster_interfaces: List[Dict[str, Any]] = Field(default_factory=list)
    sync_network: Optional[Any] = None
    topology: Dict[str, Any] = Field(default_factory=dict)
    ha_settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True


class IRCheckpointManagementAccess(BaseModel):
    name: str
    service: Optional[str] = None
    enabled: Optional[bool] = None
    port: Optional[int] = None
    interface: Optional[str] = None
    permitted_clients: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    authorization: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRCheckpointPerformanceSettings(BaseModel):
    name: str
    feature: str
    enabled: Optional[bool] = None
    instance_count: Optional[int] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRAddressGroupTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAddressGroup(BaseModel):
    name: str
    source_context: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    is_dynamic: bool = False
    dynamic_filter: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    # Source metadata used for partially normalized dynamic/EMS objects.
    source_uuid: Optional[str] = None
    associated_interface: Optional[str] = None
    allow_routing: Optional[bool] = None
    source_color: Optional[int] = None
    source_category: Optional[str] = None
    source_section: Optional[str] = None
    address_family: Optional[str] = None
    source_group_type: Optional[str] = None
    source_exclude_setting: Optional[str] = None
    source_fabric_object_setting: Optional[str] = None
    exclusion_enabled: bool = False
    exclude_members: List[str] = Field(default_factory=list)
    source_tagging_entries: List[IRAddressGroupTaggingEntry] = Field(default_factory=list)
    source_sub_type: Optional[str] = None
    source_obj_tag: Optional[str] = None
    source_tag_type: Optional[str] = None
    source_obj_type: Optional[str] = None
    source_dirty: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None

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
    schedule_type: str = "recurring"
    source_color: Optional[int] = None
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


class IRProxyAddress(BaseModel):
    name: str
    source_context: Optional[str] = None
    source_uuid: Optional[str] = None
    proxy_address_type: Optional[str] = None
    host: Optional[str] = None
    host_regex: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRWebProxySettings(BaseModel):
    proxy_fqdn: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRSecurityProfileGroup(BaseModel):
    name: str
    source_context: Optional[str] = None
    antivirus: Optional[str] = None
    vulnerability: Optional[str] = None
    anti_spyware: Optional[str] = None
    url_filtering: Optional[str] = None
    file_blocking: Optional[str] = None
    wildfire: Optional[str] = None
    ssl_decryption: Optional[str] = None
    description: Optional[str] = None
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_profile_references: Dict[str, str] = Field(default_factory=dict)
    support_level: str = "TYPED_EXTRACT_ONLY"
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRApplication(BaseModel):
    name: str
    source_uuid: Optional[str] = None
    source_context: Optional[str] = None
    category: Optional[str] = None
    urls: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    risk: Optional[Any] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRApplicationGroup(IRApplication):
    members: List[str] = Field(default_factory=list)


class IRApplicationCategory(IRApplication):
    members: List[str] = Field(default_factory=list)


class IRHTTPSInspectionRule(BaseModel):
    name: str
    source_uuid: Optional[str] = None
    rule_number: Optional[int] = None
    source_context: Optional[str] = None
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    action: Optional[str] = None
    certificate: Optional[str] = None
    bypass: Optional[bool] = None
    comments: Optional[str] = None
    enabled: Optional[bool] = None
    install_on: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSecurityProfileRule(BaseModel):
    name: Optional[str] = None
    applications: List[str] = Field(default_factory=list)
    file_types: List[str] = Field(default_factory=list)
    direction: Optional[str] = None
    action: Optional[str] = None
    vendor_ids: List[str] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)
    threat_name: Optional[str] = None
    host: Optional[str] = None
    category: Optional[str] = None
    packet_capture: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSecurityProfileCredentialEnforcement(BaseModel):
    mode: Optional[str] = None
    log_severity: Optional[str] = None
    block_categories: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSecurityProfileDefinition(BaseModel):
    name: str
    source_context: Optional[str] = None
    family: str
    source_family: str
    description: Optional[str] = None
    rules: List[IRSecurityProfileRule] = Field(default_factory=list)
    allow_categories: List[str] = Field(default_factory=list)
    alert_categories: List[str] = Field(default_factory=list)
    block_categories: List[str] = Field(default_factory=list)
    continue_categories: List[str] = Field(default_factory=list)
    override_categories: List[str] = Field(default_factory=list)
    credential_enforcement: Optional[IRSecurityProfileCredentialEnforcement] = None
    log_http_hdr_xff: Optional[bool] = None
    log_http_hdr_user_agent: Optional[bool] = None
    support_level: str = "TYPED_EXTRACT_ONLY"
    migration_status: str = "EXTRACT_ONLY"
    review_reasons: List[str] = Field(default_factory=list)
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRCheckpointIdentitySource(BaseModel):
    name: str
    source_context: Optional[str] = None
    source_type: str
    enabled: Optional[bool] = None
    settings: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRCheckpointAccessRole(BaseModel):
    name: str
    source_uuid: Optional[str] = None
    source_context: Optional[str] = None
    users: List[str] = Field(default_factory=list)
    user_groups: List[str] = Field(default_factory=list)
    machines: List[str] = Field(default_factory=list)
    networks: List[str] = Field(default_factory=list)
    remote_access_roles: List[str] = Field(default_factory=list)
    conditions: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRCheckpointThreatPreventionRule(BaseModel):
    name: Optional[str] = None
    source_uuid: Optional[str] = None
    rule_number: Optional[int] = None
    source_context: Optional[str] = None
    source_scope: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    profile: Optional[str] = None
    action: Optional[str] = None
    track: Any = None
    install_on: List[str] = Field(default_factory=list)
    comments: Optional[str] = None
    enabled: Optional[bool] = None
    exceptions: List[Any] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRCheckpointThreatPreventionProfile(BaseModel):
    name: str
    source_uuid: Optional[str] = None
    source_context: Optional[str] = None
    family: str
    activation: Dict[str, Any] = Field(default_factory=dict)
    actions: Dict[str, Any] = Field(default_factory=dict)
    confidence_severity_filters: Dict[str, Any] = Field(default_factory=dict)
    exceptions: List[Any] = Field(default_factory=list)
    update_options: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRCustomURLCategory(BaseModel):
    name: str
    source_context: Optional[str] = None
    category_type: Optional[str] = None
    entries: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    support_level: str = "TYPED_EXTRACT_ONLY"
    migration_status: str = "EXTRACT_ONLY"
    review_reasons: List[str] = Field(default_factory=list)
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRIPSSensorExemptIP(BaseModel):
    id: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None


class IRIPSSensorEntry(BaseModel):
    source_id: int
    source_signature_ids: List[int] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)
    location: Optional[str] = None
    protocols: List[str] = Field(default_factory=list)
    enabled: Optional[bool] = None
    action: Optional[str] = None
    rate_count: Optional[int] = None
    rate_duration: Optional[int] = None
    quarantine: Optional[str] = None
    quarantine_expiry: Optional[str] = None
    application: List[str] = Field(default_factory=list)
    cve: List[str] = Field(default_factory=list)
    default_action: Optional[str] = None
    default_status: Optional[str] = None
    log: Optional[str] = None
    log_packet: Optional[str] = None
    log_attack_context: Optional[str] = None
    os: List[str] = Field(default_factory=list)
    rate_mode: Optional[str] = None
    rate_track: Optional[str] = None
    vuln_type: List[int] = Field(default_factory=list)
    quarantine_log: Optional[str] = None
    exempt_ips: List[IRIPSSensorExemptIP] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRIPSSensor(BaseModel):
    name: str
    source_context: Optional[str] = None
    description: Optional[str] = None
    block_malicious_url: Optional[bool] = None
    scan_botnet_connections: Optional[str] = None
    extended_log: Optional[str] = None
    replacemsg_group: Optional[str] = None
    entries: List[IRIPSSensorEntry] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRCheckpointPolicyPackage(BaseModel):
    uid: Optional[str] = None
    name: str
    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
    access_layer_uids: List[str] = Field(default_factory=list)
    access_layer_names: List[str] = Field(default_factory=list)
    nat_policy_uid: Optional[str] = None
    nat_policy_name: Optional[str] = None
    threat_prevention_policy_uid: Optional[str] = None
    threat_prevention_policy_name: Optional[str] = None
    installation_targets: List[str] = Field(default_factory=list)
    global_assignment: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRCheckpointAccessLayer(BaseModel):
    uid: Optional[str] = None
    name: str
    package_uid: Optional[str] = None
    package_name: Optional[str] = None
    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
    parent_layer_uid: Optional[str] = None
    parent_layer_name: Optional[str] = None
    parent_rule_uid: Optional[str] = None
    parent_rule_number: Optional[int] = None
    inline: bool = False
    rule_uids: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRCheckpointDomain(BaseModel):
    uid: Optional[str] = None
    name: str
    domain_type: Optional[str] = None
    management_server: Optional[str] = None
    context: Optional[str] = None
    policy_package_uids: List[str] = Field(default_factory=list)
    policy_package_names: List[str] = Field(default_factory=list)
    global_object: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRPolicy(BaseModel):
    # Portable policy intent.  Target generators may consume these fields
    # only when the source-policy audit below confirms semantic safety.
    name: str
    source_context: Optional[str] = None
    policy_package_uid: Optional[str] = None
    policy_package_name: Optional[str] = None
    access_layer_uid: Optional[str] = None
    access_layer_name: Optional[str] = None
    access_layer_inline: bool = False
    access_layer_parent_uid: Optional[str] = None
    access_layer_parent_rule_uid: Optional[str] = None
    from_zone: List[str] = Field(default_factory=list)
    to_zone: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    action: Optional[PolicyAction] = None
    # Source-policy preservation and audit fields.  These retain source
    # syntax/semantics that are not assumed to be portable merely because a
    # corresponding typed field exists in a source parser model.
    source_rule_id: Optional[str] = None
    source_uuid: Optional[str] = None
    source_from_interfaces: List[str] = Field(default_factory=list)
    source_to_interfaces: List[str] = Field(default_factory=list)
    source_address_references: List[str] = Field(default_factory=list)
    destination_address_references: List[str] = Field(default_factory=list)
    source_ipv6_address_references: List[str] = Field(default_factory=list)
    destination_ipv6_address_references: List[str] = Field(default_factory=list)
    source_address_negate_setting: Optional[str] = None
    destination_address_negate_setting: Optional[str] = None
    source_ipv6_address_negate_setting: Optional[str] = None
    destination_ipv6_address_negate_setting: Optional[str] = None
    source_service_references: List[str] = Field(default_factory=list)
    source_service_negate_setting: Optional[str] = None
    source_action: Optional[str] = None
    source_schedule: Optional[str] = None
    source_user_groups: List[str] = Field(default_factory=list)
    source_users: List[str] = Field(default_factory=list)
    unresolved_user_groups: List[str] = Field(default_factory=list)
    unresolved_users: List[str] = Field(default_factory=list)
    identity_dependency_review: bool = False
    source_log_setting: Optional[str] = None
    source_log_setting_resolved: Optional[bool] = None
    resolved_source_log_setting: Optional[str] = None
    source_log_start_setting: Optional[str] = None
    source_utm_status: Optional[str] = None
    source_inspection_mode: Optional[str] = None
    source_timeout_send_rst: Optional[str] = None
    source_auto_asic_offload: Optional[str] = None
    source_np_acceleration: Optional[str] = None
    source_port_preserve: Optional[str] = None
    source_effective_utm_status: Optional[str] = None
    source_effective_inspection_mode: Optional[str] = None
    source_effective_ztna_status: Optional[str] = None
    source_effective_timeout_send_rst: Optional[str] = None
    source_effective_auto_asic_offload: Optional[str] = None
    source_effective_np_acceleration: Optional[str] = None
    source_effective_port_preserve: Optional[str] = None
    source_profile_type: Optional[str] = None
    source_profile_group: Optional[str] = None
    source_profile_protocol_options: Optional[str] = None
    unresolved_security_profiles: List[str] = Field(default_factory=list)
    source_security_profile_references: Dict[str, str] = Field(default_factory=dict)
    security_profile_reference_statuses: Dict[str, str] = Field(default_factory=dict)
    unresolved_security_profile_references: Dict[str, str] = Field(default_factory=dict)
    security_profile_semantics_review: bool = False
    source_internet_service_status: Optional[str] = None
    source_internet_service_settings: Dict[str, Any] = Field(default_factory=dict)
    source_vpn_tunnel: Optional[str] = None
    source_identity_based_route: Optional[str] = None
    source_ztna_status: Optional[str] = None
    source_ztna_ems_tags: List[str] = Field(default_factory=list)
    source_ztna_device_ownership: Optional[str] = None
    source_ztna_ems_tags_secondary: List[str] = Field(default_factory=list)
    source_ztna_geo_tags: List[str] = Field(default_factory=list)
    source_ztna_policy_redirect: Optional[str] = None
    source_ztna_tags_match_logic: Optional[str] = None
    source_extra_settings: Dict[str, Any] = Field(default_factory=dict)
    nat_enabled: Optional[bool] = None
    nat_pool_enabled: Optional[bool] = None
    nat_pool_names: List[str] = Field(default_factory=list)
    nat_pool_names6: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    review_reasons: List[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    description: Optional[str] = None
    schedule: Optional[str] = None
    schedules: List[str] = Field(default_factory=list)
    log_start: Optional[bool] = None
    log_end: Optional[bool] = None
    disabled: Optional[bool] = None
    # Advanced / UTM threat profiles
    security_profile_group: Optional[str] = None
    antivirus: Optional[str] = None
    ips_sensor: Optional[str] = None
    webfilter: Optional[str] = None
    application_list: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    applications: List[str] = Field(default_factory=list)
    internet_service: List[str] = Field(default_factory=list)

    @property
    def safe_for_target_generation(self) -> bool:
        return (
            self.migration_status == "NORMALIZED"
            and not self.requires_manual_review
            and not self.review_reasons
            and bool(self.source)
            and bool(self.destination)
            and bool(self.service)
        )

class IRIPPool(BaseModel):
    name: str
    source_context: Optional[str] = None
    address_family: str = "ipv4"

    pool_type: Optional[str] = None

    start_ip: Optional[str] = None
    end_ip: Optional[str] = None

    source_start_ip: Optional[str] = None
    source_end_ip: Optional[str] = None
    source_prefix6: Optional[str] = None

    start_port: Optional[int] = None
    end_port: Optional[int] = None

    associated_interface: Optional[str] = None

    arp_reply: Optional[bool] = None
    arp_interface: Optional[str] = None

    permit_any_host: Optional[bool] = None
    excluded_ips: List[str] = Field(default_factory=list)

    block_size: Optional[int] = None
    blocks_per_user: Optional[int] = None
    pba_timeout: Optional[int] = None
    pba_interim_log: Optional[int] = None
    ports_per_user: Optional[int] = None
    privileged_port_use_pba: Optional[bool] = None

    nat64: Optional[bool] = None
    add_nat64_route: Optional[bool] = None
    client_prefix_length: Optional[int] = None
    include_subnet_broadcast: Optional[bool] = None

    tcp_session_quota: Optional[int] = None
    udp_session_quota: Optional[int] = None
    icmp_session_quota: Optional[int] = None

    cgn_block_size: Optional[int] = None
    cgn_client_start_ip: Optional[str] = None
    cgn_client_end_ip: Optional[str] = None
    cgn_client_ipv6_shift: Optional[int] = None
    cgn_fixed_allocation: Optional[bool] = None
    cgn_overload: Optional[bool] = None
    cgn_port_start: Optional[int] = None
    cgn_port_end: Optional[int] = None
    cgn_spa: Optional[bool] = None

    utilization_alarm_clear: Optional[int] = None
    utilization_alarm_raise: Optional[int] = None

    nat46: Optional[bool] = None
    add_nat46_route: Optional[bool] = None

    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None

    description: Optional[str] = None


class IRVirtualIPRealServer(BaseModel):
    id: Optional[int] = None
    address_type: str = "ip"
    ip_address: Optional[str] = None
    address_reference: Optional[str] = None
    port: Optional[int] = None
    status: Optional[str] = None
    weight: Optional[int] = None
    holddown_interval: Optional[int] = None
    healthcheck: Optional[str] = None
    http_host: Optional[str] = None
    translate_host: Optional[str] = None
    max_connections: Optional[int] = None
    monitors: List[str] = Field(default_factory=list)
    client_ip: Optional[str] = None
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @property
    def address(self) -> Optional[str]:
        if self.address_type == "address":
            return self.address_reference or self.ip_address
        return self.ip_address or self.address_reference


class IRVirtualIP(BaseModel):
    name: str
    source_context: Optional[str] = None
    address_family: str = "ipv4"

    source_id: Optional[int] = None
    source_uuid: Optional[str] = None
    vip_type: Optional[str] = None
    enabled: bool = True

    external_ip: Optional[str] = None
    external_addresses: List[str] = Field(default_factory=list)
    external_interface: Optional[str] = None

    mapped_ips: List[str] = Field(default_factory=list)
    mapped_address: Optional[str] = None

    port_forward: bool = False
    protocol: Optional[str] = None
    external_port: Optional[str] = None
    mapped_port: Optional[str] = None
    port_mapping_type: Optional[str] = None

    arp_reply: Optional[bool] = None
    gratuitous_arp_interval: Optional[int] = None
    nat_source_vip: Optional[bool] = None
    nat44: Optional[bool] = None
    nat46: Optional[bool] = None
    nat64: Optional[bool] = None
    nat66: Optional[bool] = None
    add_nat46_route: Optional[bool] = None
    add_nat64_route: Optional[bool] = None
    ndp_reply: Optional[bool] = None
    ipv6_mapped_ip: Optional[str] = None
    ipv6_mapped_port: Optional[str] = None
    ipv4_mapped_ip: Optional[str] = None
    ipv4_mapped_port: Optional[str] = None
    embedded_ipv4_address: Optional[str] = None

    source_filters: List[str] = Field(default_factory=list)
    source_interface_filters: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)

    load_balance_method: Optional[str] = None
    server_type: Optional[str] = None
    persistence: Optional[str] = None
    http_redirect: Optional[bool] = None
    monitors: List[str] = Field(default_factory=list)
    max_embryonic_connections: Optional[int] = None
    real_servers: List[IRVirtualIPRealServer] = Field(default_factory=list)

    color: Optional[int] = None
    description: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None

class IRNATPortRange(BaseModel):
    start: int
    end: Optional[int] = None


class IRNATAddressRangeMapping(BaseModel):
    original_start: str
    original_end: str
    translated_start: str
    translated_end: Optional[str] = None


class IRNATRuntimeBehavior(BaseModel):
    fixed_port: Optional[bool] = None
    port_preserve: Optional[bool] = None
    pcp_inbound: Optional[bool] = None
    pcp_outbound: Optional[bool] = None
    pcp_pool_names: List[str] = Field(default_factory=list)
    permit_any_host: Optional[bool] = None
    permit_stun_host: Optional[bool] = None
    rtp_nat: Optional[bool] = None
    rtp_addresses: List[str] = Field(default_factory=list)
    nat_inbound: Optional[bool] = None
    nat_outbound: Optional[bool] = None
    nat_ip: Optional[str] = None


class IRNATRule(BaseModel):
    name: str
    type: NATType
    source_context: Optional[str] = None
    source_policy_reference: Optional[str] = None
    source_policy_uuid: Optional[str] = None
    source_policy_name: Optional[str] = None
    sequence: Optional[int] = None
    enabled: bool = True
    source_from_interfaces: List[str] = Field(default_factory=list)
    source_to_interfaces: List[str] = Field(default_factory=list)
    from_zone: List[str] = Field(default_factory=list)
    to_zone: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    internet_services: List[str] = Field(default_factory=list)
    nat_family: Optional[NATFamily] = None
    original_address_family: Optional[str] = None
    translated_address_family: Optional[str] = None
    protocol_number: Optional[int] = None
    protocol_name: Optional[str] = None
    original_source_ports: List[IRNATPortRange] = Field(default_factory=list)
    original_destination_ports: List[IRNATPortRange] = Field(default_factory=list)
    translated_source_ports: List[IRNATPortRange] = Field(default_factory=list)
    translated_destination_ports: List[IRNATPortRange] = Field(default_factory=list)
    source_port_behavior: Optional[NATSourcePortBehavior] = None
    address_range_mappings: List[IRNATAddressRangeMapping] = Field(default_factory=list)
    install_translation_route: Optional[bool] = None
    runtime_behavior: Optional[IRNATRuntimeBehavior] = None
    source_origin: Optional[str] = None
    traffic_type: str = "unicast"
    source_translation_mode: Optional[NATTranslationMode] = None
    destination_translation_mode: Optional[NATTranslationMode] = None
    source_pool_references: List[str] = Field(default_factory=list)
    source_pool_type: Optional[str] = None
    source_pool_excluded_ips: List[str] = Field(default_factory=list)
    source_pool_permit_any_host: Optional[bool] = None
    source_pool_original_start_ip: List[str] = Field(default_factory=list)
    source_pool_original_end_ip: List[str] = Field(default_factory=list)
    destination_pool_references: List[str] = Field(default_factory=list)
    translated_sources: List[str] = Field(default_factory=list)
    translated_destinations: List[str] = Field(default_factory=list)
    translated_services: List[str] = Field(default_factory=list)
    source_rule_id: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    destination_protocol: Optional[str] = None
    original_destination_port: Optional[str] = None
    source_vip_reference: Optional[str] = None
    source_vip_group_reference: Optional[str] = None
    source_vip_type: Optional[str] = None
    source_vip_enabled: Optional[bool] = None
    source_vip_nat_source_vip: Optional[bool] = None
    source_vip_filters: List[str] = Field(default_factory=list)
    source_vip_interface_filters: List[str] = Field(default_factory=list)
    source_vip_services: List[str] = Field(default_factory=list)
    source_vip_port_mapping_type: Optional[str] = None
    source_policy_fixed_port: Optional[str] = None
    source_policy_nat46: Optional[str] = None
    source_policy_nat64: Optional[str] = None
    source_policy_nat_inbound: Optional[str] = None
    source_policy_nat_outbound: Optional[str] = None
    source_policy_nat_ip: Optional[str] = None
    source_policy_match_vip: Optional[str] = None
    source_policy_match_vip_only: Optional[str] = None
    migration_status: str = "NORMALIZED"
    review_reasons: List[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    # Backward-compatible scalar fields. New code should use the list fields above.
    service: Optional[str] = None
    translated_source: Optional[str] = None
    translated_destination: Optional[str] = None
    translated_port: Optional[str] = None
    description: Optional[str] = None

    @property
    def safe_for_target_generation(self) -> bool:
        if self.migration_status != "NORMALIZED":
            return False
        if self.requires_manual_review or self.review_reasons:
            return False
        if not self.source_policy_reference:
            if not self.source or not self.destination or not self.services:
                return False
        if self.type == NATType.SOURCE:
            return bool(
                self.translated_sources
                or self.source_pool_references
                or (
                    self.source_translation_mode is not None
                    and self.source_translation_mode != NATTranslationMode.NONE
                )
            )
        if self.type == NATType.DESTINATION:
            return bool(
                self.translated_destinations
                or self.destination_pool_references
                or self.source_vip_reference
                or self.translated_destination
            )
        if self.type == NATType.TWICE:
            return bool((self.translated_sources or self.source_pool_references) and (self.translated_destinations or self.destination_pool_references))
        if self.type == NATType.ADDRESS_TRANSLATION:
            return bool(self.address_range_mappings)
        if self.type == NATType.CENTRAL:
            if (
                self.source_translation_mode is not None
                and self.source_translation_mode != NATTranslationMode.NONE
                and not self.translated_sources
            ):
                return False
            if (
                self.destination_translation_mode is not None
                and self.destination_translation_mode != NATTranslationMode.NONE
                and not self.translated_destinations
            ):
                return False
            return True
        return False

    @model_validator(mode="after")
    def normalize_compatibility_fields_and_validate_twice_nat(self):
        if not self.services and "services" not in self.model_fields_set and self.service:
            self.services = [self.service]
        elif self.services and self.service == "any":
            self.service = self.services[0]

        if not self.translated_sources and self.translated_source:
            self.translated_sources = [self.translated_source]
        elif self.translated_sources and self.translated_source is None:
            self.translated_source = self.translated_sources[0]

        if not self.translated_destinations and self.translated_destination:
            self.translated_destinations = [self.translated_destination]
        elif self.translated_destinations and self.translated_destination is None:
            self.translated_destination = self.translated_destinations[0]

        if self.type == NATType.TWICE:
            if not self.translated_sources and not self.translated_destinations:
                raise ValueError(f"NAT Rule {self.name} of type TWICE must have at least one translated field defined (source or destination).")
        return self

class IRVPNTunnel(BaseModel):
    name: str
    source_context: Optional[str] = None
    peer_address: Optional[str] = None
    local_interface: str
    ike_version: Optional[str] = None
    psk: Optional[str] = None
    has_psk: bool = False
    ike_crypto_profile: Optional[str] = None
    ipsec_crypto_profile: Optional[str] = None
    source_local_gateway: Optional[str] = None
    source_type: Optional[str] = None
    source_mode: Optional[str] = None
    source_peer_type: Optional[str] = None
    source_net_device: Optional[bool] = None
    source_proposals: List[str] = Field(default_factory=list)
    source_mode_config: Optional[bool] = None
    source_eap: Optional[bool] = None
    source_eap_identity: Optional[str] = None
    source_auth_user_group: Optional[str] = None
    unresolved_auth_user_groups: List[str] = Field(default_factory=list)
    source_client_ip_start: Optional[str] = None
    source_client_ip_end: Optional[str] = None
    source_dns_mode: Optional[str] = None
    source_split_include: List[str] = Field(default_factory=list)
    source_dpd_retry_interval: Optional[int] = None
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None


class IRVPNPhase2(BaseModel):
    name: str
    source_context: Optional[str] = None
    phase1_name: str
    proposals: List[str] = Field(default_factory=list)
    source_address_type: Optional[str] = None
    destination_address_type: Optional[str] = None
    source_names: List[str] = Field(default_factory=list)
    destination_names: List[str] = Field(default_factory=list)
    source_subnet: Optional[str] = None
    destination_subnet: Optional[str] = None
    auto_negotiate: Optional[bool] = None
    dh_groups: List[int] = Field(default_factory=list)
    keepalive: Optional[bool] = None
    description: Optional[str] = None
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRRoute(BaseModel):
    name: str
    source_context: Optional[str] = None
    address_family: str = "ipv4"
    destination: Optional[str] = None
    source_destination: Optional[str] = None
    source_destination_reference: Optional[str] = None
    source_prefix: Optional[str] = None
    source_preferred_source: Optional[str] = None
    source_route_id: Optional[int] = None
    interface: Optional[str] = None
    next_hop: Optional[str] = None
    administrative_distance: Optional[int] = None
    metric: Optional[int] = None
    priority: Optional[int] = None
    weight: Optional[int] = None
    blackhole: Optional[bool] = None
    enabled: Optional[bool] = None
    source_explicit_fields: List[str] = Field(default_factory=list)
    sdwan_zone: Optional[str] = None
    sdwan_zones: List[str] = Field(default_factory=list)
    dynamic_gateway: Optional[str] = None
    link_monitor_exempt: Optional[str] = None
    bfd: Optional[str] = None
    vrf: Optional[int] = None
    route_tag: Optional[int] = None
    internet_service: Optional[int] = None
    internet_service_custom: Optional[str] = None
    description: Optional[str] = None
    migration_status: str = "NORMALIZED"
    review_reasons: List[str] = Field(default_factory=list)
    parse_error: Optional[str] = None
    requires_manual_review: bool = False
    source_fabric_object: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @property
    def safe_for_target_generation(self) -> bool:
        return (
            self.migration_status == "NORMALIZED"
            and not self.requires_manual_review
            and not self.review_reasons
            and self.parse_error is None
            and self.destination is not None
            and self.source_destination_reference is None
        )

class IRAuditEntry(BaseModel):
    id: str
    category: str
    message: str
    confidence: MigrationConfidence
    original_config: Optional[str] = None

class IRInternetService(BaseModel):
    name: str
    source_id: Optional[int] = None
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


class IRZTNAProvider(BaseModel):
    name: str
    provider_type: Optional[str] = None
    enabled: bool = True

    source_vendor: Optional[str] = None
    source_id: Optional[str] = None
    source_serial: Optional[str] = None
    source_tenant_id: Optional[str] = None
    source_cloud_authentication: Optional[bool] = None

    verifying_ca: Optional[str] = None
    verified_cn: Optional[str] = None
    capabilities: List[str] = Field(default_factory=list)

    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    migration_instruction: Optional[str] = None


class IRSessionHelper(BaseModel):
    source_id: int
    name: str
    protocol_number: Optional[int] = None
    protocol_name: Optional[str] = None
    port: Optional[int] = None
    classification: str = "UNKNOWN"
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSessionTTLOverride(BaseModel):
    source_id: int
    protocol_number: Optional[int] = None
    protocol_name: Optional[str] = None
    start_port: Optional[int] = None
    end_port: Optional[int] = None
    timeout_seconds: Optional[int] = None
    timeout_never: bool = False
    refresh_direction: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSessionTTLSettings(BaseModel):
    default_timeout_seconds: Optional[int] = None
    default_never: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRExecutionContext(BaseModel):
    vdom: str = "root"
    scope: str = "vdom"
    central_nat: Optional[str] = None
    ngfw_mode: Optional[str] = None
    opmode: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRScheduleGroup(BaseModel):
    name: str
    source_context: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    unresolved_members: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRFortiGateSourceRule(BaseModel):
    """Sanitized FortiGate-only rule family; never portable target intent."""

    family: str
    source_id: Optional[str] = None
    name: Optional[str] = None
    source_order: int = 0
    source_context: Optional[str] = None
    enabled: Optional[bool] = None
    effective_action: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)


class IRFortiGatePolicyRoute(IRFortiGateSourceRule):
    """Typed FortiGate PBR semantics retained outside portable route intent."""

    address_family: str = "ipv4"

    source_action: Optional[str] = None
    source_status: Optional[str] = None
    comments: Optional[str] = None

    input_devices: List[str] = Field(default_factory=list)
    input_device_negate: Optional[str] = None

    source_networks: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    source_negate: Optional[str] = None

    destination_networks: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    destination_negate: Optional[str] = None

    protocol: Optional[int] = None

    destination_port_start: Optional[int] = None
    destination_port_end: Optional[int] = None
    source_port_start: Optional[int] = None
    source_port_end: Optional[int] = None

    gateway: Optional[str] = None
    output_device: Optional[str] = None

    internet_service_custom: List[str] = Field(default_factory=list)
    internet_service_ids: List[int] = Field(default_factory=list)

    tos: Optional[str] = None
    tos_mask: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _infer_legacy_address_family(cls, value):
        if isinstance(value, dict) and "address_family" not in value:
            value = dict(value)
            value["address_family"] = (
                "ipv6" if value.get("family") == "policy-route-ipv6" else "ipv4"
            )
        return value

class IRDHCPIPRange(BaseModel):
    source_id: int
    source_context: Optional[str] = None
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    lease_time_seconds: Optional[int] = None
    uci_match: Optional[str] = None
    uci_strings: List[str] = Field(default_factory=list)
    vci_match: Optional[str] = None
    vci_strings: List[str] = Field(default_factory=list)
    source_explicit_fields: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRVPNCommunity(BaseModel):
    name: str
    uid: Optional[str] = None
    source_context: Optional[str] = None
    community_type: Optional[str] = None
    member_gateways: List[str] = Field(default_factory=list)
    center_gateways: List[str] = Field(default_factory=list)
    satellite_gateways: List[str] = Field(default_factory=list)
    tunnel_sharing: Optional[str] = None
    ike_version: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    integrity_hash: Optional[str] = None
    dh_group: Optional[str] = None
    lifetime: Optional[str] = None
    pfs: Optional[str] = None
    nat_traversal: Optional[str] = None
    shared_secret_reference: Optional[str] = None
    certificate_reference: Optional[str] = None
    office_mode: Optional[Any] = None
    authentication_methods: List[str] = Field(default_factory=list)
    allowed_users: List[str] = Field(default_factory=list)
    allowed_groups: List[str] = Field(default_factory=list)
    client_settings: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRVPNGateway(BaseModel):
    name: str
    uid: Optional[str] = None
    source_context: Optional[str] = None
    main_ip: Optional[str] = None
    vpn_enabled: Optional[bool] = None
    topology: Optional[str] = None
    encryption_domain: Optional[Any] = None
    certificate_references: List[str] = Field(default_factory=list)
    community_membership: List[str] = Field(default_factory=list)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDHCPExcludeRange(BaseModel):
    source_id: int
    source_context: Optional[str] = None
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    lease_time_seconds: Optional[int] = None
    uci_match: Optional[str] = None
    uci_strings: List[str] = Field(default_factory=list)
    vci_match: Optional[str] = None
    vci_strings: List[str] = Field(default_factory=list)
    source_explicit_fields: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDHCPReservation(BaseModel):
    source_id: int
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    source_context: Optional[str] = None
    action: Optional[str] = None
    reservation_type: Optional[str] = None
    circuit_id: Optional[str] = None
    circuit_id_type: Optional[str] = None
    remote_id: Optional[str] = None
    remote_id_type: Optional[str] = None
    description: Optional[str] = None
    source_explicit_fields: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDHCPOption(BaseModel):
    source_id: int
    code: Optional[int] = None
    option_type: Optional[str] = None
    value: Optional[str] = None
    ip: Optional[str] = None
    source_context: Optional[str] = None
    ips: List[str] = Field(default_factory=list)
    uci_match: Optional[str] = None
    uci_strings: List[str] = Field(default_factory=list)
    vci_match: Optional[str] = None
    vci_strings: List[str] = Field(default_factory=list)
    source_explicit_fields: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDHCPServer(BaseModel):
    source_id: int
    enabled: bool = True
    source_context: Optional[str] = None

    interface: Optional[str] = None
    default_gateway: Optional[str] = None
    netmask: Optional[str] = None
    lease_time_seconds: Optional[int] = None

    auto_configuration: Optional[str] = None
    auto_managed_status: Optional[str] = None
    conflicted_ip_timeout: Optional[int] = None

    ddns_auth: Optional[str] = None
    has_ddns_key: bool = False
    ddns_key_format: Optional[str] = None
    ddns_key_name: Optional[str] = None
    ddns_server_ip: Optional[str] = None
    ddns_ttl: Optional[int] = None
    ddns_update: Optional[str] = None
    ddns_update_override: Optional[str] = None
    ddns_zone: Optional[str] = None

    dhcp_settings_from_fortiipam: Optional[str] = None
    domain: Optional[str] = None
    filename: Optional[str] = None
    forticlient_on_net_status: Optional[str] = None
    ip_mode: Optional[str] = None
    ipsec_lease_hold: Optional[int] = None
    mac_acl_default_action: Optional[str] = None
    next_server: Optional[str] = None
    ntp_servers: List[str] = Field(default_factory=list)
    ntp_service: Optional[str] = None
    relay_agent: Optional[str] = None
    server_type: Optional[str] = None
    shared_subnet: Optional[str] = None
    tftp_servers: List[str] = Field(default_factory=list)
    timezone: Optional[str] = None
    vci_match: Optional[str] = None
    vci_strings: List[str] = Field(default_factory=list)
    wifi_ac_service: Optional[str] = None
    wifi_ac_servers: List[str] = Field(default_factory=list)
    wins_servers: List[str] = Field(default_factory=list)

    dns_service: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    timezone_option: Optional[str] = None

    ip_ranges: List[IRDHCPIPRange] = Field(default_factory=list)
    exclude_ranges: List[IRDHCPExcludeRange] = Field(default_factory=list)
    reservations: List[IRDHCPReservation] = Field(default_factory=list)
    options: List[IRDHCPOption] = Field(default_factory=list)

    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_explicit_fields: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)



class IRCertificate(BaseModel):
    name: str
    certificate_type: str

    source_range: Optional[str] = None
    source_origin: Optional[str] = None
    public_certificate_pem: Optional[str] = None

    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    public_key_algorithm: Optional[str] = None
    public_key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None
    sha256_fingerprint: Optional[str] = None
    ca_reference: Optional[str] = None
    usage: Optional[str] = None
    is_self_signed: Optional[bool] = None
    is_ca: Optional[bool] = None

    has_certificate: bool = False
    has_private_key: bool = False
    private_key_encrypted: bool = False
    has_password: bool = False

    description: Optional[str] = None
    source_last_updated: Optional[datetime] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    parse_error: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSHKey(BaseModel):
    name: str
    key_type: str
    public_key: Optional[str] = None
    source_origin: Optional[str] = None
    has_private_key: bool = False
    has_password: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSystemSettings(BaseModel):
    hostname: Optional[str] = None
    timezone: Optional[str] = None
    admin_https_port: Optional[int] = None
    management_plane: Optional["IRManagementPlaneSettings"] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRManagementPlaneSettings(BaseModel):
    ipv4_address: Optional[str] = None
    netmask: Optional[str] = None
    default_gateway: Optional[str] = None
    address_type: Optional[str] = None
    ipv6_address: Optional[str] = None
    ipv6_default_gateway: Optional[str] = None
    ipv6_enabled: Optional[bool] = None
    ipv6_address_type: Optional[str] = None
    ipv6_gateway_type: Optional[str] = None
    services: Dict[str, bool] = Field(default_factory=dict)
    permitted_ips: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRNTPServer(BaseModel):
    role: str
    address: Optional[str] = None
    authentication_type: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRNTPSettings(BaseModel):
    servers: List[IRNTPServer] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True


class IRManagementServiceRoute(BaseModel):
    name: Optional[str] = None
    source_context: Optional[str] = None
    source_address: Optional[str] = None
    source_interface: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDNSSettings(BaseModel):
    primary: Optional[str] = None
    secondary: Optional[str] = None
    tertiary: Optional[str] = None
    domain_name: Optional[str] = None
    search_suffixes: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRVirtualIPGroup(BaseModel):
    name: str
    source_context: Optional[str] = None
    address_family: str = "ipv4"
    source_uuid: Optional[str] = None
    interface: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    source_color: Optional[int] = None
    description: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    audit_note: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSDWANZone(BaseModel):
    name: str
    source_context: str = "root"
    source_advpn_health_check: Optional[str] = None
    source_advpn_select: Optional[str] = None
    source_minimum_sla_meet_members: Optional[int] = None
    source_service_sla_tie_break: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSDWANMember(BaseModel):
    source_id: int
    source_context: str = "root"
    interface: str
    zone: str
    gateway: Optional[str] = None
    source: Optional[str] = None
    gateway6: Optional[str] = None
    source6: Optional[str] = None
    preferred_source: Optional[str] = None
    transport_group: Optional[int] = None
    cost: Optional[int] = None
    weight: Optional[int] = None
    priority: Optional[int] = None
    priority6: Optional[int] = None
    spillover_threshold: Optional[int] = None
    ingress_spillover_threshold: Optional[int] = None
    volume_ratio: Optional[int] = None
    status: Optional[str] = None
    description: Optional[str] = None
    source_explicit_fields: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)


class IRSDWANSLA(BaseModel):
    source_id: int
    source_context: str = "root"
    jitter_threshold: Optional[int] = None
    latency_threshold: Optional[int] = None
    link_cost_factors: List[str] = Field(default_factory=list)
    mos_threshold: Optional[str] = None
    packetloss_threshold: Optional[int] = None
    priority_in_sla: Optional[int] = None
    priority_out_sla: Optional[int] = None
    source_explicit_fields: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)


class IRSDWANHealthCheck(BaseModel):
    name: str
    source_context: str = "root"
    server: Optional[str] = None
    servers: List[str] = Field(default_factory=list)
    member_ids: List[int] = Field(default_factory=list)
    protocol: Optional[str] = None
    port: Optional[int] = None
    interval: Optional[int] = None
    probe_timeout: Optional[int] = None
    failtime: Optional[int] = None
    recoverytime: Optional[int] = None
    update_static_route: Optional[str] = None
    vrf: Optional[int] = None
    source: Optional[str] = None
    address_mode: Optional[str] = None
    class_id: Optional[int] = None
    detect_mode: Optional[str] = None
    diffserv_code: Optional[str] = None
    dns_match_ip: Optional[str] = None
    dns_request_domain: Optional[str] = None
    embed_measured_health: Optional[str] = None
    ftp_file: Optional[str] = None
    ftp_mode: Optional[str] = None
    ha_priority: Optional[int] = None
    http_agent: Optional[str] = None
    http_get: Optional[str] = None
    http_match: Optional[str] = None
    mos_codec: Optional[str] = None
    packet_size: Optional[int] = None
    has_password: bool = False
    password_format: Optional[str] = None
    probe_count: Optional[int] = None
    probe_packets: Optional[str] = None
    quality_measured_method: Optional[str] = None
    security_mode: Optional[str] = None
    sla_fail_log_period: Optional[int] = None
    sla_id_redistribute: Optional[int] = None
    sla_pass_log_period: Optional[int] = None
    source6: Optional[str] = None
    system_dns: Optional[str] = None
    threshold_alert_jitter: Optional[int] = None
    threshold_alert_latency: Optional[int] = None
    threshold_alert_packetloss: Optional[int] = None
    threshold_warning_jitter: Optional[int] = None
    threshold_warning_latency: Optional[int] = None
    threshold_warning_packetloss: Optional[int] = None
    update_cascade_interface: Optional[str] = None
    user: Optional[str] = None
    sla: List[IRSDWANSLA] = Field(default_factory=list)
    source_explicit_fields: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)


class IRSDWANRuleSLA(BaseModel):
    name: str
    source_context: str = "root"
    source_id: Optional[int] = None
    source_explicit_fields: List[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSDWANRule(BaseModel):
    source_id: int
    source_context: str = "root"
    name: Optional[str] = None
    mode: Optional[str] = None
    status: Optional[str] = None
    address_mode: Optional[str] = None
    agent_exclusive: Optional[str] = None
    bandwidth_weight: Optional[int] = None
    default_service: Optional[str] = None
    dscp_forward: Optional[str] = None
    dscp_forward_tag: Optional[str] = None
    dscp_reverse: Optional[str] = None
    dscp_reverse_tag: Optional[str] = None
    source_addresses: List[str] = Field(default_factory=list)
    source_addresses6: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    destination_addresses6: List[str] = Field(default_factory=list)
    destination_negate: Optional[str] = None
    destination_port_start: Optional[int] = None
    destination_port_end: Optional[int] = None
    source_port_start: Optional[int] = None
    source_port_end: Optional[int] = None
    gateway: Optional[str] = None
    user_groups: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    hash_mode: Optional[str] = None
    hold_down_time: Optional[int] = None
    input_devices: List[str] = Field(default_factory=list)
    input_device_negate: Optional[str] = None
    input_zones: List[str] = Field(default_factory=list)
    health_check: Optional[str] = None
    health_checks: List[str] = Field(default_factory=list)
    priority_member_ids: List[int] = Field(default_factory=list)
    priority_zones: List[str] = Field(default_factory=list)
    internet_service: Optional[str] = None
    internet_service_names: List[str] = Field(default_factory=list)
    internet_service_app_ctrl: List[int] = Field(default_factory=list)
    internet_service_app_ctrl_categories: List[int] = Field(default_factory=list)
    internet_service_app_ctrl_groups: List[str] = Field(default_factory=list)
    internet_service_custom: List[str] = Field(default_factory=list)
    internet_service_custom_groups: List[str] = Field(default_factory=list)
    internet_service_groups: List[str] = Field(default_factory=list)
    jitter_weight: Optional[int] = None
    latency_weight: Optional[int] = None
    packet_loss_weight: Optional[int] = None
    link_cost_factor: Optional[str] = None
    link_cost_threshold: Optional[int] = None
    load_balance: Optional[str] = None
    minimum_sla_meet_members: Optional[int] = None
    passive_measurement: Optional[str] = None
    protocol: Optional[int] = None
    quality_link: Optional[int] = None
    role: Optional[str] = None
    shortcut: Optional[str] = None
    shortcut_priority: Optional[str] = None
    sla_compare_method: Optional[str] = None
    tie_break: Optional[str] = None
    use_shortcut_sla: Optional[str] = None
    sla_stickiness: Optional[str] = None
    source_negate: Optional[str] = None
    standalone_action: Optional[str] = None
    tos: Optional[str] = None
    tos_mask: Optional[str] = None
    zone_mode: Optional[str] = None
    sla: List[IRSDWANRuleSLA] = Field(default_factory=list)
    source_explicit_fields: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)


class IRSDWANDuplicationRule(BaseModel):
    source_id: int
    source_context: str = "root"
    service_id: Optional[int] = None
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    source_addresses6: List[str] = Field(default_factory=list)
    destination_addresses6: List[str] = Field(default_factory=list)
    source_interfaces: List[str] = Field(default_factory=list)
    destination_interfaces: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    packet_duplication: Optional[str] = None
    sla_match_service: Optional[str] = None
    packet_de_duplication: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSDWANNeighbor(BaseModel):
    name: str
    source_context: str = "root"
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSDWAN(BaseModel):
    source_context: str = "root"
    status: str = "disable"
    load_balance_mode: Optional[str] = None
    zones: List[IRSDWANZone] = Field(default_factory=list)
    members: List[IRSDWANMember] = Field(default_factory=list)
    health_checks: List[IRSDWANHealthCheck] = Field(default_factory=list)
    rules: List[IRSDWANRule] = Field(default_factory=list)
    duplication_rules: List[IRSDWANDuplicationRule] = Field(default_factory=list)
    neighbors: List[IRSDWANNeighbor] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRIdentityServerEndpoint(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    port: Optional[int] = None
    has_secret: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)


class IRUserLDAP(BaseModel):
    name: str
    server: Optional[str] = None
    cnid: Optional[str] = None
    dn: Optional[str] = None
    source_type: Optional[str] = None
    username: Optional[str] = None
    has_password: bool = False
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None
    port: Optional[int] = None
    secure: Optional[str] = None
    ca_cert: Optional[str] = None
    server_identity_check: Optional[str] = None
    source_ip: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    group_filter: Optional[str] = None
    group_search_base: Optional[str] = None
    obtain_user_info: Optional[str] = None
    password_expiry_warning: Optional[str] = None
    password_renewal: Optional[str] = None
    account_key_cert_field: Optional[str] = None
    account_key_filter: Optional[str] = None
    account_key_processing: Optional[str] = None
    antiphish: Optional[str] = None
    client_cert: Optional[str] = None
    client_cert_auth: Optional[str] = None
    group_member_check: Optional[str] = None
    group_object_filter: Optional[str] = None
    member_attr: Optional[str] = None
    password_attr: Optional[str] = None
    search_type: List[str] = Field(default_factory=list)
    source_port: Optional[int] = None
    ssl_min_proto_version: Optional[str] = None
    ca_certificate_resolved: Optional[bool] = None
    client_certificate_resolved: Optional[bool] = None
    unresolved_certificate_references: List[str] = Field(default_factory=list)
    server_entries: List[IRIdentityServerEndpoint] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRUserRADIUSAccountingServer(BaseModel):
    id: str
    status: Optional[str] = None
    server: Optional[str] = None
    port: Optional[int] = None
    source_ip: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    has_secret: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRUserRADIUS(BaseModel):
    name: str
    source_context: str = "root"
    server: Optional[str] = None
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None
    auth_type: Optional[str] = None
    port: Optional[int] = None
    acct_interim_interval: Optional[int] = None
    nas_ip: Optional[str] = None
    source_ip: Optional[str] = None
    has_secret: bool = False
    accounting_servers: List[IRUserRADIUSAccountingServer] = Field(default_factory=list)
    server_entries: List[IRIdentityServerEndpoint] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRFSSOEndpoint(BaseModel):
    index: int
    server: Optional[str] = None
    port: Optional[int] = None
    has_password: bool = False


class IRFSSOProvider(BaseModel):
    name: str
    endpoints: List[IRFSSOEndpoint] = Field(default_factory=list)
    server: Optional[str] = None
    has_password: bool = False
    server2: Optional[str] = None
    server3: Optional[str] = None
    server4: Optional[str] = None
    server5: Optional[str] = None
    port: Optional[int] = None
    port2: Optional[int] = None
    port3: Optional[int] = None
    port4: Optional[int] = None
    port5: Optional[int] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    ldap_poll: Optional[str] = None
    ldap_poll_filter: Optional[str] = None
    ldap_poll_interval: Optional[int] = None
    group_poll_interval: Optional[int] = None
    ldap_server: Optional[str] = None
    logon_timeout: Optional[int] = None
    source_ip: Optional[str] = None
    source_ip6: Optional[str] = None
    ssl: Optional[str] = None
    ssl_server_host_ip_check: Optional[str] = None
    ssl_trusted_cert: Optional[str] = None
    sni: Optional[str] = None
    source_type: Optional[str] = None
    user_info_server: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRUserTACACS(BaseModel):
    name: str
    source_context: str = "root"
    server: Optional[str] = None
    secondary_server: Optional[str] = None
    tertiary_server: Optional[str] = None
    port: Optional[int] = None
    authentication_type: Optional[str] = None
    authorization: Optional[str] = None
    source_ip: Optional[str] = None
    interface_select_method: Optional[str] = None
    interface: Optional[str] = None
    status_ttl: Optional[int] = None
    has_secret: bool = False
    server_entries: List[IRIdentityServerEndpoint] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRFSSOADGroup(BaseModel):
    name: str
    provider_name: Optional[str] = None
    provider_resolved: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRUserSAML(BaseModel):
    name: str
    entity_id: Optional[str] = None
    single_sign_on_url: Optional[str] = None
    single_logout_url: Optional[str] = None
    idp_entity_id: Optional[str] = None
    idp_single_sign_on_url: Optional[str] = None
    idp_single_logout_url: Optional[str] = None
    idp_cert: Optional[str] = None
    idp_certificate_resolved: Optional[bool] = None
    cert_certificate_resolved: Optional[bool] = None
    unresolved_certificate_references: List[str] = Field(default_factory=list)
    user_name: Optional[str] = None
    group_name: Optional[str] = None
    digest_method: Optional[str] = None
    cert: Optional[str] = None
    clock_tolerance: Optional[int] = None
    adfs_claim: Optional[str] = None
    limit_relaystate: Optional[str] = None
    reauth: Optional[str] = None
    user_claim_type: Optional[str] = None
    group_claim_type: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRLocalUser(BaseModel):
    name: str
    id: Optional[int] = None
    status: Optional[str] = None
    source_type: Optional[str] = None
    has_password: bool = False
    source_passwd_time: Optional[str] = None
    two_factor: Optional[str] = None
    two_factor_authentication: Optional[str] = None
    two_factor_notification: Optional[str] = None
    fortitoken: Optional[str] = None
    email_to: Optional[str] = None
    sms_server: Optional[str] = None
    sms_custom_server: Optional[str] = None
    sms_phone: Optional[str] = None
    ldap_server: Optional[str] = None
    radius_server: Optional[str] = None
    auth_concurrent_override: Optional[str] = None
    auth_concurrent_value: Optional[int] = None
    authtimeout: Optional[int] = None
    passwd_policy: Optional[str] = None
    workstation: Optional[str] = None
    username_sensitivity: Optional[str] = None
    tacacs_server: Optional[str] = None
    ppk_identity: Optional[str] = None
    has_ppk_secret: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRUserGroupMatch(BaseModel):
    source_id: int
    server_name: Optional[str] = None
    group_name: Optional[str] = None


class IRUserGroupGuest(BaseModel):
    id: int
    name: Optional[str] = None
    user_id: Optional[str] = None
    company: Optional[str] = None
    email: Optional[str] = None
    expiration: Optional[str] = None
    mobile_phone: Optional[str] = None
    sponsor: Optional[str] = None
    has_password: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRIdentityDependency(BaseModel):
    reference: str
    dependency_type: str
    resolved: bool
    target_name: Optional[str] = None
    source_context: Optional[str] = None


class IRUserGroup(BaseModel):
    name: str
    group_type: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    matches: List[IRUserGroupMatch] = Field(default_factory=list)
    auth_concurrent_override: Optional[str] = None
    auth_concurrent_value: Optional[int] = None
    authtimeout: Optional[int] = None
    company: Optional[str] = None
    email: Optional[str] = None
    expire: Optional[int] = None
    expire_type: Optional[str] = None
    http_digest_realm: Optional[str] = None
    id: Optional[int] = None
    max_accounts: Optional[int] = None
    mobile_phone: Optional[str] = None
    multiple_guest_add: Optional[str] = None
    password: Optional[str] = None
    sms_custom_server: Optional[str] = None
    sms_server: Optional[str] = None
    sponsor: Optional[str] = None
    sso_attribute_value: Optional[str] = None
    user_id: Optional[str] = None
    user_name: Optional[str] = None
    guests: List[IRUserGroupGuest] = Field(default_factory=list)
    resolved_members: List[str] = Field(default_factory=list)
    unresolved_members: List[str] = Field(default_factory=list)
    member_dependencies: List[IRIdentityDependency] = Field(default_factory=list)
    unresolved_match_servers: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAdministrator(BaseModel):
    name: str
    access_profile: Optional[str] = None
    vdoms: List[str] = Field(default_factory=list)
    trusthost1: Optional[str] = None
    trusthost2: Optional[str] = None
    trusted_hosts_ipv4: List[str] = Field(default_factory=list)
    trusted_hosts_ipv6: List[str] = Field(default_factory=list)
    two_factor: Optional[str] = None
    token_reference: Optional[str] = None
    fortitoken_resolved: Optional[bool] = None
    access_profile_resolved: Optional[bool] = None
    unresolved_references: List[str] = Field(default_factory=list)
    email_to: Optional[str] = None
    remote_auth: Optional[str] = None
    remote_group: Optional[str] = None
    guest_user_groups: List[str] = Field(default_factory=list)
    schedule: Optional[str] = None
    peer_auth: Optional[str] = None
    peer_group: Optional[str] = None
    ssh_certificate: Optional[str] = None
    ssh_public_keys: List[str] = Field(default_factory=list)
    credential_configured: bool = False
    authentication_profile: Optional[str] = None
    authentication_sequence: Optional[str] = None
    authentication_profile_resolved: Optional[bool] = None
    authentication_sequence_resolved: Optional[bool] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAdminProfilePermissionBlock(BaseModel):
    name: str
    settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAdminProfile(BaseModel):
    name: str
    permission_blocks: List[IRAdminProfilePermissionBlock] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRFortiToken(BaseModel):
    serial: str
    status: Optional[str] = None
    assigned_user: Optional[str] = None
    description: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNHostCheckItem(BaseModel):
    source_id: int
    action: Optional[str] = None
    md5s: List[str] = Field(default_factory=list)
    target: Optional[str] = None
    check_type: Optional[str] = None
    version: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNHostCheck(BaseModel):
    name: str
    check_type: Optional[str] = None
    source_type: Optional[str] = None
    os_type: Optional[str] = None
    guid: Optional[str] = None
    version: Optional[str] = None
    check_items: List[IRSSLVPNHostCheckItem] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRFSSOPollingADGroup(BaseModel):
    name: str
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRFSSOPolling(BaseModel):
    name: str
    source_context: str = "root"
    status: Optional[str] = None
    server: Optional[str] = None
    default_domain: Optional[str] = None
    port: Optional[int] = None
    user: Optional[str] = None
    has_password: bool = False
    ldap_server: Optional[str] = None
    logon_history: Optional[int] = None
    polling_frequency: Optional[int] = None
    smbv1: Optional[str] = None
    smb_ntlmv1_auth: Optional[str] = None
    ad_groups: List[IRFSSOPollingADGroup] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNPortalSplitDNS(BaseModel):
    id: Optional[int] = None
    domains: Optional[str] = None
    dns_server1: Optional[str] = None
    dns_server2: Optional[str] = None
    ipv6_dns_server1: Optional[str] = None
    ipv6_dns_server2: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNPortalBookmarkFormData(BaseModel):
    name: str
    value_configured: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNPortalBookmark(BaseModel):
    name: str
    form_data: List[IRSSLVPNPortalBookmarkFormData] = Field(default_factory=list)
    has_logon_password: bool = False
    has_sso_password: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNPortalBookmarkGroup(BaseModel):
    name: str
    bookmarks: List[IRSSLVPNPortalBookmark] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNPortalLandingPageFormData(IRSSLVPNPortalBookmarkFormData):
    pass


class IRSSLVPNPortalLandingPage(BaseModel):
    name: str
    form_data: List[IRSSLVPNPortalLandingPageFormData] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNPortalMACAddressRule(BaseModel):
    id: Optional[int] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNPortalOSCheck(IRSSLVPNPortalMACAddressRule):
    pass


class IRSSLVPNPortal(BaseModel):
    name: str
    tunnel_mode: Optional[str] = None
    ipv6_tunnel_mode: Optional[str] = None
    ip_pools: List[str] = Field(default_factory=list)
    ipv6_pools: List[str] = Field(default_factory=list)
    split_tunneling: Optional[str] = None
    limit_user_logins: Optional[str] = None
    forticlient_download: Optional[str] = None
    host_check: Optional[str] = None
    host_check_policies: List[str] = Field(default_factory=list)
    host_check_interval: Optional[int] = None
    unresolved_host_check_policies: List[str] = Field(default_factory=list)
    allow_user_access: List[str] = Field(default_factory=list)
    auto_connect: Optional[str] = None
    exclusive_routing: Optional[str] = None
    ip_mode: Optional[str] = None
    service_restriction: Optional[str] = None
    split_tunneling_routing_addresses: List[str] = Field(default_factory=list)
    split_tunneling_routing_negate: Optional[str] = None
    client_src_range: Optional[str] = None
    clipboard: Optional[str] = None
    custom_lang: Optional[str] = None
    customize_forticlient_download_url: Optional[str] = None
    default_protocol: Optional[str] = None
    default_window_height: Optional[int] = None
    default_window_width: Optional[int] = None
    dhcp_ip_overlap: Optional[str] = None
    dhcp_ra_giaddr: Optional[str] = None
    dhcp6_ra_linkaddr: Optional[str] = None
    display_bookmark: Optional[str] = None
    display_connection_tools: Optional[str] = None
    display_history: Optional[str] = None
    display_status: Optional[str] = None
    dns_server1: Optional[str] = None
    dns_server2: Optional[str] = None
    dns_suffix: Optional[str] = None
    focus_bookmark: Optional[str] = None
    forticlient_download_method: Optional[str] = None
    heading: Optional[str] = None
    hide_sso_credential: Optional[str] = None
    ipv6_dns_server1: Optional[str] = None
    ipv6_dns_server2: Optional[str] = None
    ipv6_exclusive_routing: Optional[str] = None
    ipv6_service_restriction: Optional[str] = None
    ipv6_split_tunneling: Optional[str] = None
    ipv6_split_tunneling_routing_addresses: List[str] = Field(default_factory=list)
    ipv6_split_tunneling_routing_negate: Optional[str] = None
    ipv6_wins_server1: Optional[str] = None
    ipv6_wins_server2: Optional[str] = None
    keep_alive: Optional[str] = None
    landing_page_mode: Optional[str] = None
    mac_addr_action: Optional[str] = None
    mac_addr_check: Optional[str] = None
    macos_forticlient_download_url: Optional[str] = None
    os_check: Optional[str] = None
    prefer_ipv6_dns: Optional[str] = None
    redir_url: Optional[str] = None
    rewrite_ip_uri_ui: Optional[str] = None
    save_password: Optional[str] = None
    skip_check_for_browser: Optional[str] = None
    skip_check_for_unsupported_os: Optional[str] = None
    smb_max_version: Optional[str] = None
    smb_min_version: Optional[str] = None
    smb_ntlmv1_auth: Optional[str] = None
    smbv1: Optional[str] = None
    theme: Optional[str] = None
    use_sdwan: Optional[str] = None
    user_bookmark: Optional[str] = None
    user_group_bookmark: Optional[str] = None
    web_mode: Optional[str] = None
    windows_forticlient_download_url: Optional[str] = None
    wins_server1: Optional[str] = None
    wins_server2: Optional[str] = None
    source_fields: Dict[str, Any] = Field(default_factory=dict)
    bookmark_groups: List[IRSSLVPNPortalBookmarkGroup] = Field(default_factory=list)
    landing_pages: List[IRSSLVPNPortalLandingPage] = Field(default_factory=list)
    mac_address_check_rules: List[IRSSLVPNPortalMACAddressRule] = Field(default_factory=list)
    os_check_list: List[IRSSLVPNPortalOSCheck] = Field(default_factory=list)
    split_dns: List[IRSSLVPNPortalSplitDNS] = Field(default_factory=list)
    host_checks: List[IRSSLVPNHostCheck] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNAuthenticationRule(BaseModel):
    source_id: int
    auth: Optional[str] = None
    cipher: Optional[str] = None
    client_cert: Optional[str] = None
    realm: Optional[str] = None
    source_addresses: List[str] = Field(default_factory=list)
    source_address_negate: Optional[str] = None
    source_addresses6: List[str] = Field(default_factory=list)
    source_address6_negate: Optional[str] = None
    source_interfaces: List[str] = Field(default_factory=list)
    user_peer: Optional[str] = None
    users: List[str] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    unresolved_groups: List[str] = Field(default_factory=list)
    portal: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNSettings(BaseModel):
    status: Optional[str] = None
    ssl_min_proto_ver: Optional[str] = None
    banned_cipher: List[str] = Field(default_factory=list)
    server_certificate: Optional[str] = None
    server_certificate_configured: bool = False
    ssl_max_proto_ver: Optional[str] = None
    algorithm: Optional[str] = None
    client_signature_algorithms: List[str] = Field(default_factory=list)
    require_client_certificate: Optional[str] = None
    dtls_tunnel: Optional[str] = None
    login_attempt_limit: Optional[int] = None
    login_block_time: Optional[int] = None
    auth_timeout: Optional[int] = None
    idle_timeout: Optional[int] = None
    port: Optional[int] = None
    dns_server1: Optional[str] = None
    dns_server2: Optional[str] = None
    wins_server1: Optional[str] = None
    wins_server2: Optional[str] = None
    source_interfaces: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    tunnel_ip_pools: List[str] = Field(default_factory=list)
    auth_session_check_source_ip: Optional[str] = None
    auto_tunnel_static_route: Optional[str] = None
    browser_language_detection: Optional[str] = None
    check_referer: Optional[str] = None
    ciphersuite: Optional[str] = None
    deflate_compression_level: Optional[int] = None
    deflate_min_data_size: Optional[int] = None
    dns_suffix: Optional[str] = None
    dtls_heartbeat_fail_count: Optional[int] = None
    dtls_heartbeat_idle_timeout: Optional[int] = None
    dtls_heartbeat_interval: Optional[int] = None
    dtls_hello_timeout: Optional[int] = None
    dtls_max_proto_ver: Optional[str] = None
    dtls_min_proto_ver: Optional[str] = None
    dual_stack_mode: Optional[str] = None
    encode_2f_sequence: Optional[str] = None
    encrypt_and_store_password: Optional[str] = None
    force_two_factor_auth: Optional[str] = None
    header_x_forwarded_for: Optional[str] = None
    hsts_include_subdomains: Optional[str] = None
    http_compression: Optional[str] = None
    http_only_cookie: Optional[str] = None
    http_request_body_timeout: Optional[int] = None
    http_request_header_timeout: Optional[int] = None
    https_redirect: Optional[str] = None
    ipv6_dns_server1: Optional[str] = None
    ipv6_dns_server2: Optional[str] = None
    ipv6_wins_server1: Optional[str] = None
    ipv6_wins_server2: Optional[str] = None
    login_timeout: Optional[int] = None
    port_precedence: Optional[str] = None
    saml_redirect_port: Optional[int] = None
    server_hostname: Optional[str] = None
    source_address_negate: Optional[str] = None
    source_address6: List[str] = Field(default_factory=list)
    source_address6_negate: Optional[str] = None
    ssl_client_renegotiation: Optional[str] = None
    ssl_insert_empty_fragment: Optional[str] = None
    transform_backward_slashes: Optional[str] = None
    tunnel_addr_assigned_method: Optional[str] = None
    tunnel_connect_without_reauth: Optional[str] = None
    tunnel_ipv6_pools: List[str] = Field(default_factory=list)
    tunnel_user_session_timeout: Optional[int] = None
    unsafe_legacy_renegotiation: Optional[str] = None
    url_obscuration: Optional[str] = None
    user_peer: Optional[str] = None
    x_content_type_options: Optional[str] = None
    ztna_trusted_client: Optional[str] = None
    source_fields: Dict[str, Any] = Field(default_factory=dict)
    default_portal: Optional[str] = None
    authentication_rules: List[IRSSLVPNAuthenticationRule] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDoSAnomaly(BaseModel):
    name: str
    status: Optional[str] = None
    log: Optional[str] = None
    action: Optional[str] = None
    quarantine: Optional[str] = None
    quarantine_expiry: Optional[str] = None
    quarantine_log: Optional[str] = None
    threshold: Optional[int] = None
    threshold_default: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDoSPolicy(BaseModel):
    source_id: int
    name: Optional[str] = None
    source_context: Optional[str] = None
    address_family: str = "ipv4"
    status: Optional[str] = None
    interface: Optional[str] = None
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    anomalies: List[IRDoSAnomaly] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRFirewallSniffer(BaseModel):
    source_id: int
    source_uuid: Optional[str] = None
    logtraffic: Optional[str] = None
    ipv6: Optional[str] = None
    non_ip: Optional[str] = None
    application_list_status: Optional[str] = None
    application_list: Optional[str] = None
    ips_sensor_status: Optional[str] = None
    ips_sensor: Optional[str] = None
    av_profile_status: Optional[str] = None
    av_profile: Optional[str] = None
    webfilter_profile_status: Optional[str] = None
    webfilter_profile: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAuthenticationScheme(BaseModel):
    name: str
    method: Optional[str] = None
    user_database: Optional[str] = None
    resolved_user_databases: List[str] = Field(default_factory=list)
    unresolved_user_databases: List[str] = Field(default_factory=list)
    user_database_dependencies: List[IRIdentityDependency] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAuthenticationSequence(BaseModel):
    name: str
    source_context: Optional[str] = None
    authentication_profiles: List[str] = Field(default_factory=list)
    resolved_authentication_profiles: List[str] = Field(default_factory=list)
    unresolved_authentication_profiles: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLTLSServiceProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    certificate: Optional[str] = None
    certificate_resolved: Optional[bool] = None
    minimum_tls_version: Optional[str] = None
    maximum_tls_version: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAuthenticationRule(BaseModel):
    name: str
    source_interfaces: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    active_auth_method: Optional[str] = None
    active_auth_method_resolved: Optional[bool] = None
    unresolved_auth_methods: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRUserAuthenticationSettings(BaseModel):
    auth_certificate: Optional[str] = None
    auth_certificate_resolved: Optional[bool] = None
    auth_ca_certificate: Optional[str] = None
    auth_ca_certificate_resolved: Optional[bool] = None
    auth_timeout: Optional[int] = None
    auth_lockout_threshold: Optional[int] = None
    auth_lockout_duration: Optional[int] = None
    ssl_min_proto_version: Optional[str] = None
    management_authentication_profile: Optional[str] = None
    management_authentication_profile_resolved: Optional[bool] = None
    unresolved_management_authentication_profile: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRUserQuarantineSettings(BaseModel):
    firewall_groups: List[str] = Field(default_factory=list)
    resolved_firewall_groups: List[str] = Field(default_factory=list)
    unresolved_firewall_groups: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectClientAuthentication(BaseModel):
    name: str
    os: Optional[str] = None
    authentication_profile: Optional[str] = None
    authentication_profile_resolved: Optional[bool] = None
    resolved_authentication_profile: Optional[str] = None
    authentication_message: Optional[str] = None
    username_label: Optional[str] = None
    password_label: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectGatewayPriorityRule(BaseModel):
    name: str
    priority: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectExternalGateway(BaseModel):
    name: str
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    manual: Optional[bool] = None
    priority_rules: List[IRGlobalProtectGatewayPriorityRule] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectAppSetting(BaseModel):
    name: str
    values: List[str] = Field(default_factory=list)
    source_order: int
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectPortalClientConfig(BaseModel):
    name: str
    source_users: List[str] = Field(default_factory=list)
    operating_systems: List[str] = Field(default_factory=list)
    external_gateways: List[IRGlobalProtectExternalGateway] = Field(default_factory=list)
    external_gateway_cutoff_time: Optional[str] = None
    authentication_override_generate_cookie: Optional[bool] = None
    max_agent_user_overrides: Optional[int] = None
    agent_user_override_timeout: Optional[int] = None
    hip_collect_data: Optional[bool] = None
    hip_max_wait_time: Optional[int] = None
    app_settings: List[IRGlobalProtectAppSetting] = Field(default_factory=list)
    save_user_credentials: Optional[Union[int, str]] = None
    portal_2fa: Optional[bool] = None
    manual_only_gateway_2fa: Optional[bool] = None
    internal_gateway_2fa: Optional[bool] = None
    auto_discovery_external_gateway_2fa: Optional[bool] = None
    mdm_enrollment_port: Optional[int] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectPortalRootCA(BaseModel):
    certificate: str
    certificate_resolved: Optional[bool] = None
    resolved_certificate: Optional[str] = None
    install_in_cert_store: Optional[bool] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectPortal(BaseModel):
    name: str
    source_context: Optional[str] = None
    local_interface: Optional[str] = None
    local_interface_resolved: Optional[bool] = None
    resolved_local_interface: Optional[str] = None
    local_ipv4: Optional[str] = None
    local_ipv6: Optional[str] = None
    local_address_resolved: Optional[bool] = None
    resolved_local_address: Optional[str] = None
    ssl_tls_service_profile: Optional[str] = None
    ssl_tls_service_profile_resolved: Optional[bool] = None
    resolved_ssl_tls_service_profile: Optional[str] = None
    custom_login_page: Optional[str] = None
    custom_home_page: Optional[str] = None
    client_authentication: List[IRGlobalProtectClientAuthentication] = Field(default_factory=list)
    client_configs: List[IRGlobalProtectPortalClientConfig] = Field(default_factory=list)
    root_ca_certificates: List[IRGlobalProtectPortalRootCA] = Field(default_factory=list)
    has_agent_user_override_key: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectGatewayRole(BaseModel):
    name: str
    login_lifetime_days: Optional[int] = None
    inactivity_logout_hours: Optional[int] = None
    disconnect_on_idle_minutes: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectRemoteUserTunnelConfig(BaseModel):
    name: str
    source_users: List[str] = Field(default_factory=list)
    operating_systems: List[str] = Field(default_factory=list)
    ip_pools: List[str] = Field(default_factory=list)
    split_include_routes: List[str] = Field(default_factory=list)
    resolved_split_include_routes: List[str] = Field(default_factory=list)
    unresolved_split_include_routes: List[str] = Field(default_factory=list)
    split_exclude_routes: List[str] = Field(default_factory=list)
    resolved_split_exclude_routes: List[str] = Field(default_factory=list)
    unresolved_split_exclude_routes: List[str] = Field(default_factory=list)
    retrieve_framed_ip_address: Optional[bool] = None
    no_direct_access_to_local_network: Optional[bool] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectGateway(BaseModel):
    name: str
    source_context: Optional[str] = None
    ssl_tls_service_profile: Optional[str] = None
    ssl_tls_service_profile_resolved: Optional[bool] = None
    resolved_ssl_tls_service_profile: Optional[str] = None
    tunnel_mode: Optional[bool] = None
    remote_user_tunnel: Optional[str] = None
    remote_user_tunnel_resolved: Optional[bool] = None
    resolved_remote_user_tunnel: Optional[str] = None
    roles: List[IRGlobalProtectGatewayRole] = Field(default_factory=list)
    client_authentication: List[IRGlobalProtectClientAuthentication] = Field(default_factory=list)
    remote_user_tunnel_configs: List[IRGlobalProtectRemoteUserTunnelConfig] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRGlobalProtectNetworkGateway(BaseModel):
    name: str
    source_context: Optional[str] = None
    local_interface: Optional[str] = None
    local_interface_resolved: Optional[bool] = None
    resolved_local_interface: Optional[str] = None
    local_ipv4: Optional[str] = None
    local_ipv6: Optional[str] = None
    tunnel_interface: Optional[str] = None
    tunnel_interface_resolved: Optional[bool] = None
    resolved_tunnel_interface: Optional[str] = None
    ip_pools: List[str] = Field(default_factory=list)
    client_dns_primary: Optional[str] = None
    client_dns_secondary: Optional[str] = None
    dns_suffixes: List[str] = Field(default_factory=list)
    dns_suffix_inherited: Optional[bool] = None
    exclude_video_traffic_enabled: Optional[bool] = None
    third_party_client_enabled: Optional[bool] = None
    third_party_group_name: Optional[str] = None
    third_party_group_password_configured: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANLogServerEndpoint(BaseModel):
    name: str
    address: Optional[str] = None
    transport: Optional[str] = None
    port: Optional[int] = None
    format: Optional[str] = None
    facility: Optional[str] = None
    display_name: Optional[str] = None
    gateway: Optional[str] = None
    from_address: Optional[str] = None
    to_addresses: List[str] = Field(default_factory=list)
    snmp_version: Optional[str] = None
    community_configured: Optional[bool] = None
    username: Optional[str] = None
    authentication_password_configured: Optional[bool] = None
    privacy_password_configured: Optional[bool] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANLogServerProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    profile_type: str
    servers: List[IRPANLogServerEndpoint] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANLogForwardingMatch(BaseModel):
    name: str
    log_type: Optional[str] = None
    filter: Optional[str] = None
    send_to_panorama: Optional[bool] = None
    syslog_profiles: List[str] = Field(default_factory=list)
    email_profiles: List[str] = Field(default_factory=list)
    snmptrap_profiles: List[str] = Field(default_factory=list)
    http_profiles: List[str] = Field(default_factory=list)
    resolved_syslog_profiles: List[str] = Field(default_factory=list)
    unresolved_syslog_profiles: List[str] = Field(default_factory=list)
    resolved_email_profiles: List[str] = Field(default_factory=list)
    unresolved_email_profiles: List[str] = Field(default_factory=list)
    resolved_snmptrap_profiles: List[str] = Field(default_factory=list)
    unresolved_snmptrap_profiles: List[str] = Field(default_factory=list)
    resolved_http_profiles: List[str] = Field(default_factory=list)
    unresolved_http_profiles: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANLogForwardingProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    matches: List[IRPANLogForwardingMatch] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANManagementLogSetting(IRPANLogForwardingMatch):
    log_family: Optional[str] = None

class IRPANDNSProxyDomainServer(BaseModel):
    name: str
    domain_names: List[str] = Field(default_factory=list)
    primary: Optional[str] = None
    secondary: Optional[str] = None
    cacheable: Optional[bool] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANDNSProxy(BaseModel):
    name: str
    source_context: Optional[str] = None
    enabled: Optional[bool] = None
    cache_enabled: Optional[bool] = None
    max_ttl_enabled: Optional[bool] = None
    default_primary: Optional[str] = None
    default_secondary: Optional[str] = None
    tcp_queries_enabled: Optional[bool] = None
    interfaces: List[str] = Field(default_factory=list)
    resolved_interfaces: List[str] = Field(default_factory=list)
    unresolved_interfaces: List[str] = Field(default_factory=list)
    domain_servers: List[IRPANDNSProxyDomainServer] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANMonitorProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    interval_seconds: Optional[int] = None
    threshold: Optional[int] = None
    action: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANQoSClass(BaseModel):
    name: str
    priority: Optional[str] = None
    egress_max: Optional[float] = None
    egress_guaranteed: Optional[float] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANQoSProfile(BaseModel):
    name: str
    source_context: Optional[str] = None
    bandwidth_type: Optional[str] = None
    egress_max: Optional[float] = None
    egress_guaranteed: Optional[float] = None
    classes: List[IRPANQoSClass] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANHAInterface(BaseModel):
    name: str
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANHALinkMonitorGroup(BaseModel):
    name: str
    interfaces: List[str] = Field(default_factory=list)
    resolved_interfaces: List[str] = Field(default_factory=list)
    unresolved_interfaces: List[str] = Field(default_factory=list)
    enabled: Optional[bool] = None
    failure_condition: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANHAPathMonitorGroup(BaseModel):
    name: str
    routing_instance: Optional[str] = None
    routing_instance_resolved: Optional[str] = None
    resolved_routing_instance: Optional[str] = None
    destination_ips: List[str] = Field(default_factory=list)
    failure_condition: Optional[str] = None
    ping_interval_ms: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANHighAvailability(BaseModel):
    source_context: Optional[str] = None
    enabled: Optional[bool] = None
    group_id: Optional[int] = None
    description: Optional[str] = None
    peer_ip: Optional[str] = None
    preemptive: Optional[bool] = None
    recommended_timers: Optional[bool] = None
    ha2_keep_alive_enabled: Optional[bool] = None
    link_monitoring_enabled: Optional[bool] = None
    link_monitoring_failure_condition: Optional[str] = None
    link_groups: List[IRPANHALinkMonitorGroup] = Field(default_factory=list)
    path_monitoring_enabled: Optional[bool] = None
    path_monitoring_failure_condition: Optional[str] = None
    path_groups: List[IRPANHAPathMonitorGroup] = Field(default_factory=list)
    interfaces: List[IRPANHAInterface] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANDeviceOperationalSettings(BaseModel):
    source_context: Optional[str] = None
    rematch_sessions: Optional[bool] = None
    hostname_type_in_syslog: Optional[str] = None
    auto_acquire_commit_lock: Optional[bool] = None
    wildfire_report_benign_file: Optional[bool] = None
    wildfire_report_grayware_file: Optional[bool] = None
    tcp_urgent_data: Optional[str] = None
    tcp_asymmetric_path: Optional[str] = None
    session_timeout_default_seconds: Optional[int] = None
    session_timeout_tcp_seconds: Optional[int] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANVsysSettings(BaseModel):
    source_context: Optional[str] = None
    allow_forward_decrypted_content: Optional[bool] = None
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANBotnetUnknownApplicationThreshold(BaseModel):
    protocol: str
    sessions_per_hour: Optional[int] = None
    destinations_per_hour: Optional[int] = None
    minimum_bytes: Optional[int] = None
    maximum_bytes: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANBotnetReportSettings(BaseModel):
    dynamic_dns_enabled: Optional[bool] = None
    dynamic_dns_threshold: Optional[int] = None
    malware_sites_enabled: Optional[bool] = None
    malware_sites_threshold: Optional[int] = None
    recent_domains_enabled: Optional[bool] = None
    recent_domains_threshold: Optional[int] = None
    ip_domains_enabled: Optional[bool] = None
    ip_domains_threshold: Optional[int] = None
    executables_unknown_sites_enabled: Optional[bool] = None
    executables_unknown_sites_threshold: Optional[int] = None
    irc_enabled: Optional[bool] = None
    unknown_application_thresholds: List[IRPANBotnetUnknownApplicationThreshold] = Field(default_factory=list)
    topn: Optional[int] = None
    scheduled: Optional[bool] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPANCustomReport(BaseModel):
    name: str
    source_context: Optional[str] = None
    report_type: Optional[str] = None
    sort_by: Optional[str] = None
    group_by: Optional[str] = None
    aggregate_by: List[str] = Field(default_factory=list)
    topn: Optional[int] = None
    topm: Optional[int] = None
    caption: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRConfig(BaseModel):
    schema_version: str = IR_SCHEMA_VERSION
    generation_safe: bool = True
    generation_blocking_reasons: List[str] = Field(default_factory=list)
    requires_manual_review: bool = False
    metadata: IRMetadata
    zones: List[IRZone] = Field(default_factory=list)
    interfaces: List[IRInterface] = Field(default_factory=list)
    high_availability: List[IRHighAvailability] = Field(default_factory=list)
    checkpoint_management_access: List[IRCheckpointManagementAccess] = Field(default_factory=list)
    checkpoint_performance: List[IRCheckpointPerformanceSettings] = Field(default_factory=list)
    checkpoint_policy_packages: List[IRCheckpointPolicyPackage] = Field(default_factory=list)
    checkpoint_access_layers: List[IRCheckpointAccessLayer] = Field(default_factory=list)
    checkpoint_domains: List[IRCheckpointDomain] = Field(default_factory=list)
    addresses: List[IRAddress] = Field(default_factory=list)
    address_groups: List[IRAddressGroup] = Field(default_factory=list)
    service_categories: List[IRServiceCategory] = Field(default_factory=list)
    services: List[IRService] = Field(default_factory=list)
    service_groups: List[IRServiceGroup] = Field(default_factory=list)
    applications: List[IRApplication] = Field(default_factory=list)
    application_groups: List[IRApplicationGroup] = Field(default_factory=list)
    application_categories: List[IRApplicationCategory] = Field(default_factory=list)
    schedules: List[IRSchedule] = Field(default_factory=list)
    schedule_groups: List[IRScheduleGroup] = Field(default_factory=list)
    traffic_shapers: List[IRTrafficShaper] = Field(default_factory=list)
    proxy_addresses: List[IRProxyAddress] = Field(default_factory=list)
    web_proxy_settings: Optional[IRWebProxySettings] = None
    security_profile_groups: List[IRSecurityProfileGroup] = Field(default_factory=list)
    security_profile_definitions: List[IRSecurityProfileDefinition] = Field(default_factory=list)
    checkpoint_identity_sources: List[IRCheckpointIdentitySource] = Field(default_factory=list)
    checkpoint_access_roles: List[IRCheckpointAccessRole] = Field(default_factory=list)
    checkpoint_threat_prevention_rules: List[IRCheckpointThreatPreventionRule] = Field(default_factory=list)
    checkpoint_threat_prevention_profiles: List[IRCheckpointThreatPreventionProfile] = Field(default_factory=list)
    https_inspection_rules: List[IRHTTPSInspectionRule] = Field(default_factory=list)
    custom_url_categories: List[IRCustomURLCategory] = Field(default_factory=list)
    ips_sensors: List[IRIPSSensor] = Field(default_factory=list)
    policies: List[IRPolicy] = Field(default_factory=list)
    ip_pools: List[IRIPPool] = Field(default_factory=list)
    virtual_ips: List[IRVirtualIP] = Field(default_factory=list)
    virtual_ip_groups: List[IRVirtualIPGroup] = Field(default_factory=list)
    nat_rules: List[IRNATRule] = Field(default_factory=list)
    vpn_tunnels: List[IRVPNTunnel] = Field(default_factory=list)
    vpn_phase2: List[IRVPNPhase2] = Field(default_factory=list)
    vpn_communities: List[IRVPNCommunity] = Field(default_factory=list)
    vpn_gateways: List[IRVPNGateway] = Field(default_factory=list)
    certificates: List[IRCertificate] = Field(default_factory=list)
    ssh_keys: List[IRSSHKey] = Field(default_factory=list)
    system_settings: Optional[IRSystemSettings] = None
    dns_settings: Optional[IRDNSSettings] = None
    ntp_settings: Optional[IRNTPSettings] = None
    management_service_routes: List[IRManagementServiceRoute] = Field(default_factory=list)
    routes: List[IRRoute] = Field(default_factory=list)
    internet_services: List[IRInternetService] = Field(default_factory=list)
    internet_service_definitions: List[IRInternetServiceDefinition] = Field(default_factory=list)
    audit_entries: List[IRAuditEntry] = Field(default_factory=list)
    ztna_providers: List[IRZTNAProvider] = Field(default_factory=list)
    session_helpers: List[IRSessionHelper] = Field(default_factory=list)
    session_ttl_overrides: List[IRSessionTTLOverride] = Field(default_factory=list)
    session_ttl_settings: Optional[IRSessionTTLSettings] = None
    execution_contexts: List[IRExecutionContext] = Field(default_factory=list)
    central_snat_rules: List[IRFortiGateSourceRule] = Field(default_factory=list)
    security_policies: List[IRFortiGateSourceRule] = Field(default_factory=list)
    policy_routes: List[IRFortiGatePolicyRoute] = Field(default_factory=list)
    local_in_policies: List[IRFortiGateSourceRule] = Field(default_factory=list)
    proxy_policies: List[IRFortiGateSourceRule] = Field(default_factory=list)
    shaping_policies: List[IRFortiGateSourceRule] = Field(default_factory=list)
    dhcp6_servers: List[IRFortiGateSourceRule] = Field(default_factory=list)
    source_only_rules: List[IRFortiGateSourceRule] = Field(default_factory=list)
    custom_internet_services: List[IRFortiGateSourceRule] = Field(default_factory=list)
    custom_internet_service_groups: List[IRFortiGateSourceRule] = Field(default_factory=list)
    dhcp_servers: List[IRDHCPServer] = Field(default_factory=list)
    sdwans: List[IRSDWAN] = Field(default_factory=list)
    user_ldap_servers: List[IRUserLDAP] = Field(default_factory=list)
    user_radius_servers: List[IRUserRADIUS] = Field(default_factory=list)
    user_tacacs_servers: List[IRUserTACACS] = Field(default_factory=list)
    fsso_providers: List[IRFSSOProvider] = Field(default_factory=list)
    fsso_ad_groups: List[IRFSSOADGroup] = Field(default_factory=list)
    fsso_polling: List[IRFSSOPolling] = Field(default_factory=list)
    user_saml_servers: List[IRUserSAML] = Field(default_factory=list)
    local_users: List[IRLocalUser] = Field(default_factory=list)
    user_groups: List[IRUserGroup] = Field(default_factory=list)
    administrators: List[IRAdministrator] = Field(default_factory=list)
    admin_profiles: List[IRAdminProfile] = Field(default_factory=list)
    fortitokens: List[IRFortiToken] = Field(default_factory=list)
    ssl_vpn_portals: List[IRSSLVPNPortal] = Field(default_factory=list)
    ssl_vpn_host_checks: List[IRSSLVPNHostCheck] = Field(default_factory=list)
    ssl_vpn_settings: Optional[IRSSLVPNSettings] = None
    dos_policies: List[IRDoSPolicy] = Field(default_factory=list)
    firewall_sniffers: List[IRFirewallSniffer] = Field(default_factory=list)
    authentication_schemes: List[IRAuthenticationScheme] = Field(default_factory=list)
    authentication_sequences: List[IRAuthenticationSequence] = Field(default_factory=list)
    ssl_tls_service_profiles: List[IRSSLTLSServiceProfile] = Field(default_factory=list)
    authentication_rules: List[IRAuthenticationRule] = Field(default_factory=list)
    user_authentication_settings: Optional[IRUserAuthenticationSettings] = None
    user_quarantine_settings: Optional[IRUserQuarantineSettings] = None
    global_protect_portals: List[IRGlobalProtectPortal] = Field(default_factory=list)
    global_protect_gateways: List[IRGlobalProtectGateway] = Field(default_factory=list)
    global_protect_network_gateways: List[IRGlobalProtectNetworkGateway] = Field(default_factory=list)
    pan_log_server_profiles: List[IRPANLogServerProfile] = Field(default_factory=list)
    pan_log_forwarding_profiles: List[IRPANLogForwardingProfile] = Field(default_factory=list)
    pan_management_log_settings: List[IRPANManagementLogSetting] = Field(default_factory=list)
    pan_dns_proxies: List[IRPANDNSProxy] = Field(default_factory=list)
    pan_monitor_profiles: List[IRPANMonitorProfile] = Field(default_factory=list)
    pan_qos_profiles: List[IRPANQoSProfile] = Field(default_factory=list)
    pan_high_availability: Optional[IRPANHighAvailability] = None
    pan_device_operational_settings: Optional[IRPANDeviceOperationalSettings] = None
    pan_vsys_settings: List[IRPANVsysSettings] = Field(default_factory=list)
    pan_botnet_report_settings: Optional[IRPANBotnetReportSettings] = None
    pan_custom_reports: List[IRPANCustomReport] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_sdwan_field(cls, value: Any) -> Any:
        """Accept the pre-VDOM single-SD-WAN field when constructing IRConfig."""
        if not isinstance(value, dict) or "sdwan" not in value:
            return value
        migrated = dict(value)
        legacy_sdwan = migrated.pop("sdwan")
        if "sdwans" not in migrated and legacy_sdwan is not None:
            migrated["sdwans"] = [legacy_sdwan]
        return migrated

    @property
    def sdwan(self) -> Optional[IRSDWAN]:
        """Backward-compatible access for unambiguous single-SD-WAN configs."""
        return self.sdwans[0] if len(self.sdwans) == 1 else None

    @property
    def identity_sources(self) -> List[IRCheckpointIdentitySource]:
        return self.checkpoint_identity_sources

    @property
    def access_roles(self) -> List[IRCheckpointAccessRole]:
        return self.checkpoint_access_roles

    @property
    def threat_prevention_rules(self) -> List[IRCheckpointThreatPreventionRule]:
        return self.checkpoint_threat_prevention_rules

    @property
    def threat_prevention_profiles(self) -> List[IRCheckpointThreatPreventionProfile]:
        return self.checkpoint_threat_prevention_profiles
