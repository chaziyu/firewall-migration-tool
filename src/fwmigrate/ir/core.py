from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, model_validator

from fwmigrate.ir.version import IR_SCHEMA_VERSION
from fwmigrate.ir.enums import (
    AddressType, ServiceProtocol, PolicyAction, NATType, NATTranslationMode,
    MigrationConfidence,
)

class IRMetadata(BaseModel):
    hostname: str
    source_vendor: str = "fortinet"
    target_vendor: Optional[str] = None
    input_type: str = "Unknown"
    source_version: Optional[str] = None
    source_context: Optional[str] = None
    migration_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class IRZone(BaseModel):
    name: str
    interfaces: List[str] = Field(default_factory=list)
    description: Optional[str] = None

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

class IRInterface(BaseModel):
    name: str
    zone: Optional[str] = None
    ip: Optional[str] = None
    remote_ip: Optional[str] = None
    secondary_ips: List[
        IRInterfaceSecondaryIP
    ] = Field(default_factory=list)
    description: Optional[str] = None
    management_profile: Optional[str] = None
    parent: Optional[str] = None
    tag: Optional[int] = None
    alias: Optional[str] = None
    status: bool = True
    vlanid: Optional[int] = None
    pppoe_mode: Optional[str] = None
    pppoe_username: Optional[str] = None
    source_vdom: Optional[str] = None
    interface_type: Optional[str] = None
    role: Optional[str] = None
    addressing_mode: Optional[str] = None
    management_access: List[str] = Field(
        default_factory=list
    )
    dhcp_client: Optional[bool] = None
    requires_manual_review: bool = False
    parse_errors: List[str] = Field(
        default_factory=list
    )
    nested_source_configs: List[
        IRSourceConfigNode
    ] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(
        default_factory=dict
    )

class IRAddress(BaseModel):
    name: str
    type: AddressType

    # Source provenance and extraction-only metadata. Target generators must
    # not interpret source-only fields as portable address semantics.
    source_uuid: Optional[str] = None
    associated_interface: Optional[str] = None
    allow_routing: Optional[bool] = None
    source_color: Optional[int] = None
    source_sub_type: Optional[str] = None
    source_obj_tag: Optional[str] = None
    source_tag_type: Optional[str] = None
    source_obj_type: Optional[str] = None
    source_dirty: Optional[str] = None
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
    geo_code: Optional[str] = None
    wildcard_mask: Optional[str] = None
    dynamic_filter: Optional[str] = None
    tag_name: Optional[str] = None
    stub_value: Optional[str] = None
    
    # Stub & manual review fields
    original_type: Optional[str] = None
    original_value: Optional[str] = None
    requires_manual_review: bool = False
    audit_note: Optional[str] = None
    
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
        elif self.type == AddressType.MAC and self.mac:
            return self.mac
        elif self.type == AddressType.GEO and self.geo_code:
            return self.geo_code
        elif self.type == AddressType.WILDCARD_MASK and self.wildcard_mask:
            return self.wildcard_mask
        elif self.type == AddressType.DYNAMIC and self.dynamic_filter:
            return self.dynamic_filter
        elif self.type == AddressType.EMS_TAG and self.tag_name:
            return self.tag_name
        elif self.type == AddressType.SPECIAL:
            return self.original_value or self.name
        elif self.type == AddressType.STUB_UNSUPPORTED:
            return self.stub_value or self.subnet or "198.19.255.254/32"
            
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
            if not self.mac:
                raise ValueError(f"Address {self.name} of type MAC must have 'mac' defined.")
        elif self.type == AddressType.GEO:
            if not self.geo_code:
                raise ValueError(f"Address {self.name} of type GEO must have 'geo_code' defined.")
        elif self.type == AddressType.WILDCARD_MASK:
            if not self.wildcard_mask:
                raise ValueError(f"Address {self.name} of type WILDCARD_MASK must have 'wildcard_mask' defined.")
        elif self.type == AddressType.DYNAMIC:
            if not self.dynamic_filter:
                raise ValueError(f"Address {self.name} of type DYNAMIC must have 'dynamic_filter' defined.")
        elif self.type == AddressType.EMS_TAG:
            if not self.tag_name:
                raise ValueError(f"Address {self.name} of type EMS_TAG must have 'tag_name' defined.")
        elif self.type == AddressType.SPECIAL:
            pass
        elif self.type == AddressType.STUB_UNSUPPORTED:
            pass
                
        return self

class IRAddressGroupTaggingEntry(BaseModel):
    name: str
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAddressGroup(BaseModel):
    name: str
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
    description: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRService(BaseModel):
    name: str
    ports: List[IRServicePort] = Field(default_factory=list)
    source_uuid: Optional[str] = None
    source_category: Optional[str] = None
    source_protocol: Optional[str] = None
    source_protocol_number: Optional[int] = None
    source_proxy: Optional[bool] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None
    description: Optional[str] = None

class IRServiceGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    source_uuid: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
    description: Optional[str] = None

class IRSchedule(BaseModel):
    name: str
    start: Optional[str] = None
    end: Optional[str] = None
    days: List[str] = Field(default_factory=list)
    schedule_type: str = "recurring"
    source_color: Optional[int] = None
    expiration_days: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRTrafficShaper(BaseModel):
    name: str
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
    antivirus: Optional[str] = None
    vulnerability: Optional[str] = None
    anti_spyware: Optional[str] = None
    url_filtering: Optional[str] = None
    file_blocking: Optional[str] = None
    wildfire: Optional[str] = None
    ssl_decryption: Optional[str] = None
    description: Optional[str] = None


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
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRIPSSensor(BaseModel):
    name: str
    description: Optional[str] = None
    block_malicious_url: Optional[bool] = None
    scan_botnet_connections: Optional[str] = None
    entries: List[IRIPSSensorEntry] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRPolicy(BaseModel):
    name: str
    from_zone: List[str] = Field(default_factory=list)
    to_zone: List[str] = Field(default_factory=list)
    source: List[str] = Field(default_factory=list)
    destination: List[str] = Field(default_factory=list)
    service: List[str] = Field(default_factory=list)
    action: PolicyAction
    # Source-policy preservation and audit fields
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
    source_log_setting: Optional[str] = None
    source_log_start_setting: Optional[str] = None
    source_utm_status: Optional[str] = None
    source_inspection_mode: Optional[str] = None
    source_profile_type: Optional[str] = None
    source_profile_group: Optional[str] = None
    source_profile_protocol_options: Optional[str] = None
    source_internet_service_status: Optional[str] = None
    source_vpn_tunnel: Optional[str] = None
    source_ztna_status: Optional[str] = None
    source_ztna_ems_tags: List[str] = Field(default_factory=list)
    source_extra_settings: Dict[str, Any] = Field(default_factory=dict)
    nat_enabled: Optional[bool] = None
    nat_pool_enabled: Optional[bool] = None
    nat_pool_names: List[str] = Field(default_factory=list)
    nat_pool_names6: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    description: Optional[str] = None
    schedule: Optional[str] = None
    log_start: bool = False
    log_end: bool = True
    disabled: bool = False
    # Advanced / UTM threat profiles
    security_profile_group: Optional[str] = None
    antivirus: Optional[str] = None
    ips_sensor: Optional[str] = None
    webfilter: Optional[str] = None
    application_list: Optional[str] = None
    ssl_ssh_profile: Optional[str] = None
    applications: List[str] = Field(default_factory=list)
    internet_service: List[str] = Field(default_factory=list)

class IRIPPool(BaseModel):
    name: str
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

class IRNATRule(BaseModel):
    name: str
    type: NATType
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
    source_translation_mode: Optional[NATTranslationMode] = None
    source_pool_references: List[str] = Field(default_factory=list)
    source_pool_type: Optional[str] = None
    source_pool_excluded_ips: List[str] = Field(default_factory=list)
    source_pool_permit_any_host: Optional[bool] = None
    source_pool_original_start_ip: List[str] = Field(default_factory=list)
    source_pool_original_end_ip: List[str] = Field(default_factory=list)
    translated_sources: List[str] = Field(default_factory=list)
    translated_destinations: List[str] = Field(default_factory=list)
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
    service: str = "any"
    translated_source: Optional[str] = None
    translated_destination: Optional[str] = None
    translated_port: Optional[str] = None
    description: Optional[str] = None

    @property
    def safe_for_target_generation(self) -> bool:
        return (
            self.migration_status == "NORMALIZED"
            and not self.requires_manual_review
            and not self.review_reasons
        )

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
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRRoute(BaseModel):
    name: str
    destination: Optional[str] = None
    source_destination: Optional[str] = None
    source_route_id: Optional[int] = None
    interface: Optional[str] = None
    next_hop: Optional[str] = None
    administrative_distance: Optional[int] = None
    metric: Optional[int] = None
    priority: Optional[int] = None
    blackhole: bool = False
    enabled: Optional[bool] = None
    sdwan_zone: Optional[str] = None
    description: Optional[str] = None
    migration_status: str = "NORMALIZED"
    parse_error: Optional[str] = None
    requires_manual_review: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

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
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRDHCPIPRange(BaseModel):
    source_id: int
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDHCPReservation(BaseModel):
    source_id: int
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDHCPServer(BaseModel):
    source_id: int
    enabled: bool = True

    interface: Optional[str] = None
    default_gateway: Optional[str] = None
    netmask: Optional[str] = None
    lease_time_seconds: Optional[int] = None

    dns_service: Optional[str] = None
    dns_servers: List[str] = Field(default_factory=list)
    timezone_option: Optional[str] = None

    ip_ranges: List[IRDHCPIPRange] = Field(default_factory=list)
    reservations: List[IRDHCPReservation] = Field(default_factory=list)

    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
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
    hostname: str
    timezone: Optional[str] = None
    admin_https_port: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDNSSettings(BaseModel):
    primary: Optional[str] = None
    secondary: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRVirtualIPGroup(BaseModel):
    name: str
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
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSDWANMember(BaseModel):
    source_id: int
    interface: str
    zone: str
    gateway: Optional[str] = None
    weight: Optional[int] = None
    priority: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSDWANSLA(BaseModel):
    source_id: int
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSDWANHealthCheck(BaseModel):
    name: str
    server: Optional[str] = None
    member_ids: List[int] = Field(default_factory=list)
    interval: Optional[int] = None
    sla: List[IRSDWANSLA] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSDWANRule(BaseModel):
    source_id: int
    name: Optional[str] = None
    mode: Optional[str] = None
    source_addresses: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    health_check: Optional[str] = None
    priority_member_ids: List[int] = Field(default_factory=list)
    internet_service: Optional[str] = None
    internet_service_names: List[str] = Field(default_factory=list)
    internet_service_app_ctrl: List[int] = Field(default_factory=list)
    use_shortcut_sla: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSDWAN(BaseModel):
    status: str = "disable"
    load_balance_mode: Optional[str] = None
    zones: List[IRSDWANZone] = Field(default_factory=list)
    members: List[IRSDWANMember] = Field(default_factory=list)
    health_checks: List[IRSDWANHealthCheck] = Field(default_factory=list)
    rules: List[IRSDWANRule] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRUserLDAP(BaseModel):
    name: str
    server: Optional[str] = None
    cnid: Optional[str] = None
    dn: Optional[str] = None
    source_type: Optional[str] = None
    username: Optional[str] = None
    has_password: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRFSSOProvider(BaseModel):
    name: str
    server: Optional[str] = None
    has_password: bool = False
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
    user_name: Optional[str] = None
    group_name: Optional[str] = None
    digest_method: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRLocalUser(BaseModel):
    name: str
    status: Optional[str] = None
    source_type: Optional[str] = None
    has_password: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRUserGroupMatch(BaseModel):
    source_id: int
    server_name: Optional[str] = None
    group_name: Optional[str] = None


class IRUserGroup(BaseModel):
    name: str
    group_type: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    matches: List[IRUserGroupMatch] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAdministrator(BaseModel):
    name: str
    access_profile: Optional[str] = None
    vdoms: List[str] = Field(default_factory=list)
    trusthost1: Optional[str] = None
    trusthost2: Optional[str] = None
    two_factor: Optional[str] = None
    token_reference: Optional[str] = None
    email_to: Optional[str] = None
    remote_auth: Optional[str] = None
    remote_group: Optional[str] = None
    credential_configured: bool = False
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAdminProfile(BaseModel):
    name: str
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


class IRSSLVPNHostCheck(BaseModel):
    name: str
    source_type: Optional[str] = None
    guid: Optional[str] = None
    version: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNPortal(BaseModel):
    name: str
    tunnel_mode: Optional[str] = None
    ipv6_tunnel_mode: Optional[str] = None
    ip_pools: List[str] = Field(default_factory=list)
    ipv6_pools: List[str] = Field(default_factory=list)
    split_tunneling: Optional[str] = None
    limit_user_logins: Optional[str] = None
    forticlient_download: Optional[str] = None
    host_checks: List[IRSSLVPNHostCheck] = Field(default_factory=list)
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNAuthenticationRule(BaseModel):
    source_id: int
    groups: List[str] = Field(default_factory=list)
    portal: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRSSLVPNSettings(BaseModel):
    status: Optional[str] = None
    ssl_min_proto_ver: Optional[str] = None
    banned_cipher: List[str] = Field(default_factory=list)
    server_certificate: Optional[str] = None
    source_interfaces: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    tunnel_ip_pools: List[str] = Field(default_factory=list)
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
    threshold: Optional[int] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRDoSPolicy(BaseModel):
    source_id: int
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
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class IRAuthenticationRule(BaseModel):
    name: str
    source_interfaces: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    active_auth_method: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRConfig(BaseModel):
    schema_version: str = IR_SCHEMA_VERSION
    metadata: IRMetadata
    zones: List[IRZone] = Field(default_factory=list)
    interfaces: List[IRInterface] = Field(default_factory=list)
    addresses: List[IRAddress] = Field(default_factory=list)
    address_groups: List[IRAddressGroup] = Field(default_factory=list)
    service_categories: List[IRServiceCategory] = Field(default_factory=list)
    services: List[IRService] = Field(default_factory=list)
    service_groups: List[IRServiceGroup] = Field(default_factory=list)
    schedules: List[IRSchedule] = Field(default_factory=list)
    traffic_shapers: List[IRTrafficShaper] = Field(default_factory=list)
    proxy_addresses: List[IRProxyAddress] = Field(default_factory=list)
    web_proxy_settings: Optional[IRWebProxySettings] = None
    security_profile_groups: List[IRSecurityProfileGroup] = Field(default_factory=list)
    ips_sensors: List[IRIPSSensor] = Field(default_factory=list)
    policies: List[IRPolicy] = Field(default_factory=list)
    ip_pools: List[IRIPPool] = Field(default_factory=list)
    virtual_ips: List[IRVirtualIP] = Field(default_factory=list)
    virtual_ip_groups: List[IRVirtualIPGroup] = Field(default_factory=list)
    nat_rules: List[IRNATRule] = Field(default_factory=list)
    vpn_tunnels: List[IRVPNTunnel] = Field(default_factory=list)
    vpn_phase2: List[IRVPNPhase2] = Field(default_factory=list)
    certificates: List[IRCertificate] = Field(default_factory=list)
    ssh_keys: List[IRSSHKey] = Field(default_factory=list)
    system_settings: Optional[IRSystemSettings] = None
    dns_settings: Optional[IRDNSSettings] = None
    routes: List[IRRoute] = Field(default_factory=list)
    internet_services: List[IRInternetService] = Field(default_factory=list)
    internet_service_definitions: List[IRInternetServiceDefinition] = Field(default_factory=list)
    audit_entries: List[IRAuditEntry] = Field(default_factory=list)
    ztna_providers: List[IRZTNAProvider] = Field(default_factory=list)
    session_helpers: List[IRSessionHelper] = Field(default_factory=list)
    session_ttl_overrides: List[IRSessionTTLOverride] = Field(default_factory=list)
    dhcp_servers: List[IRDHCPServer] = Field(default_factory=list)
    sdwan: Optional[IRSDWAN] = None
    user_ldap_servers: List[IRUserLDAP] = Field(default_factory=list)
    fsso_providers: List[IRFSSOProvider] = Field(default_factory=list)
    fsso_ad_groups: List[IRFSSOADGroup] = Field(default_factory=list)
    user_saml_servers: List[IRUserSAML] = Field(default_factory=list)
    local_users: List[IRLocalUser] = Field(default_factory=list)
    user_groups: List[IRUserGroup] = Field(default_factory=list)
    administrators: List[IRAdministrator] = Field(default_factory=list)
    admin_profiles: List[IRAdminProfile] = Field(default_factory=list)
    fortitokens: List[IRFortiToken] = Field(default_factory=list)
    ssl_vpn_portals: List[IRSSLVPNPortal] = Field(default_factory=list)
    ssl_vpn_settings: Optional[IRSSLVPNSettings] = None
    dos_policies: List[IRDoSPolicy] = Field(default_factory=list)
    firewall_sniffers: List[IRFirewallSniffer] = Field(default_factory=list)
    authentication_schemes: List[IRAuthenticationScheme] = Field(default_factory=list)
    authentication_rules: List[IRAuthenticationRule] = Field(default_factory=list)
