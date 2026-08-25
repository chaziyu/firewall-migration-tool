from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, model_validator
from datetime import datetime, timezone
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

class IRInterface(BaseModel):
    name: str
    zone: Optional[str] = None
    ip: Optional[str] = None  # CIDR format: 192.168.1.1/24
    description: Optional[str] = None
    management_profile: Optional[str] = None
    # For subinterfaces/VLANs
    parent: Optional[str] = None
    tag: Optional[int] = None
    alias: Optional[str] = None
    status: bool = True
    vlanid: Optional[int] = None
    pppoe_mode: Optional[str] = None
    pppoe_username: Optional[str] = None
    # Portable interface semantics retained from the source configuration.
    source_vdom: Optional[str] = None
    interface_type: Optional[str] = None
    role: Optional[str] = None
    addressing_mode: Optional[str] = None
    management_access: List[str] = Field(default_factory=list)
    dhcp_client: Optional[bool] = None
    # Extraction-only settings; target generators must ignore this map.
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

class IRAddress(BaseModel):
    name: str
    type: AddressType
    
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
        elif self.type == AddressType.STUB_UNSUPPORTED:
            pass
                
        return self

class IRAddressGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    is_dynamic: bool = False
    dynamic_filter: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

class IRServicePort(BaseModel):
    protocol: ServiceProtocol
    port: str  # e.g., "443", "80-90"
    icmptype: Optional[int] = None
    icmpcode: Optional[int] = None
    
class IRService(BaseModel):
    name: str
    ports: List[IRServicePort] = Field(default_factory=list)
    description: Optional[str] = None

class IRServiceGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class IRSchedule(BaseModel):
    name: str
    start: Optional[str] = None
    end: Optional[str] = None
    days: List[str] = Field(default_factory=list)

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
    source_user_groups: List[str] = Field(default_factory=list)
    source_users: List[str] = Field(default_factory=list)
    source_log_setting: Optional[str] = None
    source_inspection_mode: Optional[str] = None
    source_ztna_status: Optional[str] = None
    source_ztna_ems_tags: List[str] = Field(default_factory=list)
    source_extra_settings: Dict[str, Any] = Field(default_factory=dict)
    nat_enabled: Optional[bool] = None
    nat_pool_enabled: Optional[bool] = None
    nat_pool_names: List[str] = Field(default_factory=list)
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

    description: Optional[str] = None


class IRVirtualIPRealServer(BaseModel):
    id: Optional[int] = None
    address: Optional[str] = None
    port: Optional[int] = None
    status: Optional[str] = None
    weight: Optional[int] = None
    holddown_interval: Optional[int] = None


class IRVirtualIP(BaseModel):
    name: str

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
    translated_sources: List[str] = Field(default_factory=list)
    translated_destinations: List[str] = Field(default_factory=list)
    destination_protocol: Optional[str] = None
    original_destination_port: Optional[str] = None
    source_vip_reference: Optional[str] = None
    source_vip_group_reference: Optional[str] = None
    requires_manual_review: bool = False
    # Backward-compatible scalar fields. New code should use the list fields above.
    service: str = "any"
    translated_source: Optional[str] = None
    translated_destination: Optional[str] = None
    translated_port: Optional[str] = None
    description: Optional[str] = None

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
    peer_address: str
    local_interface: str
    ike_version: str = "v1"
    psk: Optional[str] = None
    ike_crypto_profile: str = "default"
    ipsec_crypto_profile: str = "default"
    description: Optional[str] = None

class IRRoute(BaseModel):
    name: str
    destination: str
    interface: Optional[str] = None
    next_hop: Optional[str] = None
    metric: int = 10
    description: Optional[str] = None

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

class IRConfig(BaseModel):
    metadata: IRMetadata
    zones: List[IRZone] = Field(default_factory=list)
    interfaces: List[IRInterface] = Field(default_factory=list)
    addresses: List[IRAddress] = Field(default_factory=list)
    address_groups: List[IRAddressGroup] = Field(default_factory=list)
    services: List[IRService] = Field(default_factory=list)
    service_groups: List[IRServiceGroup] = Field(default_factory=list)
    schedules: List[IRSchedule] = Field(default_factory=list)
    security_profile_groups: List[IRSecurityProfileGroup] = Field(default_factory=list)
    policies: List[IRPolicy] = Field(default_factory=list)
    ip_pools: List[IRIPPool] = Field(default_factory=list)
    virtual_ips: List[IRVirtualIP] = Field(default_factory=list)
    nat_rules: List[IRNATRule] = Field(default_factory=list)
    vpn_tunnels: List[IRVPNTunnel] = Field(default_factory=list)
    routes: List[IRRoute] = Field(default_factory=list)
    internet_services: List[IRInternetService] = Field(default_factory=list)
    audit_entries: List[IRAuditEntry] = Field(default_factory=list)
    ztna_providers: List[IRZTNAProvider] = Field(default_factory=list)
    session_helpers: List[IRSessionHelper] = Field(default_factory=list)
    session_ttl_overrides: List[IRSessionTTLOverride] = Field(default_factory=list)
    dhcp_servers: List[IRDHCPServer] = Field(default_factory=list)
