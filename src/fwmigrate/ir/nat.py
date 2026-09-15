# Canonical IR nat domain models

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
from fwmigrate.ir.enums import NATType, NATTranslationMode, NATTranslationAddressSource, NATFamily, NATSourcePortBehavior
from .provenance import IRSourceConfigNode


class IRIPPoolRange(BaseModel):
    start_ip: str
    end_ip: str


class IRIPPool(BaseModel):
    name: str
    source_context: Optional[str] = None
    address_family: str = "ipv4"
    routing_instance: Optional[str] = None
    source_explicit_fields: List[str] = Field(default_factory=list)
    source_effective_settings: Dict[str, Any] = Field(default_factory=dict)

    pool_type: Optional[str] = None

    addresses: List[str] = Field(default_factory=list)
    address_ranges: List[IRIPPoolRange] = Field(default_factory=list)
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

    description: Optional[str] = None
    source_uuid: Optional[str] = None
    checkpoint_pool_object_type: Optional[str] = None
    checkpoint_network_references: List[str] = Field(default_factory=list)
    checkpoint_network_group_references: List[str] = Field(default_factory=list)
    checkpoint_address_range_references: List[str] = Field(default_factory=list)
    checkpoint_gateway_references: List[str] = Field(default_factory=list)
    checkpoint_member_assignments: Dict[str, Any] = Field(default_factory=dict)
    checkpoint_applicability: List[str] = Field(default_factory=list)
    checkpoint_precedence: Optional[int] = None
    checkpoint_vpn_scope: Optional[str] = None
    checkpoint_mep: Optional[bool] = None
    source_origin: Optional[str] = None
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
class IRVirtualIPGSLBPublicIP(BaseModel):
    index: Optional[int] = None
    ip: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRVirtualIPQUICSettings(BaseModel):
    max_idle_timeout: Optional[int] = None
    max_udp_payload_size: Optional[int] = None
    active_connection_id_limit: Optional[int] = None
    ack_delay_exponent: Optional[int] = None
    max_ack_delay: Optional[int] = None
    max_datagram_frame_size: Optional[int] = None
    active_migration: Optional[str] = None
    grease_quic_bit: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRVirtualIPSSLCipherSuite(BaseModel):
    priority: Optional[int] = None
    cipher: Optional[str] = None
    versions: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
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
    h2_support: Optional[str] = None
    h3_support: Optional[str] = None
    http_multiplex: Optional[str] = None
    ssl_mode: Optional[str] = None
    ssl_certificate: Optional[str] = None
    ssl_algorithm: Optional[str] = None
    ssl_min_version: Optional[str] = None
    ssl_max_version: Optional[str] = None
    ssl_server_algorithm: Optional[str] = None
    ssl_server_min_version: Optional[str] = None
    ssl_server_max_version: Optional[str] = None
    ssl_pfs: Optional[str] = None
    gslb_domain_name: Optional[str] = None
    gslb_hostname: Optional[str] = None
    monitors: List[str] = Field(default_factory=list)
    max_embryonic_connections: Optional[int] = None
    real_servers: List[IRVirtualIPRealServer] = Field(default_factory=list)
    source_explicit_fields: List[str] = Field(default_factory=list)
    source_effective_settings: Dict[str, Any] = Field(default_factory=dict)
    nested_source_configs: List[IRSourceConfigNode] = Field(default_factory=list)
    source_gslb_public_ips: List[IRVirtualIPGSLBPublicIP] = Field(default_factory=list)
    source_quic: Optional[IRVirtualIPQUICSettings] = None
    source_ssl_cipher_suites: List[IRVirtualIPSSLCipherSuite] = Field(default_factory=list)
    source_ssl_server_cipher_suites: List[IRVirtualIPSSLCipherSuite] = Field(default_factory=list)

    color: Optional[int] = None
    description: Optional[str] = None
    extra_settings: Dict[str, Any] = Field(default_factory=dict)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
    audit_note: Optional[str] = None
class IRNATPortRange(BaseModel):
    start: int
    end: Optional[int] = None
class IRNATServiceMatch(BaseModel):
    reference: str
    protocol: Optional[str] = None
    source_ports: List[IRNATPortRange] = Field(default_factory=list)
    destination_ports: List[IRNATPortRange] = Field(default_factory=list)
class IRNATDestinationDistribution(BaseModel):
    method: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRNATDestinationDNSRewrite(BaseModel):
    enabled: Optional[bool] = None
    direction: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
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
class IRNATTranslationAddressSelection(BaseModel):
    address_source: Optional[NATTranslationAddressSource] = None
    interface: Optional[str] = None
    ipv4_addresses: List[str] = Field(default_factory=list)
    ipv6_addresses: List[str] = Field(default_factory=list)
    floating_ips: List[str] = Field(default_factory=list)
class IRNATSourceTranslationFallback(BaseModel):
    mode: Optional[NATTranslationMode] = None
    address_selection: Optional[IRNATTranslationAddressSelection] = None
    translated_addresses: List[str] = Field(default_factory=list)
    interface: Optional[str] = None
    interface_ips: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRNATRule(BaseModel):
    name: str
    type: NATType
    source_context: Optional[str] = None
    checkpoint_domain_uid: Optional[str] = None
    checkpoint_domain_name: Optional[str] = None
    checkpoint_package_uid: Optional[str] = None
    checkpoint_package_name: Optional[str] = None
    source_policy_reference: Optional[str] = None
    source_policy_uuid: Optional[str] = None
    source_policy_name: Optional[str] = None
    sequence: Optional[int] = None
    source_rule_set: Optional[str] = None
    from_routing_instances: List[str] = Field(default_factory=list)
    to_routing_instances: List[str] = Field(default_factory=list)
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
    service_matches: List[IRNATServiceMatch] = Field(default_factory=list)
    translated_source_ports: List[IRNATPortRange] = Field(default_factory=list)
    translated_destination_ports: List[IRNATPortRange] = Field(default_factory=list)
    source_port_behavior: Optional[NATSourcePortBehavior] = None
    address_range_mappings: List[IRNATAddressRangeMapping] = Field(default_factory=list)
    install_translation_route: Optional[bool] = None
    runtime_behavior: Optional[IRNATRuntimeBehavior] = None
    source_origin: Optional[str] = None
    traffic_type: str = "unicast"
    source_translation_mode: Optional[NATTranslationMode] = None
    source_translation_address_selection: Optional[IRNATTranslationAddressSelection] = None
    source_translation_bidirectional: Optional[bool] = None
    source_translation_fallback: Optional[IRNATSourceTranslationFallback] = None
    destination_translation_mode: Optional[NATTranslationMode] = None
    destination_translation_distribution: Optional[IRNATDestinationDistribution] = None
    destination_dns_rewrite: Optional[IRNATDestinationDNSRewrite] = None
    source_device_binding: Optional[str] = None
    identity: bool = False
    exemption: bool = False
    source_pool_references: List[str] = Field(default_factory=list)
    translated_source_address_references: List[str] = Field(default_factory=list)
    source_pool_type: Optional[str] = None
    source_pool_excluded_ips: List[str] = Field(default_factory=list)
    source_pool_permit_any_host: Optional[bool] = None
    source_pool_original_start_ip: List[str] = Field(default_factory=list)
    source_pool_original_end_ip: List[str] = Field(default_factory=list)
    destination_pool_references: List[str] = Field(default_factory=list)
    translated_destination_address_references: List[str] = Field(default_factory=list)
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
    source_policy_effective_match_vip: Optional[str] = None
    source_policy_effective_match_vip_only: Optional[str] = None
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
        if self.type == NATType.STATIC:
            return False
        if self.identity or self.exemption:
            return False
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
                or self.translated_source_address_references
                or self.source_translation_address_selection
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
            return bool(
                (
                    self.translated_sources
                    or self.source_pool_references
                    or self.translated_source_address_references
                    or self.source_translation_address_selection
                )
                and (self.translated_destinations or self.destination_pool_references)
            )
        if self.type == NATType.ADDRESS_TRANSLATION:
            return bool(self.address_range_mappings)
        if self.type == NATType.CENTRAL:
            if self.source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS:
                return bool(self.source_to_interfaces)
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
        if self.type == NATType.SERVICE:
            return False
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
class IRVirtualIPGroup(BaseModel):
    name: str
    source_context: Optional[str] = None
    address_family: str = "ipv4"
    source_uuid: Optional[str] = None
    interface: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    unresolved_members: List[str] = Field(default_factory=list)
    source_color: Optional[int] = None
    description: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    audit_note: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "IRIPPool",
    "IRVirtualIPRealServer",
    "IRVirtualIPGSLBPublicIP",
    "IRVirtualIPQUICSettings",
    "IRVirtualIPSSLCipherSuite",
    "IRVirtualIP",
    "IRNATPortRange",
    "IRNATServiceMatch",
    "IRNATDestinationDistribution",
    "IRNATDestinationDNSRewrite",
    "IRNATAddressRangeMapping",
    "IRNATRuntimeBehavior",
    "IRNATTranslationAddressSelection",
    "IRNATSourceTranslationFallback",
    "IRNATRule",
    "IRVirtualIPGroup",
]
