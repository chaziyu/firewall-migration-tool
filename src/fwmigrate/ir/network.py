# Canonical IR network domain models

from datetime import timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator
from .provenance import IRSourceConfigNode
from .extension_models import (
    IRCheckPointInterfaceCompatibilityMixin,
    IRCheckPointInterfaceExtension,
    IRFortiOSInterfaceExtension,
    move_object_extension,
)


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
    source_effective_intrazone: Optional[str] = None
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
class IRInterfaceGroup(BaseModel):
    name: str
    source_context: Optional[str] = None
    source_uuid: Optional[str] = None
    members: List[str] = Field(default_factory=list)
    migration_status: str = "NORMALIZED"
    requires_manual_review: bool = False
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
class IRInterfaceIPv6Address(BaseModel):
    address: Optional[str] = None
    source_address: str
    prefix_length: Optional[int] = None
    standby: Optional[str] = None
    eui64: bool = False
    link_local: bool = False
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRInterfaceIPv4Address(BaseModel):
    address: Optional[str] = None
    source_address: str
    requires_manual_review: bool = False
    parse_error: Optional[str] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
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
class IRCheckpointInterfaceContext(BaseModel):
    """Check Point source ownership and collection context for an interface."""

    domain_uid: Optional[str] = None
    domain_name: Optional[str] = None
    management_gateway_uid: Optional[str] = None
    management_gateway_name: Optional[str] = None
    management_gateway_type: Optional[str] = None
    gaia_gateway_name: Optional[str] = None
    gaia_cluster_member_name: Optional[str] = None
    virtual_system_id: Optional[int] = None
class IRInterface(IRCheckPointInterfaceCompatibilityMixin, BaseModel):
    name: str
    source_context: Optional[str] = None
    vendor_extension: Optional[
        IRCheckPointInterfaceExtension | IRFortiOSInterfaceExtension
    ] = None
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
    additional_ipv4_addresses: List[IRInterfaceIPv4Address] = Field(default_factory=list)
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
class IRClusterInterface(BaseModel):
    name: str
    virtual_ipv4: Optional[str] = None
    virtual_ipv6: Optional[str] = None
    member_addresses: Dict[str, List[str]] = Field(default_factory=dict)
    topology: Optional[Any] = None
    interface_role: Optional[str] = None
    sync: Optional[bool] = None
    anti_spoofing: Optional[Any] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def move_legacy_vendor_fields(cls, data: Any) -> Any:
        return move_object_extension(data, ("checkpoint_context",))
class IRHighAvailability(BaseModel):
    """Source-preserved cluster topology; target generation is not implied."""
    source_uuid: Optional[str] = None
    name: str
    cluster_type: Optional[str] = None
    mode: Optional[str] = None
    member_references: List[str] = Field(default_factory=list)
    member_names: List[str] = Field(default_factory=list)
    virtual_ips: List[str] = Field(default_factory=list)
    member_interface_ips: Dict[str, List[str]] = Field(default_factory=dict)
    sync_interfaces: List[str] = Field(default_factory=list)
    cluster_uid: Optional[str] = None
    cluster_interfaces: List[IRClusterInterface] = Field(default_factory=list)
    sync_network: Optional[Any] = None
    installation_targets: List[str] = Field(default_factory=list)
    topology: Dict[str, Any] = Field(default_factory=dict)
    ha_settings: Dict[str, Any] = Field(default_factory=dict)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)

    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True


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
class IRSystemSettings(BaseModel):
    hostname: Optional[str] = None
    timezone: Optional[str] = None
    admin_https_port: Optional[int] = None
    multi_vsys_enabled: Optional[bool] = None
    management_plane: Optional["IRManagementPlaneSettings"] = None
    source_attributes: Dict[str, Any] = Field(default_factory=dict)
class IRCheckpointSICMetadata(BaseModel):
    gateway_uid: Optional[str] = None
    gateway_name: Optional[str] = None
    sic_status: Optional[str] = None
    sic_certificate_uid: Optional[str] = None
    sic_certificate_name: Optional[str] = None
    sic_certificate_fingerprint: Optional[str] = None
    management_reference: Optional[str] = None
    source_context: Optional[str] = None
    migration_status: str = "EXTRACT_ONLY"
    requires_manual_review: bool = True
    sic_credential_present: Optional[bool] = None
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
class IRDNSSettings(BaseModel):
    primary: Optional[str] = None
    secondary: Optional[str] = None
    tertiary: Optional[str] = None
    domain_name: Optional[str] = None
    search_suffixes: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "IRZoneTaggingEntry",
    "IRZone",
    "IRInterfaceGroup",
    "IRInterfaceSecondaryIP",
    "IRInterfaceIPv6Address",
    "IRInterfaceIPv4Address",
    "IRInterfaceIPv6PrefixAdvertisement",
    "IRInterfaceIPv6DelegatedPrefix",
    "IRInterfaceDHCPv6IAPD",
    "IRInterfaceVRRP6",
    "IRCheckpointInterfaceContext",
    "IRInterface",
    "IRClusterInterface",
    "IRHighAvailability",
    "IRDHCPIPRange",
    "IRDHCPExcludeRange",
    "IRDHCPReservation",
    "IRDHCPOption",
    "IRDHCPServer",
    "IRSystemSettings",
    "IRCheckpointSICMetadata",
    "IRManagementPlaneSettings",
    "IRNTPServer",
    "IRNTPSettings",
    "IRDNSSettings",
]
