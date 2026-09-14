# Canonical IR vpn domain models

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


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
    source_auth_method: Optional[str] = None
    source_remote_auth_method: Optional[str] = None
    source_certificates: List[str] = Field(default_factory=list)
    source_dh_groups: List[int] = Field(default_factory=list)
    source_key_lifetime: Optional[int] = None
    source_nat_traversal: Optional[str] = None
    source_dpd_mode: Optional[str] = None
    source_dpd_retry_count: Optional[int] = None
    source_xauth_type: Optional[str] = None
    source_peer_id: Optional[str] = None
    source_local_id: Optional[str] = None
    source_local_id_type: Optional[str] = None
    source_local_gateway_ipv4: Optional[str] = None
    source_local_gateway_ipv6: Optional[str] = None
    source_remote_gateway_ipv4: Optional[str] = None
    source_remote_gateway_ipv6: Optional[str] = None
    source_remote_gateway_ddns: Optional[str] = None
    source_mode_config_allow_client_selector: Optional[str] = None
    source_auth_user: Optional[str] = None
    source_split_exclude: List[str] = Field(default_factory=list)
    source_ipv6_split_include: List[str] = Field(default_factory=list)
    source_ipv6_split_exclude: List[str] = Field(default_factory=list)
    source_backup_gateways: List[str] = Field(default_factory=list)
    source_rekey: Optional[str] = None
    source_reauth: Optional[str] = None
    source_signature_hash_algorithms: List[str] = Field(default_factory=list)
    unresolved_interfaces: List[str] = Field(default_factory=list)
    unresolved_certificates: List[str] = Field(default_factory=list)
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
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
    source_subnet6: Optional[str] = None
    destination_subnet6: Optional[str] = None
    source_range_start: Optional[str] = None
    source_range_end: Optional[str] = None
    destination_range_start: Optional[str] = None
    destination_range_end: Optional[str] = None
    source_range_start6: Optional[str] = None
    source_range_end6: Optional[str] = None
    destination_range_start6: Optional[str] = None
    destination_range_end6: Optional[str] = None
    source_names6: List[str] = Field(default_factory=list)
    destination_names6: List[str] = Field(default_factory=list)
    pfs: Optional[bool] = None
    key_lifetime: Optional[int] = None
    keylife_type: Optional[str] = None
    keylife_seconds: Optional[int] = None
    keylife_kilobytes: Optional[int] = None
    replay: Optional[str] = None
    protocol: Optional[int] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    auto_negotiate: Optional[bool] = None
    dh_groups: List[int] = Field(default_factory=list)
    keepalive: Optional[bool] = None
    description: Optional[str] = None
    migration_status: str = "PARTIALLY_NORMALIZED"
    requires_manual_review: bool = True
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


__all__ = [
    "IRVPNTunnel",
    "IRVPNPhase2",
    "IRVPNCommunity",
    "IRVPNGateway",
]
