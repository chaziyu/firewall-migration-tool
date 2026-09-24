from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from .base import CiscoSourceRecord


class CiscoIKEPolicy(CiscoSourceRecord):
    version: Optional[str] = None
    number: Optional[int] = None
    authentication: Optional[str] = None
    encryption: Optional[str] = None
    integrity: Optional[str] = None
    hash_algorithm: Optional[str] = None
    dh_group: Optional[str] = None
    lifetime_seconds: Optional[int] = None
    prf: Optional[str] = None
    encryption_algorithms: List[str] = Field(default_factory=list)
    hash_algorithms: List[str] = Field(default_factory=list)
    integrity_algorithms: List[str] = Field(default_factory=list)
    prf_algorithms: List[str] = Field(default_factory=list)
    dh_groups: List[str] = Field(default_factory=list)
    raw_options: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoIKEv2Proposal(CiscoSourceRecord):
    encryption_algorithms: List[str] = Field(default_factory=list)
    integrity_algorithms: List[str] = Field(default_factory=list)
    prf_algorithms: List[str] = Field(default_factory=list)
    dh_groups: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoIPsecTransformSet(CiscoSourceRecord):
    encryption: Optional[str] = None
    authentication: Optional[str] = None
    mode: Optional[str] = None
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoVPNAddressPool(CiscoSourceRecord):
    start: Optional[str] = None
    end: Optional[str] = None
    mask: Optional[str] = None
    address_family: Optional[str] = None
    raw_line: Optional[str] = None
    review_reasons: List[str] = Field(default_factory=list)


class CiscoCryptoMap(CiscoSourceRecord):
    sequence: Optional[int] = None
    acl_name: Optional[str] = None
    peer: Optional[str] = None
    peers: List[str] = Field(default_factory=list)
    transform_sets: List[str] = Field(default_factory=list)
    dynamic_map: Optional[str] = None
    map_name: Optional[str] = None
    map_type: Optional[str] = None
    ikev2_proposals: List[str] = Field(default_factory=list)
    pfs_group: Optional[str] = None
    security_association_lifetime_seconds: Optional[int] = None
    security_association_lifetime_kilobytes: Optional[int] = None
    interface_attachment: Optional[str] = None
    is_dynamic: bool = False
    source_order: Optional[int] = None
    raw_options: List[str] = Field(default_factory=list)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoTunnelGroup(CiscoSourceRecord):
    group_type: Optional[str] = None
    default_group_policy: Optional[str] = None
    address_pools: List[str] = Field(default_factory=list)
    authentication_method: Optional[str] = None
    peer_address: Optional[str] = None
    trustpoint: Optional[str] = None
    ikev1_psk_present: bool = False
    ikev2_local_authentication: Optional[str] = None
    ikev2_remote_authentication: Optional[str] = None
    general_attributes: Dict[str, Any] = Field(default_factory=dict)
    ipsec_attributes: Dict[str, Any] = Field(default_factory=dict)
    webvpn_attributes: Dict[str, Any] = Field(default_factory=dict)
    review_reasons: List[str] = Field(default_factory=list)


class CiscoGroupPolicy(CiscoSourceRecord):
    policy_type: Optional[str] = None
    parent: Optional[str] = None
    address_pools: List[str] = Field(default_factory=list)
    dns_servers: List[str] = Field(default_factory=list)
    split_tunnel_policy: Optional[str] = None
    split_tunnel_acl: Optional[str] = None
    vpn_access_hours: Optional[str] = None
    vpn_filter_acl: Optional[str] = None
    vpn_simultaneous_logins: Optional[int] = None
    wins_servers: List[str] = Field(default_factory=list)
    webvpn_attributes: Dict[str, Any] = Field(default_factory=dict)
    vpn_protocols: List[str] = Field(default_factory=list)
    idle_timeout: Optional[str] = None
    session_timeout: Optional[str] = None
    default_domain: Optional[str] = None
    raw_attributes: Dict[str, Any] = Field(default_factory=dict)
    review_reasons: List[str] = Field(default_factory=list)


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
    extraction_status: str = "SOURCE_ONLY"
    requires_manual_review: bool = True
    review_reasons: List[str] = Field(default_factory=list)
    source_attributes: Dict[str, Any] = Field(default_factory=dict)


class CiscoWebVPNConfig(CiscoSourceRecord):
    enabled_interfaces: List[str] = Field(default_factory=list)
    tunnel_group_list: Optional[bool] = None
    client_images: List[str] = Field(default_factory=list)
    client_profiles: List[str] = Field(default_factory=list)
    trustpoint_references: List[str] = Field(default_factory=list)


class CiscoVPNAddressAssignment(CiscoSourceRecord):
    aaa_enabled: Optional[bool] = None
    dhcp_enabled: Optional[bool] = None
    local_enabled: Optional[bool] = None
    reuse_delay: Optional[int] = None
