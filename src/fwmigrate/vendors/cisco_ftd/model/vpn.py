"""Vendor-native cisco_ftd vpn models."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from .base import CiscoFTDReference, CiscoFTDSourceRecord


class CiscoFTDCertificate(CiscoFTDSourceRecord):
    certificate_type: Optional[str] = None
    source_collection: Optional[str] = None
    issuer: Optional[Any] = None
    subject: Optional[Any] = None
    validity: Optional[Dict[str, Any]] = None
    certificate_metadata: Optional[Dict[str, Any]] = None
    private_key_present: Optional[bool] = None


class CiscoFTDCertificateMap(CiscoFTDSourceRecord):
    conditions: Optional[Any] = None
    connection_profile: Optional[CiscoFTDReference] = None
    group_policy: Optional[CiscoFTDReference] = None


class CiscoFTDCertificateEnrollment(CiscoFTDSourceRecord): pass


class CiscoFTDAddressPool(CiscoFTDSourceRecord):
    address_family: Optional[str] = None
    source_representation: Optional[Any] = None
    start_address: Optional[str] = None
    end_address: Optional[str] = None
    override_metadata: Optional[Dict[str, Any]] = None
    address_reuse_delay: Optional[int] = None


class CiscoFTDS2SIKESettings(CiscoFTDSourceRecord):
    ike_policies: Optional[List[CiscoFTDReference]] = None
    ikev1_policies: Optional[List[CiscoFTDReference]] = None
    ikev2_policies: Optional[List[CiscoFTDReference]] = None
    ikev1_authentication_type: Optional[str] = None
    ikev2_authentication_type: Optional[str] = None
    ikev1_certificate: Optional[CiscoFTDReference] = None
    ikev2_certificate: Optional[CiscoFTDReference] = None
    ikev1_automatic_psk_length: Optional[int] = None
    ikev2_automatic_psk_length: Optional[int] = None
    ikev2_hex_psk_only: Optional[bool] = None
    certificates: Optional[List[CiscoFTDReference]] = None
    psk_present: Optional[bool] = None


class CiscoFTDS2SIPsecSettings(CiscoFTDSourceRecord):
    ipsec_proposals: Optional[List[CiscoFTDReference]] = None
    ikev1_ipsec_proposals: Optional[List[CiscoFTDReference]] = None
    ikev2_ipsec_proposals: Optional[List[CiscoFTDReference]] = None
    pfs_enabled: Optional[bool] = None
    pfs_group: Optional[int] = None
    lifetime_seconds: Optional[int] = None
    lifetime_kilobytes: Optional[int] = None
    ikev2_mode: Optional[str] = None
    crypto_map_type: Optional[str] = None
    do_not_fragment_policy: Optional[str] = None
    enable_rri: Optional[bool] = None
    enable_sa_strength_enforcement: Optional[bool] = None
    tfc_packets: Optional[Dict[str, Any]] = None
    validate_incoming_icmp_error_message: Optional[bool] = None


class CiscoFTDS2SAdvancedSettings(CiscoFTDSourceRecord):
    ike_keepalive_settings: Optional[Dict[str, Any]] = None
    advanced_ike_settings: Optional[Dict[str, Any]] = None
    advanced_ipsec_settings: Optional[Dict[str, Any]] = None
    advanced_tunnel_settings: Optional[Dict[str, Any]] = None


class CiscoFTDRAVPNIPsecSettings(CiscoFTDSourceRecord):
    ikev2_settings: Optional[Dict[str, Any]] = None
    ipsec_settings: Optional[Dict[str, Any]] = None
    nat_keepalive: Optional[Dict[str, Any]] = None


class CiscoFTDLDAPAttributeMap(CiscoFTDSourceRecord): pass


class CiscoFTDRAVPNLoadBalanceSettings(CiscoFTDSourceRecord): pass


class CiscoFTDRAVPNAddressAssignmentSettings(CiscoFTDSourceRecord):
    address_pools: Optional[List[CiscoFTDReference]] = None
    assignment_method: Optional[Any] = None
    allow_reuse: Optional[bool] = None
    reuse_delay: Optional[int] = None
    external_assignment: Optional[CiscoFTDReference] = None
    use_authorization_server_for_ipv4: Optional[bool] = None
    use_authorization_server_for_ipv6: Optional[bool] = None
    use_dhcp: Optional[bool] = None
    use_internal_address_pool_for_ipv4: Optional[bool] = None
    use_internal_address_pool_for_ipv6: Optional[bool] = None


class CiscoFTDSecureClientSettings(CiscoFTDSourceRecord):
    packages: Optional[List[CiscoFTDReference]] = None
    profiles: Optional[List[CiscoFTDReference]] = None


class CiscoFTDRAVPNIPsecCryptoMap(CiscoFTDSourceRecord): pass


class CiscoFTDS2SVPNTopology(CiscoFTDSourceRecord): pass


class CiscoFTDS2SVPNEndpoint(CiscoFTDSourceRecord):
    device: Optional[CiscoFTDReference] = None
    interface: Optional[CiscoFTDReference] = None
    vti: Optional[CiscoFTDReference] = None
    protected_networks: Optional[List[CiscoFTDReference]] = None
    peer_type: Optional[str] = None
    connection_type: Optional[str] = None
    extranet: Optional[bool] = None
    extranet_info: Optional[Dict[str, Any]] = None
    peer_ip_address: Optional[str] = None
    local_identity_type: Optional[str] = None
    local_identity: Optional[str] = None
    local_identity_enabled: Optional[bool] = None


class CiscoFTDIKEPolicy(CiscoFTDSourceRecord):
    ike_version: Optional[str] = None
    priority: Optional[int] = None
    lifetime_in_seconds: Optional[int] = None
    authentication_method: Optional[str] = None
    encryption: Optional[str] = None
    hash: Optional[str] = None
    diffie_hellman_group: Optional[int] = None
    encryption_algorithms: Optional[List[str]] = None
    integrity_algorithms: Optional[List[str]] = None
    prf_integrity_algorithms: Optional[List[str]] = None
    diffie_hellman_groups: Optional[List[int]] = None


class CiscoFTDIPsecProposal(CiscoFTDSourceRecord):
    ike_version: Optional[str] = None
    esp_encryption: Optional[str] = None
    esp_hash: Optional[str] = None
    encryption_algorithms: Optional[List[str]] = None
    integrity_algorithms: Optional[List[str]] = None


class CiscoFTDRAVPNPolicy(CiscoFTDSourceRecord):
    target_devices: Optional[List[CiscoFTDReference]] = None
    access_interfaces: Optional[List[CiscoFTDReference]] = None
    certificates: Optional[List[CiscoFTDReference]] = None
    certificate_maps: Optional[List[CiscoFTDReference]] = None
    certificate_map_settings: Optional[List[Dict[str, Any]]] = None
    connection_profiles: Optional[List[CiscoFTDReference]] = None
    group_policies: Optional[List[CiscoFTDReference]] = None
    address_pools: Optional[List[CiscoFTDReference]] = None
    realms: Optional[List[CiscoFTDReference]] = None
    ssl_tls_settings: Optional[Dict[str, Any]] = None
    dtls_settings: Optional[Dict[str, Any]] = None
    session_settings: Optional[Dict[str, Any]] = None


class CiscoFTDRAVPNConnectionProfile(CiscoFTDSourceRecord):
    parent_policy_id: Optional[str] = None
    parent_policy_name: Optional[str] = None
    alias: Optional[Any] = None
    group_url: Optional[Any] = None
    enabled: Optional[bool] = None
    authentication_method: Optional[str] = None
    realm: Optional[CiscoFTDReference] = None
    authentication_server: Optional[CiscoFTDReference] = None
    authorization: Optional[CiscoFTDReference] = None
    accounting_server: Optional[CiscoFTDReference] = None
    address_assignment: Optional[Any] = None
    address_pools: Optional[List[CiscoFTDReference]] = None
    default_group_policy: Optional[CiscoFTDReference] = None
    certificates: Optional[List[CiscoFTDReference]] = None
    certificate_maps: Optional[List[CiscoFTDReference]] = None
    connection_settings: Optional[Dict[str, Any]] = None


class CiscoFTDNativeResource(CiscoFTDSourceRecord): pass
