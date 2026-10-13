from __future__ import annotations

from .common import PANNamedSourceModel, PANNestedSourceModel


class PANIKEGateway(PANNamedSourceModel):
    local_interface: str | None = None
    local_ip: str | None = None
    peer_address_type: str | None = None
    peer_address: str | None = None
    ike_version: str | None = None
    ikev1_exchange_mode: str | None = None
    ikev1_crypto_profile: str | None = None
    ikev2_crypto_profile: str | None = None
    ikev2_require_cookie: str | None = None
    authentication_method: str | None = None
    pre_shared_key_configured: bool | None = None
    local_id: str | None = None
    peer_id: str | None = None
    ikev1_dpd_enabled: str | None = None
    ikev1_dpd_interval: str | None = None
    ikev1_dpd_retry: str | None = None
    ikev2_dpd_enabled: str | None = None
    ikev2_dpd_interval: str | None = None
    nat_traversal: str | None = None
    nat_traversal_keepalive: str | None = None
    nat_traversal_udp_checksum: str | None = None
    passive_mode: str | None = None
    fragmentation: str | None = None


class PANIKECryptoProfile(PANNamedSourceModel):
    encryption_algorithms: list[str] | None = None
    authentication_algorithms: list[str] | None = None
    dh_groups: list[str] | None = None
    lifetime_value: str | None = None
    lifetime_unit: str | None = None
    authentication_multiple: str | None = None


class PANIPsecCryptoProfile(PANNamedSourceModel):
    protocol: str | None = None
    protocols: list[str] | None = None
    esp_encryption: list[str] | None = None
    esp_authentication: list[str] | None = None
    ah_authentication: list[str] | None = None
    dh_group: str | None = None
    lifetime_value: str | None = None
    lifetime_unit: str | None = None


class PANIPsecProxyID(PANNestedSourceModel):
    name: str | None = None
    address_family: str | None = None
    local: str | None = None
    remote: str | None = None
    protocol: str | None = None
    protocol_number: str | None = None
    local_port: str | None = None
    remote_port: str | None = None


class PANIPsecTunnel(PANNamedSourceModel):
    tunnel_interface: str | None = None
    key_type: str | None = None
    ike_gateways: list[str] | None = None
    ipsec_crypto_profile: str | None = None
    tunnel_monitor: str | None = None
    globalprotect_satellite: str | None = None
    manual_key_configured: bool | None = None
    proxy_ids: list[PANIPsecProxyID] | None = None
