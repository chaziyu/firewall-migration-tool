from __future__ import annotations

from typing import Any

from .common import PANNamedSourceModel, PANNestedSourceModel


class PANGlobalProtectPortalGateway(PANNestedSourceModel):
    gateway_type: str | None = None
    gateway: str | None = None
    priority: str | None = None


class PANGlobalProtectPortalClientConfig(PANNestedSourceModel):
    name: str | None = None
    internal_host_detection_ip: str | None = None
    internal_host_detection_hostname: str | None = None
    authentication_override: dict[str, Any] | None = None
    agent_ui_settings: dict[str, Any] | None = None
    hip_collection_settings: dict[str, Any] | None = None
    agent_configuration: dict[str, Any] | None = None
    app_configuration: dict[str, Any] | None = None
    gateways: list[PANGlobalProtectPortalGateway] | None = None


class PANGlobalProtectClientlessVPN(PANNestedSourceModel):
    hostname: str | None = None
    security_zone: str | None = None
    login_lifetime: str | None = None
    login_lifetime_unit: str | None = None
    inactivity_logout: str | None = None
    inactivity_logout_unit: str | None = None
    maximum_users: str | None = None
    dns_proxy: str | None = None


class PANGlobalProtectPortal(PANNamedSourceModel):
    ssl_tls_service_profile: str | None = None
    certificate_profile: str | None = None
    clientless_vpn_enabled: str | None = None
    client_configs: list[PANGlobalProtectPortalClientConfig] | None = None
    clientless_vpn: PANGlobalProtectClientlessVPN | None = None


class PANGlobalProtectGatewayClientAuth(PANNestedSourceModel):
    name: str | None = None
    operating_system: str | None = None
    authentication_profile: str | None = None
    auto_retrieve_passcode: str | None = None


class PANGlobalProtectRemoteUserTunnel(PANNestedSourceModel):
    name: str | None = None
    ip_pools: list[str] | None = None
    authentication_server_ip_pools: list[str] | None = None
    split_tunneling: dict[str, Any] | None = None
    no_direct_access_to_local_network: str | None = None
    retrieve_framed_ip: str | None = None


class PANGlobalProtectGateway(PANNamedSourceModel):
    tunnel_mode: str | None = None
    local_interface: str | None = None
    local_address: str | None = None
    ip_address_family: str | None = None
    ssl_tls_service_profile: str | None = None
    certificate_profile: str | None = None
    client_authentication: list[PANGlobalProtectGatewayClientAuth] | None = None
    remote_user_tunnels: list[PANGlobalProtectRemoteUserTunnel] | None = None
