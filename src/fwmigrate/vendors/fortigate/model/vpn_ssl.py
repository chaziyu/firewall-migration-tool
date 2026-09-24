from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FGSSLVPNAuthenticationRule(BaseModel):
    id: int | None = None

    auth: str | None = None
    cipher: str | None = None
    client_cert: str | None = None

    groups: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)

    portal: str | None = None
    realm: str | None = None

    source_address: list[str] = Field(default_factory=list)
    source_address6: list[str] = Field(default_factory=list)
    source_interface: list[str] = Field(default_factory=list)

    source_address_negate: str | None = None
    source_address6_negate: str | None = None

    user_peer: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLVPNSettings(BaseModel):
    vdom: str = "root"

    status: str | None = None

    # TLS / authentication.
    ssl_min_proto_ver: str | None = None
    ssl_max_proto_ver: str | None = None
    auth_timeout: int | None = None
    idle_timeout: int | None = None

    # DNS.
    dns_server1: str | None = None
    dns_server2: str | None = None

    # Certificate.
    servercert: str | None = None

    # Direct source restrictions.
    source_interface: list[str] = Field(default_factory=list)
    source_address: list[str] = Field(default_factory=list)
    source_address6: list[str] = Field(default_factory=list)

    # Tunnel pools.
    tunnel_ip_pools: list[str] = Field(default_factory=list)
    tunnel_ipv6_pools: list[str] = Field(default_factory=list)

    # Portal.
    default_portal: str | None = None

    # Listener.
    port: int | None = None

    authentication_rules: list[FGSSLVPNAuthenticationRule] = Field(
        default_factory=list
    )

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLVPNPortal(BaseModel):
    name: str
    vdom: str = "root"

    tunnel_mode: str | None = None
    ipv6_tunnel_mode: str | None = None

    ip_pools: list[str] = Field(default_factory=list)
    ipv6_pools: list[str] = Field(default_factory=list)

    split_tunneling: str | None = None
    split_tunneling_routing_address: list[str] = Field(
        default_factory=list
    )

    ipv6_split_tunneling: str | None = None
    ipv6_split_tunneling_routing_address: list[str] = Field(
        default_factory=list
    )

    limit_user_logins: str | None = None
    forticlient_download: str | None = None

    web_mode: str | None = None

    host_check: str | None = None
    host_check_policy: list[str] = Field(default_factory=list)

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLVPNHostCheckItem(BaseModel):
    id: int | None = None

    action: str | None = None
    type: str | None = None
    target: str | None = None

    md5s: list[str] = Field(default_factory=list)

    version: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLVPNHostCheckSoftware(BaseModel):
    name: str
    vdom: str = "root"

    guid: str | None = None
    type: str | None = None
    os_type: str | None = None
    version: str | None = None

    check_items: list[FGSSLVPNHostCheckItem] = Field(
        default_factory=list
    )

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)