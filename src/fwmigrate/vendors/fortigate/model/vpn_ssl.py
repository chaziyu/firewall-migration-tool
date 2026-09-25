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


class FGSSLVPNRealm(BaseModel):
    url_path: str
    vdom: str = "root"
    login_page: str | None = None
    max_concurrent_user: int | None = None
    nas_ip: str | None = None
    radius_port: int | None = None
    radius_server: str | None = None
    virtual_host: str | None = None
    virtual_host_only: str | None = None
    virtual_host_server_cert: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLVPNClient(BaseModel):
    name: str
    vdom: str = "root"
    certificate: str | None = None
    class_id: int | None = None
    comment: str | None = None
    distance: int | None = None
    interface: str | None = None
    ipv4_subnets: str | None = None
    ipv6_subnets: str | None = None
    peer: str | None = None
    port: int | None = None
    priority: int | None = None
    psk_configured: bool = False
    realm: str | None = None
    server: str | None = None
    source_ip: str | None = None
    status: str | None = None
    user: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLVPNBookmarkFormData(BaseModel):
    name: str
    value: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLVPNBookmark(BaseModel):
    name: str
    additional_params: str | None = None
    apptype: str | None = None
    color_depth: str | None = None
    description: str | None = None
    domain: str | None = None
    folder: str | None = None
    form_data: list[FGSSLVPNBookmarkFormData] = Field(default_factory=list)
    height: int | None = None
    host: str | None = None
    keyboard_layout: str | None = None
    load_balancing_info: str | None = None
    logon_password_configured: bool = False
    logon_user: str | None = None
    port: int | None = None
    preconnection_blob: str | None = None
    preconnection_id: int | None = None
    restricted_admin: str | None = None
    security: str | None = None
    send_preconnection_id: str | None = None
    sso: str | None = None
    sso_credential: str | None = None
    sso_credential_sent_once: str | None = None
    sso_password_configured: bool = False
    sso_username: str | None = None
    url: str | None = None
    vnc_keyboard_layout: str | None = None
    width: int | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLVPNUserBookmark(BaseModel):
    owner_name: str
    vdom: str = "root"
    custom_lang: str | None = None
    bookmarks: list[FGSSLVPNBookmark] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGSSLVPNUserGroupBookmark(BaseModel):
    owner_name: str
    vdom: str = "root"
    custom_lang: str | None = None
    bookmarks: list[FGSSLVPNBookmark] = Field(default_factory=list)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
