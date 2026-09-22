from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FGAdminFirewallPermission(BaseModel):
    address: str | None = None
    others: str | None = None
    policy: str | None = None
    schedule: str | None = None
    service: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAdminLogPermission(BaseModel):
    config: str | None = None
    data_access: str | None = None
    report_access: str | None = None
    threat_weight: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAdminNetworkPermission(BaseModel):
    cfg: str | None = None
    packet_capture: str | None = None
    route_cfg: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAdminSystemPermission(BaseModel):
    admin: str | None = None
    cfg: str | None = None
    mnt: str | None = None
    upd: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAdminUTMPermission(BaseModel):
    antivirus: str | None = None
    application_control: str | None = None
    casb: str | None = None
    dlp: str | None = None
    dnsfilter: str | None = None
    emailfilter: str | None = None
    endpoint_control: str | None = None
    file_filter: str | None = None
    icap: str | None = None
    ips: str | None = None
    videofilter: str | None = None
    virtual_patch: str | None = None
    voip: str | None = None
    waf: str | None = None
    webfilter: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAdministrator(BaseModel):
    name: str

    # Access control.
    accprofile: str | None = None
    accprofile_override: str | None = None

    # Administrator VDOM access.
    vdoms: list[str] = Field(default_factory=list)

    # Trusted hosts.
    trusthosts: list[str] = Field(default_factory=list)
    ip6_trusthosts: list[str] = Field(default_factory=list)

    # Two-factor.
    two_factor: str | None = None
    two_factor_authentication: str | None = None
    two_factor_notification: str | None = None

    fortitoken: str | None = None
    email_to: str | None = None
    sms_phone: str | None = None
    sms_server: str | None = None
    sms_custom_server: str | None = None

    # Remote / certificate authentication.
    remote_auth: str | None = None
    remote_group: str | None = None

    peer_auth: str | None = None
    peer_group: str | None = None

    ssh_certificate: str | None = None

    # Guest administration.
    guest_auth: str | None = None
    guest_usergroups: list[str] = Field(default_factory=list)

    # Login restriction.
    schedule: str | None = None

    # Credential presence only.
    password_configured: bool = False
    ssh_key_configured: bool = False

    comments: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGAdminProfile(BaseModel):
    name: str

    # Main permission groups.
    authgrp: str | None = None
    ftviewgrp: str | None = None
    fwgrp: str | None = None
    loggrp: str | None = None
    netgrp: str | None = None
    secfabgrp: str | None = None
    sysgrp: str | None = None
    utmgrp: str | None = None
    vpngrp: str | None = None
    wanoptgrp: str | None = None
    wifi: str | None = None

    scope: str | None = None

    # CLI permissions.
    cli_config: str | None = None
    cli_diagnose: str | None = None
    cli_exec: str | None = None
    cli_get: str | None = None
    cli_show: str | None = None

    system_execute_ssh: str | None = None
    system_execute_telnet: str | None = None

    # Timeout override.
    admintimeout_override: str | None = None
    admintimeout: int | None = None

    comments: str | None = None

    # Nested custom permission blocks.
    firewall_permission: FGAdminFirewallPermission | None = None
    log_permission: FGAdminLogPermission | None = None
    network_permission: FGAdminNetworkPermission | None = None
    system_permission: FGAdminSystemPermission | None = None
    utm_permission: FGAdminUTMPermission | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)