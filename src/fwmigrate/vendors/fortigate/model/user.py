from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FGLocalUser(BaseModel):
    name: str
    vdom: str = "root"

    # Explicit FortiOS field, not edit identity.
    id: int | None = None

    status: str | None = None
    type: str | None = None

    # Authentication/session behavior.
    auth_concurrent_override: str | None = None
    auth_concurrent_value: int | None = None
    authtimeout: int | None = None

    # Credential metadata.
    passwd_time: str | None = None
    passwd_policy: str | None = None

    ppk_identity: str | None = None
    qkd_profile: str | None = None

    # External authentication references.
    ldap_server: str | None = None
    radius_server: str | None = None
    tacacs_server: str | None = None

    # Two-factor.
    two_factor: str | None = None
    two_factor_authentication: str | None = None
    two_factor_notification: str | None = None

    fortitoken: str | None = None
    email_to: str | None = None

    sms_phone: str | None = None
    sms_server: str | None = None
    sms_custom_server: str | None = None

    workstation: str | None = None
    username_sensitivity: str | None = None

    # Secret presence only.
    password_configured: bool = False
    ppk_secret_configured: bool = False

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGUserGroupMatch(BaseModel):
    # Structural `edit <id>`.
    id: int | None = None

    server_name: str | None = None
    group_name: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGUserGroupGuest(BaseModel):
    # Structural `edit <id>`.
    id: int | None = None

    name: str | None = None
    user_id: str | None = None

    email: str | None = None
    mobile_phone: str | None = None

    expiration: str | None = None
    sponsor: str | None = None
    comment: str | None = None

    password_configured: bool = False

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGUserGroup(BaseModel):
    name: str
    vdom: str = "root"

    # Explicit `set id`.
    id: int | None = None

    group_type: str | None = None

    # Direct FortiGate references.
    members: list[str] = Field(default_factory=list)

    # Remote authentication matches.
    matches: list[FGUserGroupMatch] = Field(default_factory=list)

    # Guest users.
    guests: list[FGUserGroupGuest] = Field(default_factory=list)

    authtimeout: int | None = None
    auth_concurrent_override: str | None = None
    auth_concurrent_value: int | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)