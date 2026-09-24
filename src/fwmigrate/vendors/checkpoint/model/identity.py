from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPUser(CheckPointSourceObject):
    identity_type: str | None = None
    authentication_method: str | None = None
    authentication_settings: dict | None = None
    email: str | None = None
    phone: str | None = None
    groups: list[CheckPointObjectReference | str] = Field(default_factory=list)
    directory: CheckPointObjectReference | str | None = None
    machines: list[CheckPointObjectReference | str] = Field(default_factory=list)


class CPUserGroup(CheckPointSourceObject):
    members: list[CheckPointObjectReference | str] = Field(default_factory=list)
    users: list[CheckPointObjectReference | str] = Field(default_factory=list)
    directory: CheckPointObjectReference | str | None = None


class CPAccessRole(CheckPointSourceObject):
    networks: list[CheckPointObjectReference | str] = Field(default_factory=list)
    users: list[CheckPointObjectReference | str] = Field(default_factory=list)
    groups: list[CheckPointObjectReference | str] = Field(default_factory=list)
    machines: list[CheckPointObjectReference | str] = Field(default_factory=list)
    remote_access_client_selectors: list[CheckPointObjectReference | str] = Field(default_factory=list)
    directory: CheckPointObjectReference | str | None = None


CPIdentityObject = CPUser


__all__ = ["CPAccessRole", "CPIdentityObject", "CPUser", "CPUserGroup"]
