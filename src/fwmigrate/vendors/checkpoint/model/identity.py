from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPUser(CheckPointSourceObject):
    identity_type: str | None = None
    authentication_method: str | None = None
    authentication_settings: dict | None = None
    email: str | None = None
    phone: str | None = None
    groups: list[CheckPointObjectReference | str] | None = None
    directory: CheckPointObjectReference | str | None = None
    machines: list[CheckPointObjectReference | str] | None = None


class CPUserGroup(CheckPointSourceObject):
    members: list[CheckPointObjectReference | str] | None = None
    users: list[CheckPointObjectReference | str] | None = None
    directory: CheckPointObjectReference | str | None = None


class CPAccessRole(CheckPointSourceObject):
    networks: list[CheckPointObjectReference | str] | None = None
    users: list[CheckPointObjectReference | str] | None = None
    groups: list[CheckPointObjectReference | str] | None = None
    machines: list[CheckPointObjectReference | str] | None = None
    remote_access_client_selectors: list[CheckPointObjectReference | str] | None = None
    directory: CheckPointObjectReference | str | None = None


__all__ = ["CPAccessRole", "CPUser", "CPUserGroup"]
