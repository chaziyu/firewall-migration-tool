from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPManagementAccess(CheckPointSourceObject):
    access: list[str] | None = None


class CPPermissionProfile(CheckPointSourceObject):
    permissions: list[str] = Field(default_factory=list)


class CPAdministrator(CheckPointSourceObject):
    authentication_method: str | None = None
    permission_profiles: list[CheckPointObjectReference | str] = Field(default_factory=list)
    domains: list[CheckPointObjectReference | str] = Field(default_factory=list)
    email: str | None = None


__all__ = ["CPAdministrator", "CPManagementAccess", "CPPermissionProfile"]
