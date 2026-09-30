from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPManagementAccess(CheckPointSourceObject):
    access: list[str] | None = None


class CPPermissionProfile(CheckPointSourceObject):
    permissions: list[str] | None = None


class CPAdministrator(CheckPointSourceObject):
    authentication_method: str | None = None
    permission_profiles: list[CheckPointObjectReference | str] | None = None
    domains: list[CheckPointObjectReference | str] | None = None
    email: str | None = None


__all__ = ["CPAdministrator", "CPManagementAccess", "CPPermissionProfile"]
