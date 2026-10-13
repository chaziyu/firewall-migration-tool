from __future__ import annotations

from .common import PANNamedSourceModel, PANNestedSourceModel


class PANAdminRolePermission(PANNestedSourceModel):
    channel: str | None = None
    permission_path: str | None = None
    setting: str | None = None
    value: str | None = None


class PANAdminRole(PANNamedSourceModel):
    role_scope: str | None = None
    permissions: list[PANAdminRolePermission] | None = None


class PANAdministrator(PANNamedSourceModel):
    role_type: str | None = None
    built_in_role: str | None = None
    custom_admin_role: str | None = None
    authentication_profile: str | None = None
    password_configured: bool | None = None
