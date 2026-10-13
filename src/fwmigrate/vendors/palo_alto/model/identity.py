from __future__ import annotations

from .common import PANNamedSourceModel


class PANLocalUser(PANNamedSourceModel):
    disabled: str | None = None
    password_configured: bool | None = None


class PANLocalUserGroup(PANNamedSourceModel):
    members: list[str] | None = None


class PANGroupMapping(PANNamedSourceModel):
    server_profile: str | None = None
    disabled: str | None = None
    ldap_serial_number_check: str | None = None
    use_modify_timestamp: str | None = None
    limited_group_search: str | None = None
    nested_group_level: str | None = None
    group_object_attributes: list[str] | None = None
    group_member_attributes: list[str] | None = None
    group_name_attributes: list[str] | None = None
    user_object_attributes: list[str] | None = None
    user_name_attributes: list[str] | None = None
    user_email_attributes: list[str] | None = None
    group_email_attributes: list[str] | None = None
    alternate_username_1: str | None = None
    alternate_username_2: str | None = None
    alternate_username_3: str | None = None
    container_object_attributes: list[str] | None = None
    last_modify_attribute: str | None = None
    group_include_list: list[str] | None = None
