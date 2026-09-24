from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..source_model import PANScope


class PANProfileSetting(BaseModel):
    groups: list[str] | None = None
    profiles: dict[str, list[str]] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANSecurityRule(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None
    rulebase_position: str | None = None

    from_zones: list[str] | None = None
    to_zones: list[str] | None = None
    source: list[str] | None = None
    destination: list[str] | None = None
    source_user: list[str] | None = None
    application: list[str] | None = None
    service: list[str] | None = None
    category: list[str] | None = None
    source_hip: list[str] | None = None
    destination_hip: list[str] | None = None

    negate_source: str | None = None
    negate_destination: str | None = None
    schedule: str | None = None

    action: str | None = None
    rule_type: str | None = None
    description: str | None = None

    tags: list[str] | None = None
    group_tag: str | None = None
    log_start: str | None = None
    log_end: str | None = None
    log_setting: str | None = None
    disabled: str | None = None

    profile_setting: PANProfileSetting | None = None

    disable_inspect: str | None = None
    disable_server_response_inspection: str | None = None
    icmp_unreachable: str | None = None
    saas_user_list: list[str] | None = None
    saas_tenant_list: list[str] | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANDefaultSecurityRule(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None
    rulebase_position: str | None = None

    action: str | None = None
    disabled: str | None = None
    log_start: str | None = None
    log_end: str | None = None
    log_setting: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    group_tag: str | None = None
    profile_setting: PANProfileSetting | None = None
    disable_server_response_inspection: str | None = None
    icmp_unreachable: str | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


# Compatibility name for callers that imported the initial generic policy type.
PANPolicy = PANSecurityRule
