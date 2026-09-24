from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..source_model import PANScope


class PANAddress(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None
    ip_netmask: str | None = None
    ip_range: str | None = None
    ip_wildcard: str | None = None
    fqdn: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANAddressGroup(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None
    static_members: list[str] | None = None
    dynamic_filter: str | None = None
    description: str | None = None
    tags: list[str] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
