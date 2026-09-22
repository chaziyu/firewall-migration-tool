from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..source_model import PANScope


class PANServiceOverride(BaseModel):
    timeout: str | None = None
    halfclose_timeout: str | None = None
    timewait_timeout: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANServiceProtocol(BaseModel):
    port: str | None = None
    source_port: str | None = None
    override: PANServiceOverride | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANService(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None
    tcp: PANServiceProtocol | None = None
    udp: PANServiceProtocol | None = None
    description: str | None = None
    tags: list[str] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANServiceGroup(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None
    members: list[str] | None = None
    description: str | None = None
    tags: list[str] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
