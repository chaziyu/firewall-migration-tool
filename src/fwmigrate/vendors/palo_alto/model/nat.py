from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..source_model import PANScope


class PANDNSRewrite(BaseModel):
    enabled: str | None = None
    direction: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANDynamicIPAndPortTranslation(BaseModel):
    translation_type: str | None = None
    translated_addresses: list[str] | None = None
    interface: str | None = None
    ip: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANDynamicIPTranslation(BaseModel):
    translation_type: str | None = None
    translated_addresses: list[str] | None = None
    interface: str | None = None
    ip: str | None = None
    fallback: dict[str, Any] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANStaticIPTranslation(BaseModel):
    translation_type: str | None = None
    translated_address: str | None = None
    bi_directional: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANDestinationTranslation(BaseModel):
    translated_address: str | None = None
    translated_port: str | None = None
    dns_rewrite: PANDNSRewrite | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANDynamicDestinationTranslation(BaseModel):
    translated_addresses: list[str] | None = None
    translated_port: str | None = None
    distribution: str | None = None
    dns_rewrite: PANDNSRewrite | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANNATRule(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None
    rulebase_position: str | None = None
    from_zones: list[str] | None = None
    to_zones: list[str] | None = None
    source: list[str] | None = None
    destination: list[str] | None = None
    service: str | None = None
    disabled: str | None = None
    active_active_device_binding: str | None = None
    nat_type: str | None = None
    to_interface: str | None = None
    tags: list[str] | None = None
    description: str | None = None
    source_translation: PANDynamicIPAndPortTranslation | PANDynamicIPTranslation | PANStaticIPTranslation | None = None
    destination_translation: PANDestinationTranslation | None = None
    dynamic_destination_translation: PANDynamicDestinationTranslation | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
