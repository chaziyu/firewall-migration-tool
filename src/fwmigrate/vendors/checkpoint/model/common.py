"""Small shared primitives for Check Point source-owned models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CheckPointObjectReference(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    uid: str | None = None
    name: str | None = None
    object_type: str | None = Field(default=None, alias="type")


class ManagementDomain(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    domain: str | None = None
    domain_uid: str | None = None


class CheckPointSourceObject(ManagementDomain):
    """Explicit Check Point source state shared by typed objects."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    uid: str | None = None
    name: str | None = None
    object_type: str | None = Field(default=None, alias="type")
    source_plane: str | None = None
    command: str | None = None
    package: str | None = None
    package_uid: str | None = None
    layer: str | None = None
    layer_uid: str | None = None
    parent_layer_uid: str | None = None
    parent_rule_uid: str | None = None
    gateway: str | None = None
    order: int | None = None
    comments: str | None = None
    tags: list[str] = Field(default_factory=list)
    color: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: tuple[str, ...] = ()


__all__ = ["CheckPointObjectReference", "CheckPointSourceObject", "ManagementDomain"]
