"""Source-faithful Check Point inventory evidence."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CheckPointSourceRecord(BaseModel):
    """An unsupported or unmodeled Check Point source object."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    uid: str | None = None
    name: str | None = None
    object_type: str | None = Field(default=None, alias="type")
    source_plane: str | None = None
    command: str | None = None
    domain: str | None = None
    domain_uid: str | None = None
    package: str | None = None
    package_uid: str | None = None
    layer: str | None = None
    layer_uid: str | None = None
    gateway: str | None = None
    order: int | None = None
    values: dict[str, Any] = Field(default_factory=dict)
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: tuple[str, ...] = ()


__all__ = ["CheckPointSourceRecord"]
