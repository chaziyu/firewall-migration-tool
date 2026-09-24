from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FGZoneTaggingEntry(BaseModel):
    name: str

    category: str | None = None
    tags: list[str] = Field(default_factory=list)

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGZone(BaseModel):
    name: str
    vdom: str = "root"

    description: str | None = None

    # Direct FortiGate relationship:
    # system zone.interface → interface names
    members: list[str] = Field(default_factory=list)

    intrazone: str | None = None

    tagging: list[FGZoneTaggingEntry] = Field(
        default_factory=list
    )

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)