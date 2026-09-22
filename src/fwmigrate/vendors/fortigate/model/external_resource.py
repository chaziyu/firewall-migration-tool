# model/external_resource.py

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FGExternalResource(BaseModel):
    name: str
    vdom: str = "root"

    resource: str | None = None
    type: str | None = None
    comments: str | None = None
    refresh_rate: int | None = None

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)