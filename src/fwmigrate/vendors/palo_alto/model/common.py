from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..source_model import PANScope


class PANNestedSourceModel(BaseModel):
    """Explicit PAN-OS state nested below a named source object."""

    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANNamedSourceModel(PANNestedSourceModel):
    """Common source identity retained by named PAN-OS objects."""

    name: str | None = None
    source_path: str = ""
    scope: PANScope | None = None
    source_order: int | None = None
