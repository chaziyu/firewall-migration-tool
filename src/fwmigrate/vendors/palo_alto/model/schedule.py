from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..source_model import PANScope


class PANScheduleRecurring(BaseModel):
    daily: list[str] | None = None
    weekly: dict[str, list[str]] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class PANSchedule(BaseModel):
    name: str | None = None
    source_path: str
    scope: PANScope | None = None
    source_order: int | None = None
    recurring: PANScheduleRecurring | None = None
    non_recurring: list[str] | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
