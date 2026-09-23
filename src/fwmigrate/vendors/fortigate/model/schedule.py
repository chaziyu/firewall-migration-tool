from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FGScheduleGroup(BaseModel):
    name: str
    vdom: str = "root"
    members: list[str] = Field(default_factory=list)
    color: int | None = None
    fabric_object: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGOneTimeSchedule(BaseModel):
    name: str
    vdom: str = "root"
    start: str | None = None
    end: str | None = None
    start_utc: str | None = None
    end_utc: str | None = None
    expiration_days: int | None = None
    color: int | None = None
    fabric_object: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)


class FGRecurringSchedule(BaseModel):
    name: str
    vdom: str = "root"
    days: list[str] = Field(default_factory=list)
    start: str | None = None
    end: str | None = None
    color: int | None = None
    fabric_object: str | None = None
    raw_extra: dict[str, Any] = Field(default_factory=dict)
    explicit_fields: set[str] = Field(default_factory=set)
