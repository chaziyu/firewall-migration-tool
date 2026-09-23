from __future__ import annotations

from pydantic import Field

from .common import CheckPointObjectReference, CheckPointSourceObject


class CPTime(CheckPointSourceObject):
    hours_ranges: list[dict] = Field(default_factory=list)
    recurrence: dict | None = None


class CPTimeGroup(CheckPointSourceObject):
    members: list[CheckPointObjectReference | str] = Field(default_factory=list)


CPSchedule = CPTime

__all__ = ["CPTime", "CPTimeGroup", "CPSchedule"]
