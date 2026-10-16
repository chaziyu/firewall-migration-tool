from __future__ import annotations


from .common import CheckPointObjectReference, CheckPointSourceObject


class CPTime(CheckPointSourceObject):
    hours_ranges: list[dict] | None = None
    recurrence: dict | None = None


class CPTimeGroup(CheckPointSourceObject):
    members: list[CheckPointObjectReference | str] | None = None

__all__ = ["CPTime", "CPTimeGroup"]
