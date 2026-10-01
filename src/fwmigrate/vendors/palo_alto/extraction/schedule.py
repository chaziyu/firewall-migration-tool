from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANSchedule, PANScheduleRecurring
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import raw_extra, source_fields, typed_fields, value, values


_WEEKDAYS = frozenset({
    "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
})


def _recurring(element: ET.Element | None) -> PANScheduleRecurring | None:
    if element is None:
        return None
    weekly_node = element.find("weekly")
    weekly = (
        {
            day.tag: values(weekly_node, day.tag) or []
            for day in weekly_node
            if day.tag in _WEEKDAYS
        }
        if weekly_node is not None
        else None
    )
    extra, explicit = typed_fields(element, {"daily", "weekly"})
    if weekly_node is not None:
        weekly_extra = raw_extra(weekly_node, set(_WEEKDAYS))
        for day in weekly_node:
            if day.tag not in _WEEKDAYS:
                continue
            day_extra = raw_extra(day, {"member"})
            if day_extra:
                weekly_extra[day.tag] = day_extra
        if weekly_extra:
            extra["weekly"] = weekly_extra
    return PANScheduleRecurring(daily=values(element, "daily"), weekly=weekly, raw_extra=extra, explicit_fields=explicit)


def extract_schedule(element: ET.Element, path: tuple[str, ...], context: PANWalkContext, source_order: int, spec: PANPathSpec) -> object | None:
    extra, explicit = source_fields(element, spec)
    node = element.find("schedule-type")
    recurring = node.find("recurring") if node is not None else None
    non_recurring = node.find("non-recurring") if node is not None else None
    explicit.discard("recurring")
    if recurring is not None:
        explicit.add("recurring")
    if non_recurring is not None:
        explicit.add("non_recurring")
    return PANSchedule(
        name=element.get("name"),
        source_path="/".join(path),
        scope=context.scope,
        source_order=source_order,
        recurring=_recurring(recurring),
        non_recurring=values(node, "non-recurring"),
        raw_extra=extra,
        explicit_fields=explicit,
    )
