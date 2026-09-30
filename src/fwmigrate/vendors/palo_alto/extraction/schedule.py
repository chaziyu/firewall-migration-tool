from __future__ import annotations

import xml.etree.ElementTree as ET

from ..model import PANSchedule, PANScheduleRecurring
from ..schema_registry import PANPathSpec
from ..source_context import PANWalkContext
from .common import source_fields, typed_fields, value, values


def _recurring(element: ET.Element | None) -> PANScheduleRecurring | None:
    if element is None:
        return None
    weekly_node = element.find("weekly")
    weekly = {day.tag: values(weekly_node, day.tag) or [] for day in weekly_node} if weekly_node is not None else None
    extra, explicit = typed_fields(element, {"daily", "weekly"})
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
