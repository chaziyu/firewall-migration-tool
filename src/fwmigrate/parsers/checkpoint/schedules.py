"""Check Point time objects and time groups extraction."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from fwmigrate.extraction.models import (
    ExtractionStatus,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.ir.core import IRSchedule
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import (
    CheckPointObjectResolver,
    SemanticKind,
)


def extract_time_objects(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
) -> Tuple[List[IRSchedule], List[SourceInventoryItem], List[UnsupportedItem]]:
    """Extract Check Point time objects and time groups into canonical IRSchedule."""
    schedules: List[IRSchedule] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []

    for resp in responses:
        cmd = canonicalize_command(resp.command)
        if cmd not in ("show-times", "show-time-groups", "show-objects"):
            continue

        data = resp.data
        domain = resp.domain or "global"
        objects = data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())

        for obj_index, obj in enumerate(objects):
            if not isinstance(obj, dict):
                if cmd == "show-objects":
                    continue
                inventory_items.append(SourceInventoryItem(
                    domain=domain, source_path=f"checkpoint/{cmd}",
                    name=f"<malformed-time:{obj_index}>", source_type="malformed-time",
                    source_attributes={"raw_value": str(obj)}, status=ExtractionStatus.PARSE_ERROR,
                    requires_manual_review=True, notes=["malformed-non-dict-time-object"],
                ))
                continue

            uid = obj.get("uid")
            source_name = obj.get("name")
            name = source_name or f"<unnamed:{uid or obj_index}>"
            obj_type = obj.get("type", "").strip().lower()
            if cmd == "show-objects" and obj_type not in {"time", "time-group"}:
                continue
            src_path = f"checkpoint/{cmd}"
            status = ExtractionStatus.UNSUPPORTED
            requires_review = True
            notes: List[str] = []

            if not source_name:
                status = ExtractionStatus.PARSE_ERROR
                notes.append("missing-time-object-name")
                resolver.set_object_normalization(
                    uid_or_name=uid or name, canonical_name=None, status=status,
                    requires_manual_review=True, usable=False,
                    semantic_kind=SemanticKind.TIME_GROUP if obj_type == "time-group" else SemanticKind.TIME,
                )

            elif obj_type == "time" or cmd == "show-times":
                status = ExtractionStatus.NORMALIZED
                requires_review = False
                start_time = obj.get("start-time") or obj.get("start_time")
                end_time = obj.get("end-time") or obj.get("end_time")
                start_date = obj.get("start-date") or obj.get("start_date")
                end_date = obj.get("end-date") or obj.get("end_date")
                recurrence = obj.get("recurrence", "daily")
                days_raw = obj.get("days") or obj.get("days-of-week") or []
                days = days_raw if isinstance(days_raw, list) else [str(days_raw)]
                recurrence_value = str(recurrence).lower()
                time_pattern = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
                fidelity_reasons: List[str] = []
                if start_time and not time_pattern.match(str(start_time)):
                    fidelity_reasons.append("invalid-start-time")
                if end_time and not time_pattern.match(str(end_time)):
                    fidelity_reasons.append("invalid-end-time")
                if bool(start_time) != bool(end_time):
                    fidelity_reasons.append("incomplete-time-window")
                if recurrence_value not in {"daily", "weekly"}:
                    fidelity_reasons.append(f"unsupported-recurrence:{recurrence_value}")
                if recurrence_value == "weekly" and not days:
                    fidelity_reasons.append("weekly-schedule-missing-days")
                if start_date or end_date:
                    fidelity_reasons.append("date-constrained-schedule")
                if any(key in obj for key in ("timezone", "time-zone", "holidays", "month", "day-of-month")):
                    fidelity_reasons.append("unmodeled-schedule-constraint")

                if fidelity_reasons:
                    status = ExtractionStatus.PARTIALLY_NORMALIZED
                    requires_review = True
                    notes.extend(fidelity_reasons)
                else:
                    schedules.append(IRSchedule(
                        name=name, start=start_time, end=end_time, days=days,
                        schedule_type=recurrence_value, source_attributes=obj,
                    ))

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=requires_review,
                    usable=(status == ExtractionStatus.NORMALIZED),
                    semantic_kind=SemanticKind.TIME,
                )

            elif obj_type == "time-group" or cmd == "show-time-groups":
                members = obj.get("members", [])
                status = ExtractionStatus.PARTIALLY_NORMALIZED
                requires_review = True
                notes.append("Time groups require policy decomposition in target conversion")
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path,
                    source_name=name,
                    reason="Check Point time-group requires rule expansion",
                    requires_manual_review=True,
                    raw_capture=str(obj),
                ))

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=True,
                    usable=False,
                    semantic_kind=SemanticKind.TIME_GROUP,
                )

            else:
                reason = f"Unhandled Check Point time object type '{obj_type or '<missing>'}'"
                notes.append(reason)
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path, source_name=name, reason=reason,
                    requires_manual_review=True, raw_capture=str(obj),
                ))

            inventory_items.append(SourceInventoryItem(
                domain=domain,
                source_path=src_path,
                name=name,
                source_id=uid,
                source_type=obj_type,
                source_attributes=obj,
                status=status,
                requires_manual_review=requires_review,
                notes=notes,
            ))

    return schedules, inventory_items, unsupported_items
