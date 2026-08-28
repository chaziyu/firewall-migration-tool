"""Check Point time objects and time groups extraction."""

from __future__ import annotations

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
        if cmd not in ("show-times", "show-time-groups"):
            continue

        data = resp.data
        domain = resp.domain or "global"
        objects = data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())

        for obj in objects:
            if not isinstance(obj, dict):
                continue

            uid = obj.get("uid")
            name = obj.get("name")
            obj_type = obj.get("type", "").strip().lower()
            src_path = f"checkpoint/{cmd}"
            if not name:
                continue

            status = ExtractionStatus.NORMALIZED
            requires_review = False
            notes: List[str] = []

            if obj_type == "time" or cmd == "show-times":
                start_time = obj.get("start-time") or obj.get("start_time")
                end_time = obj.get("end-time") or obj.get("end_time")
                start_date = obj.get("start-date") or obj.get("start_date")
                end_date = obj.get("end-date") or obj.get("end_date")
                recurrence = obj.get("recurrence", "daily")

                schedules.append(IRSchedule(
                    name=name,
                    start=start_time or start_date,
                    end=end_time or end_date,
                    schedule_type=str(recurrence).lower(),
                    source_attributes=obj,
                ))

                resolver.set_object_normalization(
                    uid_or_name=uid or name,
                    canonical_name=name,
                    status=status,
                    requires_manual_review=False,
                    usable=True,
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
