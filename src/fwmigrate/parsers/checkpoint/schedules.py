"""Check Point R81 Time objects and time-group extraction."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from fwmigrate.extraction.models import ExtractionStatus, SourceInventoryItem, UnsupportedItem
from fwmigrate.ir.core import IRSchedule
from fwmigrate.parsers.checkpoint.loader import canonicalize_command
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver, SemanticKind

_TIME_RE = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")


def parse_time_endpoint(raw: Any, field_name: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Validate an R81 start/end endpoint while retaining every native representation."""
    if raw is None:
        return None, []
    if not isinstance(raw, dict):
        return None, [f"malformed-{field_name}-endpoint"]
    preserved = dict(raw)
    reasons: List[str] = []
    if raw.get("time") is not None and not _TIME_RE.fullmatch(str(raw.get("time"))):
        reasons.append(f"invalid-{field_name}-time")
    for key in ("date", "iso-8601", "posix"):
        if key in raw and raw.get(key) not in (None, ""):
            reasons.append(f"absolute-{field_name}-{key}")
    if not any(key in raw for key in ("date", "time", "iso-8601", "posix")):
        reasons.append(f"empty-{field_name}-endpoint")
    return preserved, reasons


def parse_hours_ranges(raw: Any) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse native hours-ranges without dropping disabled or indexed windows."""
    if raw is None:
        return [], ["missing-hours-ranges"]
    if not isinstance(raw, list):
        return [], ["malformed-hours-ranges"]
    ranges: List[Dict[str, Any]] = []
    reasons: List[str] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            reasons.append(f"malformed-hours-range:{index}")
            continue
        preserved = dict(item)
        ranges.append(preserved)
        enabled = item.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            reasons.append(f"invalid-hours-range-enabled:{index}")
        for key in ("from", "to"):
            if item.get(key) is None or not _TIME_RE.fullmatch(str(item.get(key))):
                reasons.append(f"invalid-hours-range-{key}:{index}")
    enabled_ranges = [item for item in ranges if item.get("enabled", True) is True]
    if len(enabled_ranges) != 1:
        reasons.append("multiple-hours-ranges" if len(enabled_ranges) > 1 else "no-enabled-hours-range")
    return ranges, reasons


def classify_time_fidelity(obj: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Return an exact canonical window only when IRSchedule can preserve the semantics."""
    reasons: List[str] = []
    start, endpoint_reasons = parse_time_endpoint(obj.get("start"), "start")
    reasons.extend(endpoint_reasons)
    end, endpoint_reasons = parse_time_endpoint(obj.get("end"), "end")
    reasons.extend(endpoint_reasons)

    if obj.get("start-now") is True or obj.get("start_now") is True:
        reasons.append("start-now-constraint")
    if obj.get("end-never") is True or obj.get("end_never") is True:
        reasons.append("end-never-constraint")
    if start is not None or end is not None:
        reasons.append("absolute-date-bounds")

    ranges, range_reasons = parse_hours_ranges(obj.get("hours-ranges"))
    reasons.extend(range_reasons)
    recurrence = obj.get("recurrence")
    if not isinstance(recurrence, dict):
        reasons.append("missing-or-malformed-recurrence")
        pattern = None
        weekdays: List[str] = []
    else:
        pattern = str(recurrence.get("pattern") or "").strip().lower()
        weekdays_raw = recurrence.get("weekdays")
        weekdays = list(weekdays_raw) if isinstance(weekdays_raw, list) else []
        if pattern not in {"daily", "weekly"}:
            reasons.append(f"unsupported-recurrence:{pattern or '<missing>'}")
        if pattern == "weekly" and not weekdays:
            reasons.append("weekly-schedule-missing-weekdays")
        if recurrence.get("days") not in (None, [], {}) or recurrence.get("month") not in (None, "", [], {}):
            reasons.append("complex-recurrence")

    if any(key in obj for key in ("timezone", "time-zone", "time_zone")):
        reasons.append("timezone-semantics")
    if reasons:
        return None, list(dict.fromkeys(reasons))
    enabled_ranges = [item for item in ranges if item.get("enabled", True) is True]
    window = enabled_ranges[0]
    return {
        "start": str(window["from"]),
        "end": str(window["to"]),
        "days": weekdays if pattern == "weekly" else [],
        "schedule_type": pattern,
    }, []


def _classify_legacy_time(obj: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Retain explicit compatibility for older synthetic fixtures without permissive defaults."""
    start = obj.get("start-time", obj.get("start_time"))
    end = obj.get("end-time", obj.get("end_time"))
    recurrence = obj.get("recurrence")
    days_raw = obj.get("days", obj.get("days-of-week", []))
    days = days_raw if isinstance(days_raw, list) else [str(days_raw)]
    reasons: List[str] = ["legacy-synthetic-time-schema"]
    if start is None or end is None or not _TIME_RE.fullmatch(str(start)) or not _TIME_RE.fullmatch(str(end)):
        reasons.append("invalid-or-incomplete-time-window")
    recurrence_value = str(recurrence or "").lower()
    if recurrence_value not in {"daily", "weekly"}:
        reasons.append(f"unsupported-recurrence:{recurrence_value or '<missing>'}")
    if recurrence_value == "weekly" and not days:
        reasons.append("weekly-schedule-missing-days")
    if any(obj.get(key) not in (None, "") for key in ("start-date", "start_date", "end-date", "end_date")):
        reasons.append("date-constrained-schedule")
    fatal = [reason for reason in reasons if reason != "legacy-synthetic-time-schema"]
    if fatal:
        return None, reasons
    return {"start": str(start), "end": str(end), "days": days, "schedule_type": recurrence_value}, reasons


def extract_time_objects(
    responses: List[CheckPointResponse],
    resolver: CheckPointObjectResolver,
) -> Tuple[List[IRSchedule], List[SourceInventoryItem], List[UnsupportedItem]]:
    schedules: List[IRSchedule] = []
    inventory_items: List[SourceInventoryItem] = []
    unsupported_items: List[UnsupportedItem] = []

    for resp in responses:
        cmd = canonicalize_command(resp.command)
        is_dictionary = cmd.endswith("/objects-dictionary")
        if cmd not in ("show-times", "show-time-groups", "show-objects") and not is_dictionary:
            continue
        objects = resp.data.get("objects", [])
        if isinstance(objects, dict):
            objects = list(objects.values())
        domain = resp.domain or "global"
        for obj_index, obj in enumerate(objects):
            if not isinstance(obj, dict):
                if cmd != "show-objects":
                    inventory_items.append(SourceInventoryItem(
                        domain=domain, source_path=f"checkpoint/{cmd}", name=f"<malformed-time:{obj_index}>",
                        source_type="malformed-time", source_attributes={"raw_value": str(obj)},
                        status=ExtractionStatus.PARSE_ERROR, requires_manual_review=True,
                        notes=["malformed-non-dict-time-object"],
                    ))
                continue
            uid, source_name = obj.get("uid"), obj.get("name")
            name = source_name or f"<unnamed:{uid or obj_index}>"
            obj_type = str(obj.get("type") or "").strip().lower()
            if (cmd == "show-objects" or is_dictionary) and obj_type not in {"time", "time-group"}:
                continue
            src_path = f"checkpoint/{cmd}"
            status, requires_review, notes = ExtractionStatus.UNSUPPORTED, True, []

            if not source_name:
                status, notes = ExtractionStatus.PARSE_ERROR, ["missing-time-object-name"]
            elif obj_type == "time" or cmd == "show-times":
                legacy = "hours-ranges" not in obj and any(key in obj for key in ("start-time", "start_time", "end-time", "end_time"))
                canonical, fidelity_reasons = _classify_legacy_time(obj) if legacy else classify_time_fidelity(obj)
                if canonical is not None:
                    schedules.append(IRSchedule(name=name, source_attributes=dict(obj), **canonical))
                    status = ExtractionStatus.PARTIALLY_NORMALIZED if fidelity_reasons else ExtractionStatus.NORMALIZED
                    requires_review = bool(fidelity_reasons)
                else:
                    status, requires_review = ExtractionStatus.PARTIALLY_NORMALIZED, True
                notes.extend(fidelity_reasons)
                resolver.set_object_normalization(
                    uid_or_name=str(uid or name), canonical_name=name, status=status,
                    requires_manual_review=requires_review, usable=(status == ExtractionStatus.NORMALIZED),
                    semantic_kind=SemanticKind.TIME,
                )
            elif obj_type == "time-group" or cmd == "show-time-groups":
                status, requires_review = ExtractionStatus.PARTIALLY_NORMALIZED, True
                notes.append("time-group-requires-policy-expansion")
                unsupported_items.append(UnsupportedItem(
                    source_path=src_path, source_name=name,
                    reason="Check Point time-group requires rule expansion",
                    requires_manual_review=True, raw_capture=str(obj),
                ))
                resolver.set_object_normalization(
                    uid_or_name=str(uid or name), canonical_name=name, status=status,
                    requires_manual_review=True, usable=False, semantic_kind=SemanticKind.TIME_GROUP,
                )
            else:
                notes.append(f"unhandled-time-object-type:{obj_type or '<missing>'}")

            inventory_items.append(SourceInventoryItem(
                domain=domain, source_path=src_path, name=name, source_id=uid,
                source_type=obj_type, source_attributes=dict(obj), status=status,
                requires_manual_review=requires_review, notes=notes,
            ))
    return schedules, inventory_items, unsupported_items
