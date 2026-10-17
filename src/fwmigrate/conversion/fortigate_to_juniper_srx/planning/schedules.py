"""FortiGate schedules represented by Junos security schedulers."""

from datetime import datetime, timedelta, timezone as dt_timezone
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..models import SRXPlanItem
from .naming import item_key, target_name


_DAYS = ("sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday")
_RECURRING_CHECK_START = datetime(2026, 1, 1, 12)


def _item(vdom, name, settings=(), blockers=(), order=0):
    return SRXPlanItem(
        key=item_key(vdom, "schedule", name),
        family="schedule",
        source_vdom=vdom,
        source_name=name,
        target_name=target_name("schedule", vdom, name),
        settings=tuple(settings),
        blockers=tuple(dict.fromkeys(blockers)),
        source_order=order,
    )


def _clock(value):
    return bool(value and re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value))


def _timezone(value):
    try:
        return ZoneInfo(value) if value else None
    except (ValueError, ZoneInfoNotFoundError):
        return None


def _crosses_offset_change(start, end, timezone):
    current = start
    previous_offset = current.replace(tzinfo=timezone).utcoffset()
    while current < end:
        current = min(current + timedelta(days=1), end)
        offset = current.replace(tzinfo=timezone).utcoffset()
        if offset != previous_offset:
            return True
        previous_offset = offset
    return False


def _local_time_is_unambiguous(value, timezone):
    offsets = set()
    for fold in (0, 1):
        local = value.replace(tzinfo=timezone, fold=fold)
        round_trip = local.astimezone(dt_timezone.utc).astimezone(timezone)
        if round_trip.replace(tzinfo=None) == value:
            offsets.add(local.utcoffset())
    return len(offsets) == 1


def plan_schedules(source, options, vdom):
    items = []
    timezone = _timezone(options.timezone)
    for order, schedule in enumerate(source.recurring_schedules):
        if schedule.vdom != vdom:
            continue
        blockers = []
        if not {"days", "start", "end"} <= schedule.explicit_fields or not schedule.days:
            blockers.append("RECURRING_SCHEDULE_FIELDS_NOT_EXPLICIT")
        if schedule.raw_extra or schedule.fabric_object:
            blockers.append("RECURRING_SCHEDULE_HAS_UNSUPPORTED_SETTINGS")
        days = tuple(day.lower() for day in schedule.days)
        if len(set(days)) != len(days) or any(day not in _DAYS for day in days):
            blockers.append("RECURRING_SCHEDULE_DAYS_INVALID")
        if not _clock(schedule.start) or not _clock(schedule.end) or schedule.start >= schedule.end:
            blockers.append("RECURRING_SCHEDULE_INTERVAL_INVALID_OR_OVERNIGHT")
        if not options.timezone:
            blockers.append("SCHEDULE_TIMEZONE_CONFIRMATION_REQUIRED")
        elif timezone is None:
            blockers.append("SCHEDULE_TIMEZONE_RULES_UNAVAILABLE")
        # shortcut: recurring DST is screened over one fixed year; extend the window if the supported baseline changes.
        elif not blockers and _crosses_offset_change(
            _RECURRING_CHECK_START, _RECURRING_CHECK_START + timedelta(days=366), timezone,
        ):
            blockers.append("RECURRING_SCHEDULE_DST_NOT_VERIFIED")
        settings = ()
        if not blockers:
            settings = (("days", days), ("start", schedule.start), ("end", schedule.end))
        items.append(_item(vdom, schedule.name, settings, blockers, order))

    for order, schedule in enumerate(source.one_time_schedules, start=len(items)):
        if schedule.vdom != vdom:
            continue
        blockers = []
        start_text, end_text = schedule.start or "", schedule.end or ""
        if not {"start", "end"} <= schedule.explicit_fields:
            blockers.append("ONE_TIME_SCHEDULE_FIELDS_NOT_EXPLICIT")
        if schedule.raw_extra or schedule.fabric_object or schedule.expiration_days is not None:
            blockers.append("ONE_TIME_SCHEDULE_HAS_UNSUPPORTED_SETTINGS")
        try:
            start = datetime.strptime(start_text, "%Y/%m/%d %H:%M")
            end = datetime.strptime(end_text, "%Y/%m/%d %H:%M")
            if start >= end:
                raise ValueError
        except ValueError:
            start = end = None
            blockers.append("ONE_TIME_SCHEDULE_INTERVAL_INVALID")
        if not options.timezone:
            blockers.append("SCHEDULE_TIMEZONE_CONFIRMATION_REQUIRED")
        elif timezone is None:
            blockers.append("SCHEDULE_TIMEZONE_RULES_UNAVAILABLE")
        elif start is not None and end is not None:
            if (not _local_time_is_unambiguous(start, timezone)
                    or not _local_time_is_unambiguous(end, timezone)
                    or _crosses_offset_change(start, end, timezone)):
                blockers.append("ONE_TIME_SCHEDULE_DST_NOT_VERIFIED")
        settings = ()
        if start is not None and end is not None and not blockers:
            settings = (("start", start.strftime("%Y-%m-%d.%H.%M")),
                        ("end", end.strftime("%Y-%m-%d.%H.%M")))
        items.append(_item(vdom, schedule.name, settings, blockers, order))

    for order, schedule in enumerate(source.schedule_groups, start=len(items)):
        if schedule.vdom != vdom:
            continue
        items.append(_item(vdom, schedule.name, blockers=("SCHEDULE_GROUP_UNSUPPORTED",), order=order))
    return items
