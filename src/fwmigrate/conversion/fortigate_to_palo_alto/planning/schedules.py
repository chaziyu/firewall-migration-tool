"""FortiGate schedule planning for Palo Alto."""

from typing import Any
from datetime import datetime

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedSchedule
from ....vendors.palo_alto.validation.validator import _validate_schedule_time_range


WEEKDAYS = frozenset(('sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'))


def valid_time_range(start, end):
    return (isinstance(start, str) and isinstance(end, str)
            and _validate_schedule_time_range(f'{start}-{end}') and start < end)


def _one_time_range(start, end):
    try:
        parsed = tuple(datetime.strptime(value, '%H:%M %Y/%m/%d') for value in (start, end))
        if parsed[0] >= parsed[1] or any(value.strftime('%H:%M %Y/%m/%d') != original
                                       for value, original in zip(parsed, (start, end))):
            return ()
    except (TypeError, ValueError):
        return ()
    return (tuple(value.strftime('%Y/%m/%d@%H:%M') for value in parsed),)


def plan_schedules(source: Any, options: Any = None):
    result = []
    for item in getattr(source, "recurring_schedules", ()):
        days = tuple(item.days or ())
        warnings = []
        if not days or not set(days) <= WEEKDAYS or not valid_time_range(item.start, item.end):
            warnings.append('recurring schedule requires explicit weekdays and a supported same-day time range')
        if item.raw_extra:
            warnings.append('schedule contains preserved unsupported source settings')
        result.append(PlannedSchedule(
            source_vdom=item.vdom, source_kind="recurring_schedule", source_object_type="schedule",
            source_name=item.name, target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None) if options else None, target_name=item.name,
            status=PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW,
            warnings=tuple(warnings),
            schedule_type="recurring", weekly=tuple((day, item.start, item.end) for day in days),
        ))
    for item in getattr(source, "one_time_schedules", ()):
        ranges = _one_time_range(item.start, item.end)
        warnings = []
        if not ranges:
            warnings.append('one-time schedule requires an ordered FortiGate HH:MM YYYY/MM/DD range')
        if item.raw_extra or item.start_utc is not None or item.end_utc is not None:
            warnings.append('schedule contains preserved unsupported source settings or UTC controls')
        if item.expiration_days is not None:
            warnings.append('one-time schedule expiration-days event-log notification requires manual monitoring review')
        result.append(PlannedSchedule(
            source_vdom=item.vdom, source_kind="one_time_schedule", source_object_type="schedule",
            source_name=item.name, target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None) if options else None, target_name=item.name,
            status=PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW,
            warnings=tuple(warnings),
            schedule_type="one-time", non_recurring=ranges,
        ))
    for item in getattr(source, "schedule_groups", ()):
        result.append(PlannedSchedule(
            source_vdom=item.vdom, source_kind="schedule_group", source_object_type="schedule",
            source_name=item.name, target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None) if options else None, target_name=item.name, status=PANMigrationStatus.MANUAL_REVIEW,
            warnings=("FortiGate schedule groups require manual review",),
            schedule_type="group",
        ))
    return tuple(result)
