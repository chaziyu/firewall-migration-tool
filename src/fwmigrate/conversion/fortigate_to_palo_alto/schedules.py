"""FortiGate schedule planning for Palo Alto."""

from typing import Any

from .models import PANMigrationStatus, PlannedSchedule


def plan_schedules(source: Any, options: Any = None):
    result = []
    for item in getattr(source, "recurring_schedules", ()):
        days = tuple(item.days or ())
        valid = bool(days and item.start and item.end)
        result.append(PlannedSchedule(
            source_vdom=item.vdom, source_kind="recurring_schedule", source_object_type="schedule",
            source_name=item.name, target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None) if options else None, target_name=item.name,
            status=PANMigrationStatus.SUPPORTED if valid else PANMigrationStatus.MANUAL_REVIEW,
            warnings=() if valid else ("recurring schedule is missing days or time range",),
            schedule_type="recurring", weekly=tuple((day, item.start, item.end) for day in days),
        ))
    for item in getattr(source, "one_time_schedules", ()):
        valid = bool(item.start and item.end)
        result.append(PlannedSchedule(
            source_vdom=item.vdom, source_kind="one_time_schedule", source_object_type="schedule",
            source_name=item.name, target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None) if options else None, target_name=item.name,
            status=PANMigrationStatus.SUPPORTED if valid else PANMigrationStatus.MANUAL_REVIEW,
            warnings=() if valid else ("one-time schedule is missing a time range",),
            schedule_type="one-time", non_recurring=((item.start, item.end),) if valid else (),
        ))
    for item in getattr(source, "schedule_groups", ()):
        result.append(PlannedSchedule(
            source_vdom=item.vdom, source_kind="schedule_group", source_object_type="schedule",
            source_name=item.name, target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None) if options else None, target_name=item.name, status=PANMigrationStatus.MANUAL_REVIEW,
            warnings=("FortiGate schedule groups require manual review",),
            schedule_type="group",
        ))
    return tuple(result)
