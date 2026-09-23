"""FortiGate schedule planning for Palo Alto."""

from typing import Any

from .models import PANMigrationStatus, PlannedSchedule


def plan_schedules(source: Any):
    result = []
    for item in getattr(source, "recurring_schedules", ()):
        value = f"{','.join(item.days)} {item.start or ''}-{item.end or ''}".strip()
        result.append(PlannedSchedule(
            source_vdom=item.vdom, source_kind="recurring_schedule", source_object_type="schedule",
            source_name=item.name, status=PANMigrationStatus.SUPPORTED,
            schedule_type="recurring", value=value,
        ))
    for item in getattr(source, "one_time_schedules", ()):
        value = f"{item.start or ''}-{item.end or ''}".strip("-")
        result.append(PlannedSchedule(
            source_vdom=item.vdom, source_kind="one_time_schedule", source_object_type="schedule",
            source_name=item.name, status=PANMigrationStatus.SUPPORTED,
            schedule_type="one-time", value=value,
        ))
    for item in getattr(source, "schedule_groups", ()):
        result.append(PlannedSchedule(
            source_vdom=item.vdom, source_kind="schedule_group", source_object_type="schedule",
            source_name=item.name, status=PANMigrationStatus.MANUAL_REVIEW,
            warnings=("FortiGate schedule groups require manual review",),
            schedule_type="group", value=",".join(item.members),
        ))
    return tuple(result)
