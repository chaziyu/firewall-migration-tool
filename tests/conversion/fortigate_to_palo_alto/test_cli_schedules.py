from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedSchedule,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer


def test_weekly_and_one_time_schedule_commands():
    plan = PANMigrationPlan(schedules=(
        PlannedSchedule(source_object_type="schedule", source_name="work", target_vsys="vsys1",
                        status=PANMigrationStatus.SUPPORTED, schedule_type="recurring",
                        weekly=(("monday", "08:00", "17:00"), ("friday", "08:30", "16:00"))),
        PlannedSchedule(source_object_type="schedule", source_name="holiday", target_vsys="vsys1",
                        status=PANMigrationStatus.SUPPORTED, schedule_type="one-time",
                        non_recurring=(("2026/12/25@00:00", "2026/12/26@00:00"),)),
    ))

    assert PANSetRenderer().render(plan).commands == (
        "set system setting target-vsys vsys1",
        "set schedule work schedule-type recurring",
        "set schedule work schedule-type recurring weekly monday [ 08:00-17:00 ]",
        "set schedule work schedule-type recurring weekly friday [ 08:30-16:00 ]",
        "set schedule holiday schedule-type non-recurring [ 2026/12/25@00:00-2026/12/26@00:00 ]",
    )
