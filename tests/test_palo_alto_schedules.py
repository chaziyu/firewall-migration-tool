from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "schedules.xml"


def _extract():
    return PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))


def _schedule(result, name):
    return next(schedule for schedule in result.canonical_ir.schedules if schedule.name == name)


def _records(result, name):
    return [item for item in result.inventory_items if item.domain == "schedules" and item.name == name]


def test_daily_schedule_extracted():
    result = _extract()
    schedule = _schedule(result, "Daily-One")
    assert schedule.start == "08:00"
    assert schedule.end == "17:00"
    assert schedule.days == []
    assert schedule.schedule_type == "recurring"


def test_weekly_schedule_extracted():
    result = _extract()
    schedule = _schedule(result, "Weekly-One")
    assert schedule.days == ["monday"]
    assert schedule.start == "08:00"
    assert schedule.end == "17:00"


def test_non_recurring_schedule_extracted():
    result = _extract()
    schedule = _schedule(result, "Once-One")
    assert schedule.schedule_type == "non-recurring"
    assert schedule.start == "2026/09/01@08:00"
    assert schedule.end == "2026/09/01@17:00"


def test_multiple_daily_windows_not_truncated():
    result = _extract()
    schedule = _schedule(result, "Daily-Multiple")
    windows = schedule.source_attributes["pan_schedule_windows"]["daily"]
    assert [window["raw_value"] for window in windows] == ["08:00-12:00", "13:00-17:00"]
    assert schedule.start is None and schedule.end is None


def test_multiple_weekly_windows_not_truncated():
    result = _extract()
    windows = _schedule(result, "Weekly-Multiple").source_attributes["pan_schedule_windows"]["weekly"]["monday"]
    assert len(windows) == 2


def test_weekly_different_times_not_broadened():
    result = _extract()
    schedule = _schedule(result, "Weekly-Different")
    assert schedule.schedule_type == "source-only"
    assert schedule.start is None and schedule.end is None
    assert _records(result, "Weekly-Different")[0].status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_multiple_non_recurring_ranges_not_truncated():
    result = _extract()
    schedule = _schedule(result, "Once-Multiple")
    assert len(schedule.source_attributes["pan_schedule_windows"]["non_recurring"]) == 2
    assert schedule.schedule_type == "source-only"


def test_invalid_schedule_time_parse_error():
    result = _extract()
    assert all(schedule.name != "Bad-Time" for schedule in result.canonical_ir.schedules)
    assert _records(result, "Bad-Time")[0].status == ExtractionStatus.PARSE_ERROR


def test_invalid_schedule_date_parse_error():
    result = _extract()
    assert all(schedule.name != "Bad-Date" for schedule in result.canonical_ir.schedules)
    assert _records(result, "Bad-Date")[0].status == ExtractionStatus.PARSE_ERROR


def test_schedule_unknown_field_partial():
    result = _extract()
    schedule = _schedule(result, "Unknown-Schedule")
    assert schedule.source_attributes["pan_unknown_fields"] == {"future-setting": "retain-me"}
    assert _records(result, "Unknown-Schedule")[0].status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_schedule_scope_collision_deterministic():
    result = _extract()
    by_start = {schedule.start: schedule.name for schedule in result.canonical_ir.schedules if schedule.name.endswith("Scoped-Schedule")}
    assert by_start == {"01:00": "Scoped-Schedule", "03:00": "vsys1::Scoped-Schedule", "05:00": "vsys2::Scoped-Schedule"}


def test_schedule_exactly_one_terminal_status():
    result = _extract()
    assert len(_records(result, "Daily-One")) == 1
    assert len([item for item in result.inventory_items if item.name == "Daily-One"]) == 1
    assert _records(result, "Daily-One")[0].status == ExtractionStatus.NORMALIZED
