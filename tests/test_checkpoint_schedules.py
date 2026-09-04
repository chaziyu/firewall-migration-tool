from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.core import IRScheduleGroup
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver
from fwmigrate.parsers.checkpoint.schedules import extract_time_objects


def test_time_fields_and_groups_are_preserved():
    schedules, groups, items, unsupported = extract_time_objects([
        CheckPointResponse(command="show-times", data={"objects": [{
            "uid": "daily", "name": "Daily", "type": "time",
            "start-now": True, "end-never": True,
            "start": {"date": "2026-01-01", "time": "00:00"},
            "hours-ranges": [
                {"enabled": True, "from": "08:00", "to": "10:00"},
                {"enabled": True, "from": "14:00", "to": "16:00"},
            ],
            "recurrence": {"pattern": "Daily", "days": [1]},
            "timezone": "Asia/Kuala_Lumpur",
        }]}),
        CheckPointResponse(command="show-time-groups", data={"objects": [{
            "uid": "group", "name": "Windows", "type": "time-group",
            "members": ["Daily"],
        }]}),
    ], CheckPointObjectResolver(), include_groups=True)
    assert unsupported == []
    assert items[0].status == ExtractionStatus.NORMALIZED
    assert len(schedules) == 1
    assert len(schedules[0].hours_ranges) == 2
    assert schedules[0].start_endpoint["date"] == "2026-01-01"
    assert schedules[0].start_now is True
    assert schedules[0].end_never is True
    assert schedules[0].timezone == "Asia/Kuala_Lumpur"
    assert isinstance(groups[0], IRScheduleGroup)
    assert groups[0].members == ["Daily"]
