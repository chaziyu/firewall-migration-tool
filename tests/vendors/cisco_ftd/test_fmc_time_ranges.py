import json

from fwmigrate.vendors.cisco_ftd.derived import build_ftd_derived_views
from fwmigrate.vendors.cisco_ftd.source_report import extract_cisco_ftd_source
from fwmigrate.vendors.cisco_ftd.validation import validate_ftd_config


def _bundle(time_ranges, time_range_reference=None):
    rule = {"id": "rule-1", "name": "Rule"}
    if time_range_reference is not None:
        rule["timeRange"] = time_range_reference
    return json.dumps({
        "format": "cisco-fmc-rest-export-v1",
        "domain": {"id": "domain-1", "name": "Global"},
        "objects": {"timeranges": time_ranges},
        "access_policies": [{"id": "acp-1", "name": "ACP", "rules": [rule]}],
    })


def test_fmc_time_range_source_shape_and_reference_are_preserved():
    payload = [
        {"id": "absolute", "name": "Absolute", "description": "release window",
         "effectiveStartDateTime": "2026-09-24T09:00:00", "effectiveEndDateTime": "2026-09-24T17:00:00",
         "vendorNote": "safe"},
        {"id": "empty", "name": "Empty", "recurrenceList": []},
        {"id": "mixed", "name": "Mixed", "recurrenceList": [
            {"recurrenceType": "DAILY_INTERVAL", "days": ["MON"],
             "dailyStartTime": "08:00", "dailyEndTime": "12:00", "extra": "kept"},
            {"recurrenceType": "DAILY_INTERVAL", "days": ["MON"],
             "dailyStartTime": "13:00", "dailyEndTime": "17:00"},
            {"recurrenceType": "RANGE", "rangeStartDay": "FRI", "rangeStartTime": "17:00",
             "rangeEndDay": "MON", "rangeEndTime": "08:00"},
        ]},
    ]
    result = extract_cisco_ftd_source(_bundle(payload, {"id": "mixed", "name": "Mixed"}))
    config = result.config

    assert len(config.time_ranges) == 3
    absolute, empty, mixed = config.time_ranges
    assert absolute.absolute_start_date_time == "2026-09-24T09:00:00"
    assert absolute.absolute_end_date_time == "2026-09-24T17:00:00"
    assert absolute.recurrence_entries is None
    assert absolute.raw_extra["vendorNote"] == "safe"
    assert "absolute_start_date_time" in absolute.explicit_fields
    assert empty.recurrence_entries == []
    assert "recurrence_entries" in empty.explicit_fields
    assert len(mixed.recurrence_entries) == 3
    assert [(entry.recurrence_type, entry.days, entry.daily_start_time, entry.daily_end_time)
            for entry in mixed.recurrence_entries[:2]] == [
        ("DAILY_INTERVAL", ["MON"], "08:00", "12:00"),
        ("DAILY_INTERVAL", ["MON"], "13:00", "17:00"),
    ]
    assert (mixed.recurrence_entries[2].range_start_day, mixed.recurrence_entries[2].range_start_time,
            mixed.recurrence_entries[2].range_end_day, mixed.recurrence_entries[2].range_end_time) == (
        "FRI", "17:00", "MON", "08:00")
    assert mixed.recurrence_entries[0].raw_extra["extra"] == "kept"
    assert mixed.recurrence_entries[0].explicit_fields == [
        "recurrence_type", "days", "daily_start_time", "daily_end_time"]

    derived = build_ftd_derived_views(config)
    issues = validate_ftd_config(config, derived).issues
    assert any(ref["owner"] == "Rule" and ref["field"] == "time_range" and ref["kind"] == "TIME_RANGE"
               for ref in derived.resolved_references)
    assert not any(issue.category == "invalid-time-range" for issue in issues)


def test_fmc_time_range_validation_and_unresolved_reference_do_not_repair_source():
    config = extract_cisco_ftd_source(_bundle([
        {"id": "bad", "name": "Bad", "effectiveStartDateTime": "not-a-date",
         "recurrenceList": [{"recurrenceType": "DAILY_INTERVAL", "days": ["MONDAY"],
                             "dailyStartTime": "25:00"}]},
    ], {"id": "missing", "name": "Missing"})).config
    derived = build_ftd_derived_views(config)
    issues = validate_ftd_config(config, derived).issues

    assert len(config.time_ranges) == 1
    assert config.time_ranges[0].absolute_start_date_time == "not-a-date"
    assert config.time_ranges[0].recurrence_entries[0].days == ["MONDAY"]
    assert any(issue.category == "unresolved-reference" and issue.source_object == "Rule"
               for issue in issues)
    assert sum(issue.category == "invalid-time-range" for issue in issues) >= 3
