from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_absolute_and_periodic_time_ranges_are_extracted_and_policy_resolves():
    parser = CiscoASAParser("""
interface Gi0/0
 nameif inside
time-range ABS
 absolute start 00:00 1 January 2026 end 23:59 31 December 2026
time-range WORK
 periodic weekdays 08:00 to 17:00
time-range DAILY
 periodic daily 00:00 to 23:59
access-list A extended permit ip any any time-range WORK
access-group A in interface inside
""")
    ir = parser.transform_to_ir()
    assert [item.name for item in ir.schedules] == ["ABS", "WORK", "DAILY"]
    absolute = next(item for item in ir.schedules if item.name == "ABS")
    work = next(item for item in ir.schedules if item.name == "WORK")
    daily = next(item for item in ir.schedules if item.name == "DAILY")
    assert absolute.start == "00:00 1 January 2026"
    assert absolute.end == "23:59 31 December 2026"
    assert work.days == ["weekdays"] and (work.start, work.end) == ("08:00", "17:00")
    assert daily.days == ["daily"]
    assert ir.policies[0].schedule == "WORK"
    assert not any("unresolved" in reason.lower() for reason in ir.policies[0].review_reasons)
