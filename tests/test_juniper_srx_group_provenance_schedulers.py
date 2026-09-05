from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_scheduler_scalar_override_and_repeated_periods():
    cfg = JuniperSRXParser("""
set groups G1 schedulers scheduler work description inherited
set groups G1 schedulers scheduler work daily 09:00 to 10:00
set apply-groups G1
set schedulers scheduler work description local
set schedulers scheduler work daily 11:00 to 12:00
""").parse_raw()
    sched = cfg.contexts["root"].schedulers["work"]
    assert sched.description == "local"
    assert sched.daily == ["09:00 to 10:00", "11:00 to 12:00"]
    assert sched.field_candidate_history["description"][0].shadowed
    assert len(sched.member_candidate_history["daily"]) == 2
