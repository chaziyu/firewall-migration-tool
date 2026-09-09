from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_schedulers_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "schedulers.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    sched_dict = {s.name: s for s in ir.schedules}

    assert "work_hours" in sched_dict
    assert "09:00:00 to 17:00:00" in sched_dict["work_hours"].days

    assert "maintenance_window" in sched_dict
    assert sched_dict["maintenance_window"].start == "2026-10-01.00:00:00"
    assert sched_dict["maintenance_window"].end == "2026-10-02.00:00:00"

    pol = next(p for p in ir.policies if p.name == "Timed_Policy")
    assert pol.schedule == "work_hours"
    assert pol.source_schedule == "work_hours"

    assert_no_silent_loss(res, total_input_commands=14)
