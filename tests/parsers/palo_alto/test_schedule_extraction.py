from pathlib import Path

from fwmigrate.vendors.palo_alto.model import PANSchedule
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def test_recurring_and_non_recurring_schedules_are_extracted_from_source():
    config = build_panos_config((FIXTURES / "schedules.xml").read_text())
    schedules = {(item.scope.name, item.name): item for item in config.schedules}

    assert schedules[("vsys1", "Daily-Multiple")].recurring.daily == ["08:00-12:00", "13:00-17:00"]
    assert schedules[("vsys1", "Weekly-Different")].recurring.weekly == {
        "monday": ["08:00-12:00"],
        "tuesday": ["14:00-18:00"],
    }
    assert schedules[("vsys1", "Once-One")].non_recurring == ["2026/09/01@08:00-2026/09/01@17:00"]
    assert schedules[("vsys1", "Unknown-Schedule")].raw_extra["future-setting"] == "retain-me"


def test_schedule_contract_preserves_explicit_state_scope_inventory_and_redaction(assert_source_contract):
    secret = "schedule-secret-value"
    config = build_panos_config(
        f"""<config><shared><schedule>
          <entry name='explicit'><schedule-type><recurring><daily><member>08:00-17:00</member></daily><future-nested>keep-nested</future-nested><future-password>{secret}</future-password></recurring></schedule-type><future-toggle>no</future-toggle></entry>
          <entry name='missing'/>
        </schedule></shared></config>"""
    )
    explicit, missing = config.schedules

    assert isinstance(explicit, PANSchedule)
    assert explicit.recurring.daily == ["08:00-17:00"]
    assert missing.recurring is None
    assert missing.non_recurring is None
    assert explicit.raw_extra["future-toggle"] == "no"
    assert explicit.recurring.raw_extra["future-nested"] == "keep-nested"
    assert "future-nested" not in explicit.raw_extra
    assert explicit.scope.kind == "shared"
    assert_source_contract(explicit, config)
    assert secret not in str(config.model_dump())
