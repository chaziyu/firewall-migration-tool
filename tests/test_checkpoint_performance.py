from fwmigrate.parsers.checkpoint.gaia import parse_gaia_configuration
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.checkpoint.performance import extract_performance_settings


def test_performance_extracts_explicit_settings_only():
    settings, inventory = extract_performance_settings(
        "set fwaccel on\nset corexl instances 4 enable\nfwaccel stats",
        gateway="GW-A", cluster_member="member-1",
    )
    assert settings == []
    assert len(inventory) == 3
    assert all(item.status == ExtractionStatus.EXTRACT_ONLY for item in inventory[:2])
    assert all(item.requires_manual_review for item in inventory[:2])
    assert inventory[-1].status == ExtractionStatus.EXTRACT_ONLY
    assert all(item.source_context.endswith(":GW-A:member-1:unknown") for item in inventory)
    assert not any(item.source_type and "fwaccel" in item.source_type for item in parse_gaia_configuration("fwaccel stats")[4])


def test_runtime_commands_do_not_create_persistent_settings():
    settings, inventory = extract_performance_settings(
        "fwaccel on\nfwaccel off\nfwaccel stat\nfw ctl multik stat\ncpview\ntop\nfwaccel unknown"
    )
    assert settings == []
    assert len(inventory) == 7
    assert all(item.status == ExtractionStatus.EXTRACT_ONLY for item in inventory)
    assert all("runtime-operational-evidence" in item.notes for item in inventory[:2])
    assert any("unrecognized-performance-command" in item.notes for item in inventory)


def test_invalid_and_conflicting_persistent_values_require_review():
    settings, inventory = extract_performance_settings(
        "set securexl state on\nset securexl state off\nset corexl instances nope"
    )
    assert settings == []
    assert all(item.status == ExtractionStatus.EXTRACT_ONLY for item in inventory)
    assert any("persistent-state-not-proven" in note for item in inventory for note in item.notes)


def test_gateway_contexts_are_not_merged():
    a, a_inventory = extract_performance_settings("set corexl instances 4", gateway="GW-A")
    b, b_inventory = extract_performance_settings("set corexl instances 8", gateway="GW-B")
    assert a == b == []
    assert {a_inventory[0].source_context, b_inventory[0].source_context} == {
        "unknown:GW-A:unknown:unknown", "unknown:GW-B:unknown:unknown",
    }
