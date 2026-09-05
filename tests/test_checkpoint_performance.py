from fwmigrate.parsers.checkpoint.gaia import parse_gaia_configuration
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.checkpoint.performance import extract_performance_settings


def test_performance_extracts_explicit_settings_only():
    settings, inventory = extract_performance_settings(
        "set fwaccel on\nset corexl instances 4 enable\nfwaccel stats",
        gateway="GW-A", cluster_member="member-1",
    )
    assert settings[0].enabled is True
    assert settings[1].instance_count == 4
    assert settings[1].instance_count_explicit is True
    assert settings[0].migration_status == "NORMALIZED"
    assert len(inventory) == 3
    assert inventory[-1].status == ExtractionStatus.EXTRACT_ONLY
    assert all(item.source_context.endswith(":GW-A:member-1:unknown") for item in inventory)
    assert not any(item.source_type and "fwaccel" in item.source_type for item in parse_gaia_configuration("fwaccel stats")[4])


def test_runtime_commands_do_not_create_persistent_settings():
    settings, inventory = extract_performance_settings(
        "fwaccel stat\nfw ctl multik stat\ncpview\ntop\nfwaccel unknown"
    )
    assert settings == []
    assert len(inventory) == 5
    assert all(item.status == ExtractionStatus.EXTRACT_ONLY for item in inventory)
    assert any("unrecognized-performance-command" in item.notes for item in inventory)


def test_invalid_and_conflicting_persistent_values_require_review():
    settings, inventory = extract_performance_settings(
        "set securexl state on\nset securexl state off\nset corexl instances nope"
    )
    assert len(settings) == 3
    assert all(item.requires_manual_review for item in settings)
    assert all(item.migration_status == "PARTIALLY_NORMALIZED" for item in settings[:2])
    assert settings[2].migration_status == "PARSE_ERROR"
    assert any("conflicting-securexl-enable" in note for item in inventory for note in item.notes)
    assert any("invalid-corexl-instance-count" in note for item in inventory for note in item.notes)


def test_gateway_contexts_are_not_merged():
    a, _ = extract_performance_settings("set corexl instances 4", gateway="GW-A")
    b, _ = extract_performance_settings("set corexl instances 8", gateway="GW-B")
    assert {a[0].source_context, b[0].source_context} == {
        "unknown:GW-A:unknown:unknown", "unknown:GW-B:unknown:unknown",
    }
    assert {a[0].instance_count, b[0].instance_count} == {4, 8}
