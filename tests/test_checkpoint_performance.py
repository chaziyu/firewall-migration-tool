from fwmigrate.parsers.checkpoint.gaia import parse_gaia_configuration
from fwmigrate.parsers.checkpoint.performance import extract_performance_settings


def test_performance_extracts_explicit_settings_only():
    settings, inventory = extract_performance_settings("set fwaccel on\nset corexl instances 4 enable\nfwaccel stats")
    assert settings[0].enabled is True
    assert settings[1].instance_count == 4
    assert len(inventory) == 2
    assert not any(item.source_type and "fwaccel" in item.source_type for item in parse_gaia_configuration("fwaccel stats")[4])
