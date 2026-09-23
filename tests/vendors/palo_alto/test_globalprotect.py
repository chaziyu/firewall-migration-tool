from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_globalprotect_fixture_is_not_dropped_as_empty_configuration():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_firewall.xml"
    config = build_panos_config(path.read_text())
    assert config.source_inventory
