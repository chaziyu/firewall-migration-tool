from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_management_access_fixture_is_retained_as_source_inventory():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "management_access.xml"
    config = build_panos_config(path.read_text())
    assert config.source_inventory
    assert any("management" in record.source_path for record in config.source_inventory)
