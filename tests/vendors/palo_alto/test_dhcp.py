from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_dhcp_fixture_is_extracted_without_losing_source_evidence():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "interfaces_extended.xml"
    config = build_panos_config(path.read_text())
    assert config.source_inventory
    assert any("dhcp" in str(record.model_dump()).lower() for record in config.source_inventory)
