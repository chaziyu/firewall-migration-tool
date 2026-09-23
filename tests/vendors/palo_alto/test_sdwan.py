from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_sdwan_related_unknown_source_leaves_survive_inventory_capture():
    path = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "phase13_conformance.xml"
    config = build_panos_config(path.read_text())
    assert config.source_inventory
    assert config.unknown_paths or any(record.raw_xml for record in config.source_inventory)
