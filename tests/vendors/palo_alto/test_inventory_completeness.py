from pathlib import Path

from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


FIXTURES = Path(__file__).parents[2] / "fixtures" / "palo_alto"


def _evidence(config, marker: str) -> bool:
    return marker in str(config.model_dump())


def test_rich_fixtures_keep_unsupported_source_evidence():
    cases = {
        "policy_families.xml": ("future-policy",),
        "interfaces_extended.xml": ("future-l3", "future-l2"),
        "dynamic_routing.xml": ("future-peer-field", "future-bgp-field"),
        "phase94_production.xml": (),
    }

    for filename, markers in cases.items():
        config = build_panos_config((FIXTURES / filename).read_text())
        assert config.source_inventory
        for marker in markers:
            assert _evidence(config, marker), f"missing source evidence {marker} in {filename}"


def test_typed_extraction_does_not_drop_inventory_entries():
    for filename in ("policy_families.xml", "interfaces_extended.xml", "dynamic_routing.xml", "phase94_production.xml"):
        config = build_panos_config((FIXTURES / filename).read_text())
        assert config.source_inventory
        assert all(record.raw_xml for record in config.source_inventory)
