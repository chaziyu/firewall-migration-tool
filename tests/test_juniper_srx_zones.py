from fwmigrate.core.registry import PluginRegistry
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_zones_and_zone_mapping():
    fixture_path = JUNIPER_FIXTURES_DIR / "interfaces.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    ir = parser.parse(content, zone_mapping={"trust": "INTERNAL_ZONE", "untrust": "EXTERNAL_ZONE"})

    zone_names = [z.name for z in ir.zones]
    assert "INTERNAL_ZONE" in zone_names
    assert "EXTERNAL_ZONE" in zone_names
    assert "dmz" in zone_names

    # Check interface mapped zone
    i_trust = next(i for i in ir.interfaces if i.name == "ge-0/0/0.0")
    assert i_trust.zone == "INTERNAL_ZONE"
