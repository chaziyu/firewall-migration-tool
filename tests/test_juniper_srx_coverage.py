from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_empty_config_produces_no_fake_zones_or_interfaces():
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract("")
    assert res.canonical_ir.zones == []
    assert res.canonical_ir.interfaces == []
    assert res.canonical_ir.addresses == []
    assert res.canonical_ir.policies == []
    assert res.canonical_ir.routes == []
    assert len(res.inventory_items) == 0

def test_coverage_and_zero_silent_loss_on_basic_fixture():
    fixture_path = JUNIPER_FIXTURES_DIR / "basic.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)

    assert_no_silent_loss(res, total_input_commands=14, expected_unsupported=0)
    assert len(res.canonical_ir.zones) == 2
    assert len(res.canonical_ir.addresses) == 2
    assert len(res.canonical_ir.policies) == 1
    assert len(res.canonical_ir.routes) == 1

def test_coverage_on_unsupported_fixture():
    fixture_path = JUNIPER_FIXTURES_DIR / "unsupported.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)

    # Screen extraction is now retained as source inventory rather than dropped.
    assert_no_silent_loss(res, total_input_commands=7, expected_unsupported=3)
    assert len(res.unsupported_items) >= 3
