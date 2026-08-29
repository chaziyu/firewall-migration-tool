from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.enums import NATTranslationMode, NATType
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_source_nat_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "nat_source.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    nat_dict = {n.name: n for n in ir.nat_rules}

    # Pool NAT
    assert "r1" in nat_dict
    assert nat_dict["r1"].type == NATType.SOURCE
    assert nat_dict["r1"].source_translation_mode == NATTranslationMode.POOL
    assert nat_dict["r1"].source_pool_references == ["src_pool_1"]

    # Interface NAT
    assert "r2_interface" in nat_dict
    assert nat_dict["r2_interface"].type == NATType.SOURCE
    assert nat_dict["r2_interface"].source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS

    # NAT off
    assert "r3_off" in nat_dict
    assert nat_dict["r3_off"].type == NATType.SOURCE
    assert nat_dict["r3_off"].source_translation_mode == NATTranslationMode.NONE

    assert_no_silent_loss(res, total_input_commands=17)

def test_destination_nat_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "nat_destination.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    nat_dict = {n.name: n for n in ir.nat_rules}
    assert "r_vip" in nat_dict
    assert nat_dict["r_vip"].type == NATType.DESTINATION
    assert "172.16.1.100/32" in nat_dict["r_vip"].translated_destinations

    assert_no_silent_loss(res, total_input_commands=11)

def test_static_nat_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "nat_static.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    nat_dict = {n.name: n for n in ir.nat_rules}
    assert "r_static_server" in nat_dict
    assert nat_dict["r_static_server"].requires_manual_review is True

    assert_no_silent_loss(res, total_input_commands=7)
