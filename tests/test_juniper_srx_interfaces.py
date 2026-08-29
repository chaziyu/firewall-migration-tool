from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_interfaces_extraction_and_vlan():
    fixture_path = JUNIPER_FIXTURES_DIR / "interfaces.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)

    ir = res.canonical_ir
    intf_names = [i.name for i in ir.interfaces]

    assert "ge-0/0/0.0" in intf_names
    assert "ge-0/0/0.10" in intf_names
    assert "ge-0/0/1.0" in intf_names

    i_vlan = next(i for i in ir.interfaces if i.name == "ge-0/0/0.10")
    assert i_vlan.vlanid == 10
    assert i_vlan.ip == "10.10.10.1/24"

    i_primary = next(i for i in ir.interfaces if i.name == "ge-0/0/0.0")
    assert i_primary.ip == "10.10.1.1/24"
    assert len(i_primary.secondary_ips) == 2  # secondary IPv4 + IPv6

    assert_no_silent_loss(res, total_input_commands=20)
