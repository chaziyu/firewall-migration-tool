from fwmigrate.core.registry import PluginRegistry
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


def test_physical_interface_settings_and_deactivation():
    content = """
    set interfaces ge-0/0/0 mtu 9000
    set interfaces ge-0/0/0 speed 1g
    set interfaces ge-0/0/0 link-mode full-duplex
    set interfaces ge-0/0/0 encapsulation ethernet-bridge
    set interfaces ge-0/0/0 gigether-options no-auto-negotiation
    deactivate interfaces ge-0/0/0
    """
    res = PluginRegistry.get_parser("juniper_srx").extract(content)
    interface = next(i for i in res.canonical_ir.interfaces if i.name == "ge-0/0/0")
    assert (interface.mtu, interface.status) == (9000, False)
    assert interface.source_attributes["junos_speed"] == "1g"
    assert interface.source_attributes["junos_link_mode"] == "full-duplex"
    assert interface.source_attributes["junos_encapsulation"] == "ethernet-bridge"
    assert interface.source_attributes["junos_physical_link"]


def test_nested_physical_link_settings_are_typed():
    content = """
    set interfaces ge-0/0/1 ether-options speed 10g
    set interfaces ge-0/0/1 gigether-options link-mode full-duplex
    """
    interface = next(
        i for i in PluginRegistry.get_parser("juniper_srx").extract(content).canonical_ir.interfaces
        if i.name == "ge-0/0/1"
    )
    assert interface.source_attributes["junos_speed"] == "10g"
    assert interface.source_attributes["junos_link_mode"] == "full-duplex"
