from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_aggregate_members_parent_options_and_units_are_preserved():
    content = """
    set interfaces ae0 aggregated-ether-options lacp active
    set interfaces ae0 aggregated-ether-options lacp periodic fast
    set interfaces ge-0/0/0 ether-options 802.3ad ae0
    set interfaces ge-0/0/1 ether-options 802.3ad ae0
    set interfaces ae0 unit 10 family inet address 198.51.100.1/24
    """
    cfg = JuniperSRXParser(content).parse_raw().contexts["root"]
    ae = cfg.interfaces["ae0"]
    assert ae.interface_type == "aggregate-ethernet"
    assert ae.aggregate_members == ["ge-0/0/0", "ge-0/0/1"]
    assert ae.aggregate_options[0]["path"] == ["aggregated-ether-options", "lacp", "active"]
    out = JuniperSRXParser(content).transform_to_ir()
    item = next(i for i in out.interfaces if i.name == "ae0.10")
    assert item.ip == "198.51.100.1/24"
    assert item.source_attributes["junos_interface_type"] == "aggregate-ethernet"

