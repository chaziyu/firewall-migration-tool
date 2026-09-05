from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_vlan_inventory_and_l3_relationship_are_preserved():
    content = """
    set vlans users vlan-id 100
    set vlans users l3-interface irb.100
    set vlans users interface ge-0/0/0.0
    set interfaces irb unit 100 family inet address 192.0.2.1/24
    """
    parser = JuniperSRXParser(content)
    cfg = parser.parse_raw()
    vlan = cfg.contexts["root"].vlans["users"]
    assert vlan.vlan_id == 100
    assert vlan.l3_interface == "irb.100"
    assert vlan.members == ["ge-0/0/0.0"]

    ir = JuniperSRXParser(content).transform_to_ir()
    irb = next(i for i in ir.interfaces if i.name == "irb.100")
    assert irb.source_attributes["junos_vlan"]["name"] == "users"
