from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_irb_ipv4_ipv6_keeps_vlan_relationship():
    content = """
    set vlans users vlan-id 100
    set vlans users l3-interface irb.100
    set interfaces irb unit 100 family inet address 192.0.2.1/24
    set interfaces irb unit 100 family inet6 address 2001:db8:100::1/64
    """
    cfg = JuniperSRXParser(content).parse_raw()
    irb = cfg.contexts["root"].interfaces["irb"].units["100"]
    assert [a.family for a in irb.addresses] == ["inet", "inet6"]
    assert cfg.contexts["root"].interfaces["irb"].interface_type == "irb"
    out = JuniperSRXParser(content).transform_to_ir()
    item = next(i for i in out.interfaces if i.name == "irb.100")
    assert item.ip == "192.0.2.1/24"
    assert item.source_attributes["junos_vlan"]["name"] == "users"
