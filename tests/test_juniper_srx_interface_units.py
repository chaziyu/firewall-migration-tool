from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_units_keep_families_filters_addresses_and_vrrp_separate():
    content = """
    set interfaces ge-0/0/0 description physical
    set interfaces ge-0/0/0 mtu 1500
    set interfaces ge-0/0/0 unit 0 description inside
    set interfaces ge-0/0/0 unit 0 mtu 1492
    set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 primary
    set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.2/24 preferred
    set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64
    set interfaces ge-0/0/0 unit 0 family inet filter input FILTER4
    set interfaces ge-0/0/0 unit 0 family inet6 filter output FILTER6
    set interfaces ge-0/0/0 unit 0 vrrp-group 1 virtual-address 10.0.0.254
    set interfaces ge-0/0/0 unit 0 encapsulation vlan-bridge
    """
    parser = JuniperSRXParser(content)
    cfg = parser.parse_raw()
    unit = cfg.contexts["root"].interfaces["ge-0/0/0"].units["0"]
    assert [a.family for a in unit.addresses] == ["inet", "inet", "inet6"]
    assert unit.addresses[0].primary is True
    assert unit.addresses[1].preferred is True
    assert {f["name"] for f in unit.filters} == {"FILTER4", "FILTER6"}
    assert unit.vrrp[0]["virtual_address"] == ["10.0.0.254"]
    assert unit.encapsulation == "vlan-bridge"

    ir = JuniperSRXParser(content).transform_to_ir()
    physical = next(item for item in ir.interfaces if item.name == "ge-0/0/0")
    interface = next(item for item in ir.interfaces if item.name == "ge-0/0/0.0")
    assert physical.description == "physical"
    assert physical.mtu == 1500
    assert interface.description == "inside"
    assert interface.mtu == 1492
    assert interface.parent == "ge-0/0/0"
    assert interface.ip == "10.0.0.1/24"
    assert interface.ipv6_address == "2001:db8::1/64"
    assert [item.address for item in interface.additional_ipv4_addresses] == ["10.0.0.2/24"]
    assert interface.additional_ipv6_addresses == []
    assert [item.ip for item in interface.secondary_ips] == ["10.0.0.2/24"]


def test_deactivated_unit_does_not_disable_physical_interface():
    content = """
    set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
    deactivate interfaces ge-0/0/0 unit 0
    """
    ir = JuniperSRXParser(content).transform_to_ir()
    physical = next(i for i in ir.interfaces if i.name == "ge-0/0/0")
    unit = next(i for i in ir.interfaces if i.name == "ge-0/0/0.0")
    assert physical.status is True
    assert unit.status is False
