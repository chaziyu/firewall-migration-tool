from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_units_keep_families_filters_addresses_and_vrrp_separate():
    content = """
    set interfaces ge-0/0/0 unit 0 description inside
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


def test_deactivated_unit_does_not_disable_physical_interface():
    content = """
    set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
    deactivate interfaces ge-0/0/0 unit 0
    """
    ir = JuniperSRXParser(content).transform_to_ir()
    physical = next(i for i in ir.interfaces if i.name == "ge-0/0/0.0")
    assert physical.status is False
