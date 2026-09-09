from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_interfaces_are_context_local_and_units_merge():
    parser = JuniperSRXParser("\n".join([
        "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
        "set logical-systems LS1 interfaces ge-0/0/0 unit 0 description ls1",
        "set logical-systems LS1 interfaces ge-0/0/0 unit 0 family inet address 10.1.1.1/24",
        "set logical-systems LS1 interfaces lt-0/0/0 unit 5 family inet6 address 2001:db8::1/64",
        "set logical-systems LS1 interfaces ge-0/0/0 unit 0 unsupported-child foo",
        "set logical-systems LS2 interfaces ge-0/0/0 unit 0 family inet address 10.2.2.1/24",
    ])).parse_raw()
    assert parser.contexts["root"].interfaces["ge-0/0/0"].units["0"].addresses[0].address == "192.0.2.1/24"
    ls1 = parser.contexts["LS1"].interfaces
    assert ls1["ge-0/0/0"].units["0"].description == "ls1"
    assert len(ls1["ge-0/0/0"].units) == 1
    assert ls1["lt-0/0/0"].units["5"].addresses[0].family == "inet6"
    assert ls1["ge-0/0/0"].units["0"].source_attributes
    assert parser.contexts["LS2"].interfaces["ge-0/0/0"].units["0"].addresses[0].address == "10.2.2.1/24"


def test_interface_activation_isolated():
    parser = JuniperSRXParser("\n".join([
        "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
        "set logical-systems LS1 interfaces ge-0/0/0 unit 0 family inet address 10.1.1.1/24",
        "set logical-systems LS2 interfaces ge-0/0/0 unit 0 family inet address 10.2.2.1/24",
        "deactivate logical-systems LS1 interfaces ge-0/0/0 unit 0",
    ]))
    parser.extract()
    assert not parser.config.contexts["root"].interfaces["ge-0/0/0"].units["0"].disabled
    assert parser.config.contexts["LS1"].interfaces["ge-0/0/0"].units["0"].disabled
    assert not parser.config.contexts["LS2"].interfaces["ge-0/0/0"].units["0"].disabled
