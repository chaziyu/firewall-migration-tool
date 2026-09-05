from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

def test_ipv6_interface_family_and_flags_are_preserved():
    u = JuniperSRXParser("set interfaces ge-0/0/0 unit 0 family inet6 address 2001:db8::1/64 primary").parse_raw().contexts["root"].interfaces["ge-0/0/0"].units["0"]
    assert u.addresses[0].family == "inet6" and u.addresses[0].primary
