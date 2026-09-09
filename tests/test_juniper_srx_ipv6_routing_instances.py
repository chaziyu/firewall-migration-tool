from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

def test_ipv6_route_in_routing_instance_keeps_table():
    r = JuniperSRXParser("set routing-instances ri routing-options rib inet6.0 static route 2001:db8::/64 next-hop 2001:db8::1").parse_raw().contexts["root"].routes[0]
    assert r.routing_instance == "ri" and r.rib == "inet6.0"
