from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

def test_inet6_rib_static_route_is_kept():
    r = JuniperSRXParser("set routing-options rib inet6.0 static route 2001:db8::/64 next-hop 2001:db8::1").parse_raw().contexts["root"].routes[0]
    assert r.rib == "inet6.0" and r.destination == "2001:db8::/64"
