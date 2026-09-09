from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_ipv6_vpn_gateway_st0_and_selectors_are_retained():
    c = JuniperSRXParser("""
    set interfaces st0 unit 0 family inet6 address 2001:db8:10::1/64
    set security ike gateway gw address 2001:db8:20::1
    set security ipsec vpn v bind-interface st0.0
    set security ipsec vpn v ike gateway gw
    set security ipsec vpn v traffic-selector ts local-ip 2001:db8:10::/64
    set security ipsec vpn v traffic-selector ts remote-ip 2001:db8:30::/64
    """).parse_raw()
    assert c.contexts["root"].interfaces["st0"].units["0"].addresses[0].family == "inet6"
    assert c.contexts["root"].vpn.ike_gateways["gw"].address == "2001:db8:20::1"
    assert c.contexts["root"].vpn.ipsec_vpns["v"].traffic_selectors["ts"].remote_ip == ["2001:db8:30::/64"]
