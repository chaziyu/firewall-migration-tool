from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss


def test_ipsec_traffic_selectors_preserve_ipv4_ipv6_and_terms():
    content = """
    set security ipsec vpn site-to-site traffic-selector corp local-ip 10.0.0.0/24
    set security ipsec vpn site-to-site traffic-selector corp remote-ip 2001:db8:1::/64
    set security ipsec vpn site-to-site traffic-selector corp protocol tcp
    set security ipsec vpn site-to-site traffic-selector corp term https local-port 443
    set security ipsec vpn site-to-site traffic-selector corp term https remote-ip 2001:db8:2::/64
    set security ipsec vpn site-to-site vpn-monitor destination-ip 192.0.2.1
    """
    config = JuniperSRXParser(content).parse_raw()
    vpn = config.contexts["root"].vpn.ipsec_vpns["site-to-site"]
    selector = vpn.traffic_selectors["corp"]

    assert selector.local_ip == ["10.0.0.0/24"]
    assert selector.remote_ip == ["2001:db8:1::/64"]
    assert selector.terms["https"].local_port == ["443"]
    assert selector.terms["https"].remote_ip == ["2001:db8:2::/64"]
    assert vpn.vpn_monitor.destination_ip == "192.0.2.1"
    assert_no_silent_loss(JuniperSRXParser(content).extract(), total_input_commands=6)
