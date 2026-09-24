from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser


def test_selected_dhcp_details_are_structured():
    config = CiscoASAParser("""interface GigabitEthernet0/1
 nameif inside
dhcpd address 192.0.2.10-192.0.2.20 inside
dhcpd enable inside
dhcpd wins 192.0.2.2
dhcpd ping_timeout 30
dhcpd reserve-address 192.0.2.11 0011.2233.4455 inside
dhcpd auto_config outside inside
dhcpd update dns server 192.0.2.3
dhcpd option 150 ip 192.0.2.4
""").parse_raw()
    server = config.dhcp_servers[0]
    assert server.wins_servers == ["192.0.2.2"]
    assert server.ping_timeout == 30
    assert server.reservations[0].interface == "inside"
    assert server.auto_config == "outside inside"
    assert server.dns_update == "server 192.0.2.3"
    assert (server.options[0].value_type, server.options[0].value) == ("ip", "192.0.2.4")
