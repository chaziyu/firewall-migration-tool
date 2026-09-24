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
    global_settings = config.dhcp_global_settings[0]
    assert global_settings.wins_servers == ["192.0.2.2"]
    assert global_settings.ping_timeout == 30
    assert server.reservations[0].interface == "inside"
    assert server.auto_config == "outside inside"
    assert server.dns_update == "server 192.0.2.3"
    assert (global_settings.options[0].value_type, global_settings.options[0].value) == ("ip", "192.0.2.4")


def test_global_dhcp_settings_and_interface_overrides_keep_source_ownership():
    config = CiscoASAParser(
        "dhcpd dns 8.8.8.8\n"
        "dhcpd domain example.net\n"
        "dhcpd lease 3600\n"
        "dhcpd option 15 ascii example.net\n"
        "dhcpd dns 1.1.1.1 interface inside\n"
        "dhcpd lease 1800 interface inside\n"
        "dhcpd address 192.0.2.10-192.0.2.20 inside\n"
        "dhcpd enable inside\n"
    ).parse_raw()
    global_settings = config.dhcp_global_settings[0]
    server = config.dhcp_servers[0]
    assert (global_settings.dns_servers, global_settings.domain_name, global_settings.lease_seconds) == (
        ["8.8.8.8"], "example.net", 3600
    )
    assert [(item.code, item.value) for item in global_settings.options] == [("15", "example.net")]
    assert (server.interface, server.dns_servers, server.lease_seconds) == ("inside", ["1.1.1.1"], 1800)
    assert (server.pool, server.enabled) == ("192.0.2.10-192.0.2.20", True)
