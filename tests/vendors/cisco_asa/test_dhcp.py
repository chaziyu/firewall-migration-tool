from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser
from fwmigrate.vendors.cisco_asa.relationships.references import build_asa_reference_index
from fwmigrate.vendors.cisco_asa.relationships.routing import build_routing_relationships


def test_dhcp_and_reservations_resolve_to_the_explicit_interface():
    config = CiscoASAParser("""interface GigabitEthernet0/1
 nameif inside
dhcpd address 192.0.2.10-192.0.2.20 inside
dhcpd enable inside
dhcpd reserve-address 192.0.2.11 0011.2233.4455 inside
""").parse_raw()
    result = build_routing_relationships(config, build_asa_reference_index(config))
    assert result.dhcp_server_interfaces[0].interface is config.interfaces[0]
    assert result.dhcp_reservation_interfaces[0].interface is config.interfaces[0]

def test_selected_dhcp_details_are_structured():
    config = CiscoASAParser("""interface GigabitEthernet0/1
 nameif inside
dhcpd address 192.0.2.10-192.0.2.20 inside
dhcpd enable inside
dhcpd wins 192.0.2.2
dhcpd ping_timeout 30
dhcpd reserve-address 192.0.2.11 0011.2233.4455 inside
dhcpd auto_config outside interface inside
dhcpd update dns both override interface inside
dhcpd option 150 ip 192.0.2.4
""").parse_raw()
    server = config.dhcp_servers[0]
    global_settings = config.dhcp_global_settings[0]
    assert global_settings.wins_servers == ["192.0.2.2"]
    assert global_settings.ping_timeout == 30
    assert server.reservations[0].interface == "inside"
    assert server.auto_config == "outside"
    assert server.dns_update == "both override"
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

def test_reservation_uses_its_explicit_interface_and_dns_update_defaults_global():
    config = CiscoASAParser(
        "dhcpd address 192.0.2.10-192.0.2.20 inside\n"
        "dhcpd address 198.51.100.10-198.51.100.20 outside\n"
        "dhcpd reserve-address 192.0.2.11 0011.2233.4455 inside\n"
        "dhcpd update dns both override\n"
    ).parse_raw()
    inside = next(server for server in config.dhcp_servers if server.interface == "inside")
    outside = next(server for server in config.dhcp_servers if server.interface == "outside")
    assert len(inside.reservations) == 1 and inside.reservations[0].interface == "inside"
    assert not outside.reservations
    assert config.dhcp_global_settings[0].dns_update == "both override"
    assert all(server.interface for server in config.dhcp_servers)

def test_dhcp_command_without_required_interface_does_not_attach_to_sole_server():
    config = CiscoASAParser(
        "dhcpd address 192.0.2.10-192.0.2.20 inside\n"
        "dhcpd address 198.51.100.10-198.51.100.20\n"
        "dhcpd auto_config outside\n"
    ).parse_raw()
    assert [(server.interface, server.pool) for server in config.dhcp_servers] == [
        ("inside", "192.0.2.10-192.0.2.20"),
    ]
    assert config.dhcp_global_settings[0].auto_config == "outside"
    assert any("explicit interface" in item.reason for item in config.diagnostics)
