from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser
from fwmigrate.vendors.cisco_asa.relationships.references import build_asa_reference_index
from fwmigrate.vendors.cisco_asa.relationships.routing import build_routing_relationships


def test_path_monitor_is_source_only_and_dhcp_interface_resolves():
    config = CiscoASAParser("""interface GigabitEthernet0/1
 nameif inside
 policy-route path-monitoring auto
dhcpd address 192.0.2.10-192.0.2.20 inside
dhcpd enable inside
dhcpd reserve-address 192.0.2.11 0011.2233.4455 inside
""").parse_raw()
    result = build_routing_relationships(config, build_asa_reference_index(config))
    assert result.path_monitors[0].status == "SOURCE_ONLY"
    assert result.dhcp_server_interfaces[0].interface is config.interfaces[0]
    assert result.dhcp_reservation_interfaces[0].interface is config.interfaces[0]
