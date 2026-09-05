from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.cisco_asa.extractor import extract_cisco_asa_config
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def parse(text: str):
    return CiscoASAParser(text).parse_raw()


def test_dhcp_commands_aggregate_by_interface():
    config = parse("""
interface GigabitEthernet0/1
 nameif inside
dhcpd address 10.0.0.10-10.0.0.100 inside
dhcpd dns 8.8.8.8 1.1.1.1 inside
dhcpd domain example.local
dhcpd lease 3600
dhcpd enable inside
""")
    assert len(config.dhcp_servers) == 1
    server = config.dhcp_servers[0]
    assert (server.interface, server.pool_start, server.pool_end) == ("inside", "10.0.0.10", "10.0.0.100")
    assert server.dns_servers == ["8.8.8.8", "1.1.1.1"]
    assert (server.domain_name, server.lease_seconds, server.enabled) == ("example.local", 3600, True)
    assert not [issue for issue in config.reference_issues if issue["reference_type"] == "interface" and not issue["resolved"]]


def test_dhcp_invalid_pool_is_parse_error_and_missing_interface_is_partial():
    config = parse("dhcpd address 10.0.0.100-10.0.0.10 inside")
    assert config.dhcp_servers[0].migration_status == "PARSE_ERROR"
    missing = parse("dhcpd enable").dhcp_servers[0]
    assert missing.requires_manual_review
    assert missing.interface is None


def test_dhcp_relay_preserves_servers_and_enabled_interfaces():
    config = parse("""
interface GigabitEthernet0/1
 nameif inside
dhcprelay server 192.0.2.53 inside
dhcprelay server 192.0.2.54 inside
dhcprelay enable inside
dhcprelay enable outside
""")
    relay = config.dhcp_relays[0]
    assert relay.servers == ["192.0.2.53", "192.0.2.54"]
    assert relay.enabled_interfaces == ["inside", "outside"]
    assert len(relay.server_entries) == 2
    assert any(issue["reference_name"] == "outside" and not issue["resolved"] for issue in config.reference_issues)


def test_dns_groups_and_system_settings_are_separate():
    config = parse("""
dns server-group corp
 name-server 192.0.2.53
 name-server 2001:db8::53
 domain-name corp.example
domain-name example.local
dns domain-lookup inside
""")
    assert len(config.dns_server_groups) == 1
    assert config.dns_server_groups[0].name_servers == ["192.0.2.53", "2001:db8::53"]
    assert config.dns_server_groups[0].domain_name == "corp.example"
    assert config.dns_settings.domain_name == "example.local"
    assert config.dns_settings.lookup_interfaces == ["inside"]


def test_malformed_dns_server_is_parse_error():
    config = parse("""
dns server-group corp
 name-server not-an-ip
""")
    assert config.dns_server_groups[0].migration_status == "PARSE_ERROR"
    assert config.parse_errors[0]["section"] == "dns"


def test_dhcp_dns_coverage_is_partial():
    result = extract_cisco_asa_config("""
dhcpd enable inside
dhcprelay enable inside
dns server-group corp
domain-name example.local
""")
    assert [section.status for section in result.source_sections] == [ExtractionStatus.PARTIALLY_NORMALIZED] * 4
