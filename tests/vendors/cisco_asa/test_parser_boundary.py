from copy import deepcopy

from fwmigrate.vendors.cisco_asa.derived import build_asa_derived_views

from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser

from fwmigrate.vendors.cisco_asa.validation import validate_asa_config

def parse(text):
    return CiscoASAParser(text).parse_raw()

def test_parse_raw_constructs_interface_acl_time_and_global_mtu_source():
    config = parse("\n".join([
        "mtu outside 1400", "interface BVI 1", " nameif outside",
        "interface Port-channel 3", "interface Port-channel4", "interface Vlan 10",
        "interface Redundant 2", "interface GigabitEthernet0/1.20",
        "access-list STANDARD standard permit host 192.0.2.4",
        "time-range WINDOW", " absolute end 12:00 2 January 2025 start 10:00 1 January 2025",
    ]))
    bvi = next(item for item in config.interfaces if item.name == "BVI1")
    assert (bvi.interface_type, bvi.bvi_id, bvi.mtu) == ("bvi", 1, 1400)
    assert bvi.source_attributes["raw_header"] == "interface BVI 1"
    assert next(item for item in config.interfaces if item.name == "Port-channel3").port_channel_id == 3
    assert next(item for item in config.interfaces if item.name == "Port-channel4").port_channel_id == 4
    assert next(item for item in config.interfaces if item.name == "Vlan10").vlan_id == 10
    assert next(item for item in config.interfaces if item.name == "Redundant2").interface_type == "redundant"
    assert next(item for item in config.interfaces if item.name == "GigabitEthernet0/1.20").parent_interface == "GigabitEthernet0/1"
    rule = config.access_rules[0]
    assert rule.acl_type == "standard" and rule.source_endpoint is None
    assert rule.destination_endpoint.value == "192.0.2.4"
    clause = config.time_ranges[0].clauses[0]
    assert clause.start.startswith("10:00") and clause.end.startswith("12:00")
    assert not config.unsupported_commands

def test_legacy_nat_is_parsed_by_base_parser_and_keeps_acl_reference():
    parser = CiscoASAParser("nat (inside) 0 access-list MISSING extra")
    config = parser.parse_raw()
    rule = config.nat_rules[0]
    assert rule.syntax_family == "legacy-exemption" and rule.access_list == "MISSING"
    assert rule.sequence == rule.source_sequence == 0
    assert rule.raw_extra["unparsed_tokens"] == ["extra"]

def test_invalid_ipv6_standard_acl_is_a_parse_error_at_construction():
    config = parse("access-list V6 standard permit 2001:db8::1")
    rule = config.access_rules[0]
    assert rule.source_endpoint is None
    assert rule.destination_endpoint.address_family == "ipv6"
    assert rule.extraction_status == "PARSE_ERROR"

def test_source_blocks_are_built_when_the_parser_reaches_them():
    config = parse("\n".join([
        "dns server-group DNS", " name-server 192.0.2.53", " retries 2", "dns-group DNS",
        "interface Ethernet0/0", " nameif outside", " dhcprelay server 192.0.2.1",
        "context blue", " allocate-interface GigabitEthernet0/1 mapped", "admin-context blue",
        "failover group 1", " primary", " priority 100", " preempt",
        "no service-policy POLICY global", "http server enable 8443",
        "crypto ca trustpoint TP", " enrollment terminal",
        "crypto ca certificate chain TP", " certificate ca 01",
    ]))

    assert config.dns_server_groups[0].name_servers == ["192.0.2.53"]
    assert config.dns_server_groups[0].retries == 2
    assert config.dns_settings.default_server_group == "DNS"
    assert config.dhcp_relays[0].server_entries[0].interface == "Ethernet0/0"
    assert config.contexts[0].allocated_interface_entries[0].mapped_name == "mapped"
    assert config.multi_context_system.admin_context_name == "blue"
    assert config.failover_config.failover_groups[0].preempt is True
    assert config.service_policies[0].enabled is False
    assert config.http_server.port == 8443
    assert config.trustpoint_records[0].certificate_present is True

def test_syntax_safety_is_recorded_during_source_parsing():
    config = parse("CLASS-MAP test\n match protocol\nconn-max 100\n")

    class_map = config.class_maps[0]
    assert class_map.extraction_status == "PARSE_ERROR"
    assert any("Malformed class-map match" in item.reason for item in config.diagnostics)
    connection = config.connection_controls[0]
    assert connection.control_type == "unverified_global_connection"
    assert connection.extraction_status == "UNSUPPORTED"
