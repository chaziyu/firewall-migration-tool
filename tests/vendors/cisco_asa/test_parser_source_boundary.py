from copy import deepcopy

from fwmigrate.vendors.cisco_asa.derived import build_asa_derived_views
from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser
from fwmigrate.vendors.cisco_asa.stages import get_asa_parser_class
from fwmigrate.vendors.cisco_asa.validation import validate_asa_config


def parse(text):
    return get_asa_parser_class()(text).parse_raw()


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


def test_parser_does_not_attach_reference_failures_and_derived_views_do_not_mutate_source():
    config = parse("object-group network SERVERS\n network-object object MISSING")
    before = deepcopy(config)
    assert not config.reference_issues
    assert not any("reference_issues" in item.source_attributes for item in config.network_groups)
    assert not any("reference" in reason.lower() for group in config.network_groups for reason in group.review_reasons)
    derived = build_asa_derived_views(config)
    validate_asa_config(config, derived)
    assert config == before
    assert any(not issue.resolved for issue in derived.reference_issues)


def test_invalid_ipv6_standard_acl_is_a_parse_error_at_construction():
    config = parse("access-list V6 standard permit 2001:db8::1")
    rule = config.access_rules[0]
    assert rule.source_endpoint is None
    assert rule.destination_endpoint.address_family == "ipv6"
    assert rule.extraction_status == "PARSE_ERROR"
