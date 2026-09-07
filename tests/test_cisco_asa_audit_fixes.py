from fwmigrate.ir.enums import NATTranslationMode
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_standard_acl_is_destination_only_and_ipv4_only():
    parser = CiscoASAParser(
        """
access-list STANDARD standard permit host 10.0.0.10
access-list BADV6 standard permit any6
"""
    )
    cfg = parser.parse_raw()

    standard = next(rule for rule in cfg.access_rules if rule.acl_name == "STANDARD")
    assert standard.source_endpoint is None
    assert standard.destination_endpoint is not None
    assert standard.destination_endpoint.value == "10.0.0.10"
    assert standard.destination_endpoint.address_family == "ipv4"
    assert standard.source_attributes["standard_acl_semantics"] == "destination-only-ipv4"

    bad = next(rule for rule in cfg.access_rules if rule.acl_name == "BADV6")
    assert bad.migration_status == "PARSE_ERROR"
    assert "ASA standard ACLs are IPv4-only" in bad.review_reasons


def test_acl_service_object_and_service_group_references_resolve():
    parser = CiscoASAParser(
        """
interface GigabitEthernet0/0
 nameif inside
 ip address 10.0.0.1 255.255.255.0
object service HTTPS
 service tcp destination eq 443
object-group service WEB tcp
 port-object eq 80
access-list IN extended permit object HTTPS any any
access-list IN extended permit object-group WEB any any
access-group IN in interface inside
"""
    )
    cfg = parser.parse_raw()

    false_unresolved = [
        issue for issue in cfg.reference_issues
        if issue["reference_name"] in {"HTTPS", "WEB"} and not issue["resolved"]
    ]
    assert false_unresolved == []

    ir = parser.transform_to_ir()
    assert [policy.service for policy in ir.policies] == [["HTTPS"], ["WEB"]]


def test_logical_interface_headers_global_mtu_and_port_channel_membership():
    parser = CiscoASAParser(
        """
interface GigabitEthernet0/0
 channel-group 1 mode active
 no shutdown
interface port-channel 1
 nameif outside
 ip address 192.0.2.1 255.255.255.0
interface bvi 2
 nameif bridge
 ip address 10.0.2.1 255.255.255.0
interface redundant 1
 member-interface GigabitEthernet0/1
 nameif redundant-zone
interface vlan 100
 nameif vlan100
 ip address 10.0.100.1 255.255.255.0
mtu outside 1400
"""
    )
    cfg = parser.parse_raw()

    names = {interface.name for interface in cfg.interfaces}
    assert {"Port-channel1", "BVI2", "Redundant1", "Vlan100"}.issubset(names)
    port_channel = next(interface for interface in cfg.interfaces if interface.name == "Port-channel1")
    assert port_channel.mtu == 1400

    ir = parser.transform_to_ir()
    ir_port_channel = next(interface for interface in ir.interfaces if interface.name == "Port-channel1")
    assert "GigabitEthernet0/0" in ir_port_channel.members


def test_dynamic_nat_is_not_coerced_to_pat_and_network_group_resolves():
    parser = CiscoASAParser(
        """
object network REAL
 host 10.0.0.10
object-group network POOL
 network-object host 203.0.113.10
nat (inside,outside) source dynamic REAL POOL
nat (inside,outside) source dynamic REAL interface
nat (inside,outside) source dynamic REAL POOL interface
"""
    )
    cfg = parser.parse_raw()

    unresolved_pool = [
        issue for issue in cfg.reference_issues
        if issue["reference_name"] == "POOL" and not issue["resolved"]
    ]
    assert unresolved_pool == []
    fallback = cfg.nat_rules[2]
    assert fallback.source_attributes["interface_pat_fallback"] is True

    ir = parser.transform_to_ir()
    assert ir.nat_rules[0].source_translation_mode is None
    assert ir.nat_rules[0].source_attributes["asa_translation_semantics"] == "dynamic-nat"
    assert ir.nat_rules[0].requires_manual_review is True
    assert ir.nat_rules[1].source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS
    assert ir.nat_rules[2].source_translation_mode is None
    assert ir.nat_rules[2].source_attributes["interface_pat_fallback"] is True


def test_legacy_nat_exemption_single_interface_tuple_is_preserved():
    parser = CiscoASAParser(
        """
access-list NONAT extended permit ip 10.0.0.0 255.255.255.0 any
nat (inside) 0 access-list NONAT
"""
    )
    cfg = parser.parse_raw()

    assert len(cfg.nat_rules) == 1
    rule = cfg.nat_rules[0]
    assert rule.syntax_family == "legacy-exemption"
    assert rule.source_interface == "inside"
    assert rule.access_list == "NONAT"
    assert rule.nat_exemption is True
    assert rule.migration_status == "EXTRACT_ONLY"


def test_absolute_time_range_accepts_official_end_then_start_order():
    parser = CiscoASAParser(
        """
time-range CONTRACT
 absolute end 18:00 31 December 2030 start 08:00 1 January 2026
"""
    )
    cfg = parser.parse_raw()

    schedule = cfg.time_ranges[0]
    assert schedule.migration_status != "PARSE_ERROR"
    assert schedule.clauses[0].end == "18:00 31 December 2030"
    assert schedule.clauses[0].start == "08:00 1 January 2026"
