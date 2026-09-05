from fwmigrate.ir.enums import NATType, ServiceProtocol
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def test_phase3_service_members_preserve_types_ports_and_icmp6():
    parser = CiscoASAParser("""
object service WEB
 service tcp source range 1024 65535 destination eq https
object-group service MIXED tcp
 service-object object WEB
 service-object udp destination eq domain
 port-object neq 443
object-group protocol PROTOS
 protocol-object gre
object-group icmp-type TYPES
 icmp-object echo
""")
    config = parser.parse_raw()
    group = config.service_groups[0]
    assert [entry.type for entry in group.member_entries] == ["service_object", "inline_service", "port_object"]
    assert config.service_objects[0].ports[0].source.operator == "range"
    assert config.service_objects[0].ports[0].destination.values == ["https"]
    assert config.protocol_groups[0].member_entries[0].type == "protocol"
    assert config.icmp_type_groups[0].member_entries[0].value == "echo"


def test_phase3_unresolved_service_group_reference_is_partial_and_typed():
    config = CiscoASAParser("""
object-group service OUTER tcp
 group-object MISSING
""").parse_raw()
    entry = config.service_groups[0].member_entries[0]
    assert entry.type == "service_group"
    assert entry.resolved is False
    assert config.service_groups[0].migration_status == "PARTIALLY_NORMALIZED"
    assert not any(issue["resolved"] for issue in config.reference_issues if issue["reference_name"] == "MISSING")


def test_service_object_preserves_both_ports_tcp_udp_and_sctp():
    ir = CiscoASAParser("""
object service Both
 service tcp-udp source eq 1024 destination range 8000 9000
object service SctpSvc
 service sctp destination eq 3868
""").transform_to_ir()
    both = next(item for item in ir.services if item.name == "Both")
    assert {port.protocol for port in both.ports} == {ServiceProtocol.TCP, ServiceProtocol.UDP}
    assert all(port.source_port == "1024" and port.port == "8000-9000" for port in both.ports)
    sctp = next(item for item in ir.services if item.name == "SctpSvc")
    assert sctp.ports[0].protocol == ServiceProtocol.SCTP


def test_object_and_twice_nat_retain_ownership_translation_and_order():
    parser = CiscoASAParser("""
object network WEB
 host 10.0.0.10
 nat (inside,outside) static PUBLIC
object network PUBLIC
 host 198.51.100.10
object network DST
 host 203.0.113.1
object network NEWDST
 host 10.0.0.20
nat (inside,outside) 10 source static WEB PUBLIC destination static DST NEWDST service tcp 443
""")
    ir = parser.transform_to_ir()
    object_nat = next(item for item in ir.nat_rules if item.source_attributes["section"] == "object")
    assert object_nat.source == ["WEB"]
    assert object_nat.translated_sources == ["PUBLIC"]
    assert object_nat.source_attributes["owning_object"] == "WEB"
    twice = next(item for item in ir.nat_rules if item.type == NATType.TWICE)
    twice_source = next(item for item in parser.config.nat_rules if item.destination_mode)
    assert twice_source.mapped_destination == "DST"
    assert twice_source.real_destination == "NEWDST"
    assert twice.destination == ["DST"]
    assert twice.translated_destinations == ["NEWDST"]
    assert twice.sequence == 10
    assert twice.requires_manual_review


def test_object_nat_uses_cisco_order_after_source_order_is_reversed():
    ir = CiscoASAParser("""
object network broad
 subnet 10.0.0.0 255.255.255.0
 nat (inside,outside) dynamic interface
object network host-static
 host 10.0.0.10
 nat (inside,outside) static 198.51.100.10
object network subnet-static
 subnet 10.0.0.0 255.255.255.0
 nat (inside,outside) static 198.51.100.11
""").transform_to_ir()
    assert [item.source_attributes["owning_object"] for item in ir.nat_rules] == [
        "host-static", "subnet-static", "broad"
    ]


def test_object_nat_missing_or_fqdn_owner_requires_review():
    cfg = CiscoASAParser("""
object network missing-owner
 fqdn v4 example.invalid
 nat (inside,outside) static 198.51.100.10
""").parse_raw()
    rule = cfg.nat_rules[0]
    assert rule.migration_status == "PARTIALLY_NORMALIZED"
    assert rule.requires_manual_review
    assert "FQDN" in " ".join(rule.review_reasons)
