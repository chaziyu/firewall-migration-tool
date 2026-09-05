from fwmigrate.ir.enums import NATType
from fwmigrate.parsers.cisco_asa.parser import CiscoASAParser


def _objects() -> str:
    return """
object network REAL
 host 10.0.0.10
object network MAPPED
 host 198.51.100.10
object network PUBLIC_DST
 host 203.0.113.10
object network PRIVATE_DST
 host 10.0.0.20
object network PAT_POOL
 range 198.51.100.20 198.51.100.30
"""


def test_twice_nat_destination_operands_follow_mapped_real_grammar():
    parser = CiscoASAParser(_objects() + "nat (inside,outside) source static REAL MAPPED destination static PUBLIC_DST PRIVATE_DST")
    ir = parser.transform_to_ir()
    source = parser.config.nat_rules[0]
    assert source.mapped_destination == "PUBLIC_DST"
    assert source.real_destination == "PRIVATE_DST"
    rule = ir.nat_rules[0]
    assert rule.type == NATType.TWICE
    assert rule.destination == ["PUBLIC_DST"]
    assert rule.translated_destinations == ["PRIVATE_DST"]
    assert rule.source == ["REAL"]
    assert rule.translated_sources == ["MAPPED"]


def test_nat_without_interface_tuple_is_interface_independent_not_malformed():
    parser = CiscoASAParser(_objects() + "nat source static REAL MAPPED")
    parser.transform_to_ir()
    rule = parser.config.nat_rules[0]
    assert rule.source_interface is None
    assert rule.destination_interface is None
    assert rule.migration_status != "PARSE_ERROR"


def test_pat_pool_and_modifiers_are_preserved_safely():
    parser = CiscoASAParser(_objects() + "nat (inside,outside) source dynamic REAL pat-pool PAT_POOL round-robin extended flat include-reserve block-allocation")
    ir = parser.transform_to_ir()
    rule = parser.config.nat_rules[0]
    assert rule.mapped_source_mode == "pat_pool"
    assert rule.pat_pool == "PAT_POOL"
    assert rule.mapped_source == "PAT_POOL"
    assert rule.pat_pool_options == ["round-robin", "extended", "flat", "include-reserve", "block-allocation"]
    assert rule.requires_manual_review
    assert ir.nat_rules[0].source_attributes["pat_pool"] == "PAT_POOL"


def test_interface_ipv6_translation_is_not_collapsed():
    parser = CiscoASAParser(_objects() + "nat (inside,outside) source dynamic REAL interface ipv6")
    ir = parser.transform_to_ir()
    rule = parser.config.nat_rules[0]
    assert rule.mapped_source_mode == "interface"
    assert rule.mapped_source_address_family == "ipv6"
    assert ir.nat_rules[0].source_attributes["mapped_source_address_family"] == "ipv6"
    assert ir.nat_rules[0].requires_manual_review


def test_object_nat_static_pat_preserves_protocol_and_ports():
    parser = CiscoASAParser("""
object network WEB
 host 10.0.0.10
 nat (inside,outside) static 198.51.100.10 service tcp 80 8080 no-proxy-arp
""")
    ir = parser.transform_to_ir()
    source = parser.config.nat_rules[0]
    assert source.owning_object == "WEB"
    assert source.service_protocol == "tcp"
    assert source.original_service == "80"
    assert source.translated_service == "8080"
    assert source.no_proxy_arp
    assert ir.nat_rules[0].translated_services == ["8080"]
    assert ir.nat_rules[0].requires_manual_review


def test_nat_effective_order_retains_all_three_asa_sections():
    parser = CiscoASAParser("""
nat (inside,outside) 10 source static REAL MAPPED
object network REAL
 host 10.0.0.10
 nat (inside,outside) static MAPPED
nat (inside,outside) after-auto 5 source dynamic REAL interface
object network MAPPED
 host 198.51.100.10
""")
    ir = parser.transform_to_ir()
    assert [item.source_attributes["section"] for item in ir.nat_rules] == ["manual", "object", "after-auto"]
    assert [item.source_attributes["section_order"] for item in ir.nat_rules] == [1, 2, 3]
    assert [item.source_attributes["source_sequence"] for item in ir.nat_rules] == [10, None, 5]


def test_object_nat_static_precedes_dynamic_even_when_source_order_is_reversed():
    parser = CiscoASAParser("""
object network DYNAMIC
 host 10.0.0.20
 nat (inside,outside) dynamic interface
object network STATIC
 host 10.0.0.10
 nat (inside,outside) static 198.51.100.10
""")
    ir = parser.transform_to_ir()
    assert [item.source_attributes["owning_object"] for item in ir.nat_rules] == ["STATIC", "DYNAMIC"]
    assert [item.source_attributes["object_nat_precedence"] for item in ir.nat_rules] == [0, 1]


def test_object_nat_static_quantity_order_beats_source_order_and_prefix_length():
    parser = CiscoASAParser("""
object network BROAD_STATIC
 subnet 10.0.0.0 255.255.255.0
 nat (inside,outside) static 198.51.100.20
object network SMALL_STATIC
 range 10.0.0.10 10.0.0.11
 nat (inside,outside) static 198.51.100.10
""")
    ir = parser.transform_to_ir()
    assert [item.source_attributes["owning_object"] for item in ir.nat_rules] == ["SMALL_STATIC", "BROAD_STATIC"]
    assert [item.source_attributes["effective_order_inputs"]["address_quantity"] for item in ir.nat_rules] == [2, 256]
    assert parser.config.nat_rules[0].source_order < parser.config.nat_rules[1].source_order
    assert ir.nat_rules[0].source_attributes["source_order"] > ir.nat_rules[1].source_attributes["source_order"]


def test_object_nat_dynamic_quantity_order_beats_source_order():
    parser = CiscoASAParser("""
object network BROAD_DYNAMIC
 subnet 10.0.0.0 255.255.255.0
 nat (inside,outside) dynamic interface
object network SMALL_DYNAMIC
 range 10.0.0.10 10.0.0.11
 nat (inside,outside) dynamic interface
""")
    ir = parser.transform_to_ir()
    assert [item.source_attributes["owning_object"] for item in ir.nat_rules] == ["SMALL_DYNAMIC", "BROAD_DYNAMIC"]
    assert [item.source_attributes["object_nat_specificity"] for item in ir.nat_rules] == [2, 256]


def test_object_nat_same_quantity_and_ip_uses_object_name_tiebreak():
    ir = CiscoASAParser("""
object network Z_OBJECT
 host 10.0.0.10
 nat (inside,outside) dynamic interface
object network A_OBJECT
 host 10.0.0.10
 nat (inside,outside) dynamic interface
""").transform_to_ir()
    assert [item.source_attributes["owning_object"] for item in ir.nat_rules] == ["A_OBJECT", "Z_OBJECT"]


def test_object_nat_malformed_owner_is_partial_with_raw_evidence():
    parser = CiscoASAParser("""
object network BROKEN_OWNER
 subnet not-an-ip 255.255.255.0
 nat (inside,outside) static 198.51.100.10
""")
    parser.transform_to_ir()
    rule = parser.config.nat_rules[0]
    assert rule.migration_status == "PARTIALLY_NORMALIZED"
    assert rule.requires_manual_review
    assert "malformed" in " ".join(rule.review_reasons)
    assert rule.raw_line == "nat (inside,outside) static 198.51.100.10"
    assert rule.source_attributes["raw_command"] == rule.raw_line
    assert "address_quantity" not in rule.effective_order_inputs


def test_object_nat_missing_owner_is_partial_without_guessed_specificity():
    parser = CiscoASAParser("")
    parser._parse_nat_line("nat (inside,outside) static 198.51.100.10", 1, owning_object="MISSING_OWNER")
    parser._compute_object_nat_order()
    rule = parser.config.nat_rules[0]
    assert rule.migration_status == "PARTIALLY_NORMALIZED"
    assert rule.requires_manual_review
    assert rule.object_nat_precedence == 0
    assert rule.object_nat_specificity is None
    assert "address_quantity" not in rule.effective_order_inputs


def test_object_nat_unresolved_source_reference_is_partial_without_any_fallback():
    parser = CiscoASAParser("nat (inside,outside) source static MISSING 198.51.100.10")
    ir = parser.transform_to_ir()
    rule = ir.nat_rules[0]
    assert rule.source == ["MISSING"]
    assert rule.requires_manual_review
    assert rule.migration_status == "PARTIALLY_NORMALIZED"
    assert "MISSING" in rule.review_reasons[-1]


def test_malformed_object_nat_is_parse_error_with_source_order_preserved():
    parser = CiscoASAParser("""
object network BROKEN_NAT
 host 10.0.0.10
 nat (inside,outside) 1
""")
    parser.transform_to_ir()
    rule = parser.config.nat_rules[0]
    assert rule.migration_status == "PARSE_ERROR"
    assert rule.requires_manual_review
    assert rule.source_order_within_section == 1
    assert rule.raw_line == "nat (inside,outside) 1"


def test_nat_exemption_is_preserved_as_extract_only():
    parser = CiscoASAParser("nat (inside,outside) 0 access-list NAT_EXEMPT")
    parser.transform_to_ir()
    rule = parser.config.nat_rules[0]
    assert rule.nat_exemption and rule.access_list == "NAT_EXEMPT"
    assert rule.migration_status == "EXTRACT_ONLY"
