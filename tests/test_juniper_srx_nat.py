from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.enums import NATTranslationMode, NATType
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_source_nat_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "nat_source.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    nat_dict = {n.name: n for n in ir.nat_rules}

    # Pool NAT
    assert "r1" in nat_dict
    assert nat_dict["r1"].type == NATType.SOURCE
    assert nat_dict["r1"].source_translation_mode == NATTranslationMode.POOL
    assert nat_dict["r1"].source_pool_references == ["src_pool_1"]

    # Interface NAT
    assert "r2_interface" in nat_dict
    assert nat_dict["r2_interface"].type == NATType.SOURCE
    assert nat_dict["r2_interface"].source_translation_mode == NATTranslationMode.INTERFACE_ADDRESS

    # NAT off
    assert "r3_off" in nat_dict
    assert nat_dict["r3_off"].type == NATType.SOURCE
    assert nat_dict["r3_off"].source_translation_mode == NATTranslationMode.NONE

    assert_no_silent_loss(res, total_input_commands=17)

def test_destination_nat_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "nat_destination.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    nat_dict = {n.name: n for n in ir.nat_rules}
    assert "r_vip" in nat_dict
    assert nat_dict["r_vip"].type == NATType.DESTINATION
    assert "172.16.1.100/32" in nat_dict["r_vip"].translated_destinations

    assert_no_silent_loss(res, total_input_commands=11)

def test_static_nat_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "nat_static.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    nat_dict = {n.name: n for n in ir.nat_rules}
    assert "r_static_server" in nat_dict
    assert nat_dict["r_static_server"].requires_manual_review is True

    assert_no_silent_loss(res, total_input_commands=7)

def test_nat_with_port_protocol_and_context_restrictions():
    content = """
    set version 21.4R1.12
    set system host-name SRX-NAT-Ext
    set security nat source rule-set rs_port from interface ge-0/0/0.0
    set security nat source rule-set rs_port to zone untrust
    set security nat source rule-set rs_port rule r_port match source-address 10.0.0.0/24
    set security nat source rule-set rs_port rule r_port match destination-address 0.0.0.0/0
    set security nat source rule-set rs_port rule r_port match protocol tcp
    set security nat source rule-set rs_port rule r_port match destination-port 443
    set security nat source rule-set rs_port rule r_port then source-nat interface
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    r = next(n for n in ir.nat_rules if n.name == "r_port")
    assert r.requires_manual_review is True
    assert r.migration_status == "PARTIALLY_NORMALIZED"
    assert any("port/protocol" in reason for reason in r.review_reasons)
    assert any("interface or routing-instance" in reason for reason in r.review_reasons)

def test_nat_address_name_resolution():
    content = """
    set version 21.4R1.12
    set system host-name SRX-NAT-Addr
    set security address-book global address web_vip 198.51.100.50/32
    set security nat destination pool dst_pool address 10.1.1.50/32
    set security nat destination rule-set rs_dnat from zone untrust
    set security nat destination rule-set rs_dnat rule r_dnat match destination-address-name web_vip
    set security nat destination rule-set rs_dnat rule r_dnat then destination-nat pool dst_pool
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    r = next(n for n in ir.nat_rules if n.name == "r_dnat")
    assert "web_vip" in r.destination


def test_nat_unresolved_pools_and_unknown_matches():
    content = """
    set version 21.4R1.12
    set system host-name SRX-NAT-Hardening
    set security nat source rule-set rs_snat from zone trust
    set security nat source rule-set rs_snat to zone untrust
    set security nat source rule-set rs_snat rule r_unresolved_pool match source-address 10.0.0.0/24
    set security nat source rule-set rs_snat rule r_unresolved_pool match destination-address 0.0.0.0/0
    set security nat source rule-set rs_snat rule r_unresolved_pool then source-nat pool non_existent_pool
    set security nat source rule-set rs_snat rule r_unknown_match match source-address 10.1.0.0/24
    set security nat source rule-set rs_snat rule r_unknown_match match proprietary-feature enabled
    set security nat source rule-set rs_snat rule r_unknown_match then source-nat interface
    set security nat destination rule-set rs_dnat from zone untrust
    set security nat destination rule-set rs_dnat rule r_unresolved_dst_pool match destination-address 198.51.100.1/32
    set security nat destination rule-set rs_dnat rule r_unresolved_dst_pool then destination-nat pool missing_dpool
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    nat_dict = {n.name: n for n in ir.nat_rules}

    # 1. Unresolved source pool
    r_snat = nat_dict["r_unresolved_pool"]
    assert r_snat.requires_manual_review is True
    assert r_snat.migration_status == "PARTIALLY_NORMALIZED"
    assert r_snat.source_pool_references == ["non_existent_pool"]
    assert r_snat.translated_sources == []
    assert any("Unresolved source NAT pool: non_existent_pool" in reason for reason in r_snat.review_reasons)

    # 2. Unknown match condition: must NOT pollute source_addresses
    r_match = nat_dict["r_unknown_match"]
    assert r_match.requires_manual_review is True
    assert r_match.migration_status == "PARTIALLY_NORMALIZED"
    assert r_match.source == ["10.1.0.0/24"]
    assert "proprietary-feature_enabled" not in r_match.source
    assert "proprietary-feature enabled" in r_match.source_attributes.get("unknown_match_conditions", [])

    # 3. Unresolved destination pool
    r_dnat = nat_dict["r_unresolved_dst_pool"]
    assert r_dnat.requires_manual_review is True
    assert r_dnat.migration_status == "PARTIALLY_NORMALIZED"
    assert r_dnat.destination_pool_references == ["missing_dpool"]
    assert r_dnat.translated_destinations == []
    assert any("Unresolved destination NAT pool: missing_dpool" in reason for reason in r_dnat.review_reasons)

    assert_no_silent_loss(res, total_input_commands=13)


def test_static_nat_prefix_name_and_mapped_port():
    content = """
    set version 21.4R1.12
    set system host-name SRX-Static-NAT
    set security nat static rule-set rs_stat from zone untrust
    set security nat static rule-set rs_stat rule r_pfx match destination-address 198.51.100.10/32
    set security nat static rule-set rs_stat rule r_pfx then static-nat prefix-name internal_srv
    set security nat static rule-set rs_stat rule r_pfx then static-nat mapped-port 8443
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    # Under zero-fabrication invariant, static NAT rules without real IP prefix are withheld from canonical IRNATRule
    assert len(ir.nat_rules) == 0
    assert any("internal_srv" in str(item.commands) or "mapped-port" in str(item.commands) for item in res.inventory_items)
    assert_no_silent_loss(res, total_input_commands=6)


def test_source_nat_pool_port_and_attributes_provenance_preserved():
    """Verify that source NAT pool port constraints and attributes are preserved in rule source_attributes."""
    content = """
    set version 21.4R1.12
    set system host-name SRX-Pool-Provenance
    set security nat source pool my_pat_pool address 203.0.113.10/32
    set security nat source pool my_pat_pool port range 5000 to 6000
    set security nat source rule-set rs1 from zone trust
    set security nat source rule-set rs1 to zone untrust
    set security nat source rule-set rs1 rule r1 match source-address 10.0.0.0/24
    set security nat source rule-set rs1 rule r1 match destination-address 0.0.0.0/0
    set security nat source rule-set rs1 rule r1 then source-nat pool my_pat_pool
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    assert len(ir.nat_rules) == 1
    r = ir.nat_rules[0]
    assert r.requires_manual_review is True
    assert "pool_ports" in r.source_attributes
    assert "5000-6000" in r.source_attributes["pool_ports"] or "5000" in str(r.source_attributes["pool_ports"])
    assert any("port/PAT constraints" in reason for reason in r.review_reasons)


def test_static_nat_prefix_syntax_validation():
    """Verify that static NAT prefix is validated; malformed prefixes are marked PARSE_ERROR and withheld from IRNATRule."""
    content_valid = """
    set version 21.4R1.12
    set system host-name SRX-Static-Valid
    set security nat static rule-set rs_stat from zone untrust
    set security nat static rule-set rs_stat rule r_valid match destination-address 198.51.100.10/32
    set security nat static rule-set rs_stat rule r_valid then static-nat prefix 10.1.1.10/32
    """
    res_valid = PluginRegistry.get_parser("juniper_srx").extract(content_valid)
    assert len(res_valid.canonical_ir.nat_rules) == 1
    assert res_valid.canonical_ir.nat_rules[0].translated_destinations == ["10.1.1.10/32"]

    content_invalid = """
    set version 21.4R1.12
    set system host-name SRX-Static-Invalid
    set security nat static rule-set rs_stat from zone untrust
    set security nat static rule-set rs_stat rule r_invalid match destination-address 198.51.100.10/32
    set security nat static rule-set rs_stat rule r_invalid then static-nat prefix invalid_not_an_ip
    """
    res_invalid = PluginRegistry.get_parser("juniper_srx").extract(content_invalid)
    assert len(res_invalid.canonical_ir.nat_rules) == 0
    assert any("invalid_not_an_ip" in str(item.raw_capture) for item in res_invalid.unsupported_items)
    assert any("Invalid static NAT prefix" in item.reason or "Syntax error" in item.reason for item in res_invalid.unsupported_items)

