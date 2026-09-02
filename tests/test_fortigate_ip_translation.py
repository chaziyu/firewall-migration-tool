from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_ip_translation_is_typed_and_preserves_unknown_settings():
    config = FortiGateParser(FortiGateTokenizer("""
config firewall ip-translation
    edit 7
        set type SCTP
        set startip 10.0.0.1
        set endip 10.0.0.4
        set map-startip 192.0.2.1
        set future-setting keep
    next
end
""")).parse()

    rule = config.ip_translations[0]
    assert (rule.id, rule.source_order) == (7, 1)
    assert (rule.startip, rule.endip, rule.map_startip) == (
        "10.0.0.1", "10.0.0.4", "192.0.2.1"
    )
    assert rule.extra_settings["future_setting"] == "keep"


def test_sctp_ip_translation_is_normalized_as_an_address_range_mapping():
    result = extract_fortigate_config("""
config firewall ip-translation
    edit 7
        set type SCTP
        set startip 10.0.0.1
        set endip 10.0.0.4
        set map-startip 192.0.2.1
    next
end
""")

    rule = result.canonical_ir.nat_rules[0]
    assert rule.type.value == "address-translation"
    assert rule.address_range_mappings[0].translated_end == "192.0.2.4"
    assert rule.protocol_name == "SCTP"
    assert rule.migration_status == "NORMALIZED"
