from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_central_snat_is_normalized_in_source_order_with_pool_and_ports():
    extraction = extract_fortigate_config("""
config system global
    set central-nat enable
end
config firewall ippool
    edit "pool1"
        set startip 198.51.100.10
        set endip 198.51.100.20
    next
end
config firewall central-snat-map
    edit 20
        set srcintf "lan"
        set dstintf "wan"
        set orig-addr "all"
        set dst-addr "all"
        set protocol 6
        set orig-port 1000-2000
        set dst-port 443
        set nat-ippool enable
        set nat-ippool pool1
        set nat-port 40000-40010
    next
    edit 10
        set srcintf "lan"
        set dstintf "wan"
        set orig-addr "all"
        set dst-addr "all"
        set nat disable
    next
end
""")

    rules = extraction.canonical_ir.nat_rules
    assert [rule.sequence for rule in rules] == [1, 2]
    assert rules[0].source_pool_references == ["pool1"]
    assert rules[0].translated_sources == ["198.51.100.10-198.51.100.20"]
    assert rules[0].original_source_ports[0].start == 1000
    assert rules[0].translated_source_ports[0].end == 40010
    assert rules[1].source_translation_mode.value == "none"
