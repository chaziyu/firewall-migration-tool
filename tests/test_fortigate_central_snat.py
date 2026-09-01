from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_central_snat_extracts_typed_fields_and_preserves_list_order():
    config = parse_fortigate_config("""config firewall central-snat-map
    edit 10
        set uuid "11111111-2222-3333-4444-555555555555"
        set type ipv4
        set srcintf "port2" "port1"
        set dstintf "wan1"
        set orig-addr "SRC_Z" "SRC_A" "SRC_M"
        set dst-addr "DST_B" "DST_A"
        set protocol 6
        set orig-port 1000-2000
        set dst-port 443
        set nat-ippool "POOL_B" "POOL_A"
        set nat-port 40000-50000
        set port-preserve disable
        set comments "IPv4 central SNAT"
    next
end
""")

    rule = config.central_snat_rules[0]
    assert rule.uuid == "11111111-2222-3333-4444-555555555555"
    assert rule.type == "ipv4"
    assert rule.srcintf == ["port2", "port1"]
    assert rule.orig_addr == ["SRC_Z", "SRC_A", "SRC_M"]
    assert rule.dst_addr == ["DST_B", "DST_A"]
    assert rule.nat_ippool == ["POOL_B", "POOL_A"]
    assert rule.protocol == "6"
    assert rule.port_preserve == "disable"


def test_central_snat_preserves_ipv6_lists_as_lists_in_source_ir():
    result = extract_fortigate_config("""config firewall central-snat-map
    edit 20
        set type ipv6
        set orig-addr6 "SRC6_Z" "SRC6_A"
        set dst-addr6 "DST6_B" "DST6_A"
        set nat-ippool6 "POOL6_B" "POOL6_A"
    next
end
""")

    rule = result.canonical_ir.central_snat_rules[0]
    assert rule.migration_status == "PARTIALLY_NORMALIZED"
    assert rule.requires_manual_review is True
    assert rule.source_attributes["type"] == "ipv6"
    for field, expected in {
        "orig_addr6": ["SRC6_Z", "SRC6_A"],
        "dst_addr6": ["DST6_B", "DST6_A"],
        "nat_ippool6": ["POOL6_B", "POOL6_A"],
    }.items():
        assert rule.source_attributes[field] == expected
        assert isinstance(rule.source_attributes[field], list)
    assert result.canonical_ir.nat_rules == []
    assert result.canonical_ir.policies == []
    assert result.canonical_ir.routes == []


def test_central_snat_effective_defaults_do_not_create_source_commands():
    result = extract_fortigate_config("""config firewall central-snat-map
    edit 30
        set srcintf "lan"
        set dstintf "wan"
    next
end
""")

    rule = result.canonical_ir.central_snat_rules[0]
    assert {key: rule.source_attributes[key] for key in (
        "status", "type", "nat", "nat46", "nat64", "port_preserve"
    )} == {
        "status": "enable", "type": "ipv4", "nat": "enable",
        "nat46": "disable", "nat64": "disable", "port_preserve": "enable",
    }
    item = next(item for item in result.inventory_items if item.source_id == "30")
    assert {command.key for command in item.commands}.isdisjoint(
        {"status", "type", "nat", "nat46", "nat64", "port-preserve"}
    )


def test_central_snat_explicit_values_override_defaults_and_unknowns_remain():
    config = parse_fortigate_config("""config firewall central-snat-map
    edit 40
        set status disable
        set type ipv6
        set nat disable
        set nat46 enable
        set nat64 enable
        set port-preserve disable
        set custom-future-setting "abc"
    next
end
""")

    rule = config.central_snat_rules[0]
    assert (rule.status, rule.type, rule.nat) == ("disable", "ipv6", "disable")
    assert (rule.nat46, rule.nat64, rule.port_preserve) == ("enable", "enable", "disable")
    assert rule.extra_settings["custom_future_setting"] == "abc"
