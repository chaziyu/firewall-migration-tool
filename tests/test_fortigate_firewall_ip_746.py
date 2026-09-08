from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.model import FGIPPool
from fwmigrate.parsers.fortigate.firewall_ip_746 import (
    FORTIOS_746_IPPOOL_FIELDS,
    FORTIOS_746_IPPOOL6_DEFAULTS,
    FORTIOS_746_IPPOOL_TYPES,
    effective_ippool_settings,
    FORTIOS_746_IPV6_EH_DEFAULTS,
    effective_ipv6_eh_filter_settings,
    validate_ipv6_eh_filter_746,
    validate_ippool6_746,
    validate_ippool_746,
)
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.generators.target_helpers import is_generation_safe_object


def test_ippool_tracks_explicit_fields_and_unset():
    config = '''
config firewall ippool
    edit "POOL1"
        set startip 203.0.113.10
        set arp-reply disable
        unset arp-reply
    next
end
'''

    pool = FortiGateParser(FortiGateTokenizer(config)).parse().ip_pools[0]

    assert pool.source_explicit_fields == {"startip"}
    assert pool.arp_reply == "enable"
    assert "type" not in pool.source_explicit_fields


def test_ippool6_tracks_explicit_fields():
    config = '''
config firewall ippool6
    edit "POOL6"
        set startip 2001:db8::10
        set nat46 enable
    next
end
'''

    pool = FortiGateParser(FortiGateTokenizer(config)).parse().ip_pools6[0]

    assert pool.source_explicit_fields == {"startip", "nat46"}


def test_fortios_746_contract_constants_are_centralized():
    assert "cgn-resource-allocation" in FORTIOS_746_IPPOOL_TYPES
    assert "startip" in FORTIOS_746_IPPOOL_FIELDS
    assert FORTIOS_746_IPPOOL6_DEFAULTS["startip"] == "::"


def test_ippool_validation_rejects_official_range_and_address_errors():
    pool = FGIPPool(
        name="POOL1",
        block_size=63,
        startip="not-an-ip",
        endip="203.0.113.10",
    )

    reasons = validate_ippool_746(pool)

    assert any("block-size value 63" in reason for reason in reasons)
    assert any("invalid IPv4 address 'not-an-ip'" in reason for reason in reasons)


def test_cgn_resource_allocation_is_retained_but_not_generation_safe():
    result = extract_fortigate_config('''
config firewall ippool
    edit "CGN"
        set type cgn-resource-allocation
    next
end
''')

    pool = result.canonical_ir.ip_pools[0]
    assert pool.pool_type == "cgn-resource-allocation"
    assert pool.migration_status == "PARTIALLY_NORMALIZED"
    assert pool.requires_manual_review is True
    assert "hyperscale" in pool.audit_note
    assert is_generation_safe_object(pool) is False


def test_malformed_numeric_values_remain_in_source_evidence():
    result = extract_fortigate_config('''
config firewall ippool
    edit "POOL1"
        set block-size malformed
    next
end
''')

    pool = result.canonical_ir.ip_pools[0]
    assert pool.block_size is None
    assert pool.source_attributes["unparsed_block_size"] == "malformed"
    assert pool.requires_manual_review is True
    assert "invalid source value for block-size" in pool.audit_note


def test_effective_defaults_are_separate_from_explicit_values():
    pool = FGIPPool(
        name="POOL1",
        startip="203.0.113.10",
        source_explicit_fields={"startip"},
    )

    effective = effective_ippool_settings(pool)

    assert effective["startip"] == "203.0.113.10"
    assert effective["type"] == "overload"
    assert effective["arp_reply"] == "enable"
    assert effective["add_nat64_route"] == "enable"
    assert "comments" not in effective


def test_ippool6_validation_keeps_invalid_source_value_visible():
    config = '''
config firewall ippool6
    edit "POOL6"
        set startip not-an-ipv6
        set endip 2001:db8::10
        set nat46 maybe
    next
end
'''
    parsed = FortiGateParser(FortiGateTokenizer(config)).parse()
    pool = parsed.ip_pools6[0]

    reasons = validate_ippool6_746(pool)
    assert pool.startip == "not-an-ipv6"
    assert any("invalid IPv6 address" in reason for reason in reasons)
    assert any("nat46 has invalid" in reason for reason in reasons)


def test_ippool6_is_extract_only_even_when_valid():
    result = extract_fortigate_config('''
config firewall ippool6
    edit "POOL6"
        set startip 2001:db8::10
        set endip 2001:db8::20
    next
end
''')

    pool = result.canonical_ir.ip_pools[0]
    assert pool.migration_status == "EXTRACT_ONLY"
    assert result.source_sections[0].status.value == "EXTRACT_ONLY"


def test_ipv6_eh_filter_is_typed_source_inventory_with_effective_defaults():
    result = extract_fortigate_config('''
config firewall ipv6-eh-filter
    set routing enable
    set hdopt-type 0 255
    set routing-type 255
    set future-setting abc
end
''')

    item = next(
        item for item in result.inventory_items
        if item.source_path == "firewall ipv6-eh-filter"
    )
    attrs = item.source_attributes
    assert attrs["routing"] == "enable"
    assert attrs["hdopt_type"] == [0, 255]
    assert attrs["routing_type"] == 255
    assert attrs["source_explicit_fields"] == [
        "future_setting", "hdopt_type", "routing", "routing_type"
    ]
    assert attrs["source_effective_settings"]["routing"] == "enable"
    assert attrs["source_effective_settings"]["auth"] == "disable"
    assert attrs["additional_settings"]["future_setting"] == "abc"
    assert item.status.value == "EXTRACT_ONLY"
    assert result.source_sections[0].status.value == "EXTRACT_ONLY"
    assert not hasattr(result.canonical_ir, "ipv6_eh_filter")


def test_ipv6_eh_filter_validation_preserves_invalid_values():
    config = '''
config firewall ipv6-eh-filter
    set hdopt-type 0 1 2 3 4 5 6 256
    set routing-type 256
end
'''
    parsed = FortiGateParser(FortiGateTokenizer(config)).parse()
    item = parsed.ipv6_eh_filter
    reasons = validate_ipv6_eh_filter_746(item)

    assert item.hdopt_type[-1] == 256
    assert any("at most seven" in reason for reason in reasons)
    assert any("outside range 0-255" in reason for reason in reasons)
    assert effective_ipv6_eh_filter_settings(item)["routing"] == (
        FORTIOS_746_IPV6_EH_DEFAULTS["routing"]
    )
