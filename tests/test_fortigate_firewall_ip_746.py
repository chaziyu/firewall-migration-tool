from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.model import FGIPPool
from fwmigrate.parsers.fortigate.firewall_ip_746 import (
    FORTIOS_746_IPPOOL_FIELDS,
    FORTIOS_746_IPPOOL6_DEFAULTS,
    FORTIOS_746_IPPOOL_TYPES,
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
