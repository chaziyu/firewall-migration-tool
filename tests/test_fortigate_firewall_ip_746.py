from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.firewall_ip_746 import (
    FORTIOS_746_IPPOOL_FIELDS,
    FORTIOS_746_IPPOOL6_DEFAULTS,
    FORTIOS_746_IPPOOL_TYPES,
)


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
