from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser

def test_ipv6_address_book_prefix_is_validated_as_ipv6():
    a = JuniperSRXParser("set security address-book global address v6 2001:db8::/64").parse_raw().contexts["root"].address_books["global"].addresses["v6"]
    assert a.prefix == "2001:db8::/64"
