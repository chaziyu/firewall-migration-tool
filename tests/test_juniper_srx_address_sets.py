from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser
from fwmigrate.parsers.juniper_srx.resolver import JuniperReferenceResolver


def resolve(text, name="A"):
    context = JuniperSRXParser(text).parse_raw().contexts["root"]
    return JuniperReferenceResolver(context).expand_address_set(context.address_books["global"], name)


def test_address_set_diamond_is_not_a_cycle():
    members, has_cycle = resolve("""
    set security address-book global address-set D address 192.0.2.4/32
    set security address-book global address-set A address-set B
    set security address-book global address-set A address-set C
    set security address-book global address-set B address-set D
    set security address-book global address-set C address-set D
    """)
    assert has_cycle is False
    assert members == ["192.0.2.4/32"]


def test_address_set_cycles_are_detected_without_recursing_forever():
    for links in (
        "set security address-book global address-set A address-set A",
        "set security address-book global address-set A address-set B\nset security address-book global address-set B address-set A",
        "set security address-book global address-set A address-set B\nset security address-book global address-set B address-set C\nset security address-book global address-set C address-set A",
    ):
        _, has_cycle = resolve(links)
        assert has_cycle is True
