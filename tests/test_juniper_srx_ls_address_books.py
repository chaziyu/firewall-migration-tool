from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_attached_book_precedes_same_context_global_book():
    ir = JuniperSRXParser("""
    set logical-systems LS1 security zones security-zone trust
    set logical-systems LS1 security zones security-zone untrust
    set logical-systems LS1 security address-book global address WEB 10.1.1.1/32
    set logical-systems LS1 security address-book INSIDE address WEB 10.1.1.2/32
    set logical-systems LS1 security address-book INSIDE attach zone trust
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P match source-address WEB
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P match destination-address any
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P match application any
    """).transform_to_ir()

    assert ir.policies[0].source == ["LS1__INSIDE__WEB"]

