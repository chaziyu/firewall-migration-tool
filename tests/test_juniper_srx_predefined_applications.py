from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser
from fwmigrate.parsers.juniper_srx.resolver import JuniperReferenceResolver


def test_predefined_and_custom_application_scope_resolution():
    parser = JuniperSRXParser("""
    set applications application ROOT protocol tcp
    set tenants T applications application APP1 protocol tcp
    set logical-systems LS applications application APP1 protocol tcp
    """)
    parser.extract()
    root = JuniperReferenceResolver(parser.config.contexts["root"])
    assert root.resolve_application("junos-http")[2] == "junos-http"
    assert root.resolve_application("junos-h323-suite")[1]
    assert root.resolve_application("junos-smtp")[2] == "junos-smtp"
    assert root.resolve_application("junos-foo")[2] is None
    assert root.is_unverified_application("junos-foo")
    assert root.resolve_application("ROOT")[2] == "ROOT"
    assert JuniperReferenceResolver(parser.config.contexts["T"]).resolve_application("APP1")[2] == "T__APP1"
    assert JuniperReferenceResolver(parser.config.contexts["LS"]).resolve_application("APP1")[2] == "LS__APP1"


def test_unknown_predefined_looking_application_requires_review():
    ir = JuniperSRXParser("""
    set security policies from-zone trust to-zone untrust policy P match source-address any
    set security policies from-zone trust to-zone untrust policy P match destination-address any
    set security policies from-zone trust to-zone untrust policy P match application junos-foo
    set security policies from-zone trust to-zone untrust policy P then permit
    """).transform_to_ir()
    assert ir.policies[0].requires_manual_review
    assert any("Unverified predefined-looking" in reason for reason in ir.policies[0].review_reasons)
