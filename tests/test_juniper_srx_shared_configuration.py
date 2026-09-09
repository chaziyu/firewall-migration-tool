from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_root_custom_application_does_not_resolve_in_logical_system():
    ir = JuniperSRXParser("""
    set applications application ROOT-ONLY term T protocol tcp
    set logical-systems LS1 security zones security-zone trust
    set logical-systems LS1 security zones security-zone untrust
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P match source-address any
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P match destination-address any
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P match application ROOT-ONLY
    """).transform_to_ir()

    assert ir.policies[0].service == ["LS1__ROOT-ONLY"]
    assert ir.policies[0].requires_manual_review
