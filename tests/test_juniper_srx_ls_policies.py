from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_policies_are_context_owned_and_predefined_apps_are_shared():
    result = JuniperSRXParser("""
    set logical-systems LS1 security zones security-zone trust
    set logical-systems LS1 security zones security-zone untrust
    set security policies from-zone trust to-zone untrust policy P1 match source-address any
    set security policies from-zone trust to-zone untrust policy P1 match destination-address any
    set security policies from-zone trust to-zone untrust policy P1 match application any
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 match source-address any
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 match destination-address any
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 match application junos-http
    """).extract().canonical_ir

    assert {p.name for p in result.policies} == {"P1", "LS1__P1"}
    assert next(p for p in result.policies if p.name == "LS1__P1").service == ["junos-http"]


def test_logical_system_global_zone_is_rejected():
    parser = JuniperSRXParser("""
    set logical-systems LS1 security policies from-zone global to-zone trust policy BAD match source-address any
    """)
    parser.extract()

    assert any(c.parse_error for c in parser.config.unsupported_commands)
