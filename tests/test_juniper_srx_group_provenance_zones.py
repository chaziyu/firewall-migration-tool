from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_zone_scalar_member_and_excluded_history():
    cfg = JuniperSRXParser("""
set groups G1 security zones security-zone trust description inherited
set groups G1 security zones security-zone trust interfaces ge-0/0/0.0
set security zones security-zone trust apply-groups-except G1
set security zones security-zone trust description local
""").parse_raw()
    zone = cfg.contexts["root"].zones["trust"]
    assert zone.description == "local"
    assert [c.value for c in zone.member_candidate_history["interfaces"]] == ["ge-0/0/0.0"]
    assert zone.member_candidate_history["interfaces"][0].status.value == "EXCLUDED"
    assert [c.status.value for c in zone.field_candidate_history["description"]] == ["EXCLUDED", "EFFECTIVE"]
