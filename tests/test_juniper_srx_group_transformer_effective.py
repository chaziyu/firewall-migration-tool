from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_transformer_emits_effective_scalar_and_member_once():
    result = JuniperSRXParser("""
set groups G1 security zones security-zone z description inherited
set groups G1 security zones security-zone z interfaces ge-0/0/0.0
set apply-groups G1
set security zones security-zone z description local
set security zones security-zone z interfaces ge-0/0/0.0
""").extract()
    zone = next(zone for zone in result.canonical_ir.zones if zone.name == "z")
    assert zone.description == "local"
    assert zone.interfaces == ["ge-0/0/0.0"]
