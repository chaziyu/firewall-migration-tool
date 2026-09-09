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


def test_transformer_uses_effective_interface_and_address_values():
    result = JuniperSRXParser("""
set groups G interfaces ge-0/0/0 unit 0 description weak
set groups G interfaces ge-0/0/0 unit 0 vlan-id 10
set groups G security address-book global address server 192.0.2.1/32
set apply-groups G
set interfaces ge-0/0/0 unit 0 description strong
set interfaces ge-0/0/0 unit 0 vlan-id 20
set security address-book global address server 198.51.100.1/32
""").extract().canonical_ir
    interface = next(i for i in result.interfaces if i.name == "ge-0/0/0.0")
    address = next(a for a in result.addresses if a.name == "server")
    assert interface.description == "strong"
    assert interface.vlanid == 20
    assert address.subnet == "198.51.100.1/32"


def test_transformer_uses_effective_route_and_nat_values():
    result = JuniperSRXParser("""
set groups G routing-options static route 10.0.0.0/8 preference 20
set groups G security nat source rule-set rs rule r then source-nat interface
set apply-groups G
set routing-options static route 10.0.0.0/8 preference 10
set security nat source rule-set rs rule r then source-nat off
""").extract().canonical_ir
    route = next(r for r in result.routes if r.destination == "10.0.0.0/8")
    nat = next(r for r in result.nat_rules if r.name == "r")
    assert route.administrative_distance == 10
    assert nat.source_translation_mode.value == "none"


def test_transformer_uses_effective_scheduler_window():
    result = JuniperSRXParser("""
set groups G schedulers scheduler work start-date 2026-01-01.00:00:00
set groups G schedulers scheduler work daily 09:00 to 10:00
set apply-groups G
set schedulers scheduler work start-date 2026-02-01.00:00:00
set schedulers scheduler work daily 11:00 to 12:00
""").extract().canonical_ir
    scheduler = next(s for s in result.schedules if s.name == "work")
    assert scheduler.start == "2026-02-01.00:00:00"
    assert scheduler.hours_ranges == [
        {"values": ["09:00", "to", "10:00"]},
        {"values": ["11:00", "to", "12:00"]},
    ]
