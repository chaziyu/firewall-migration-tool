from fwmigrate.parsers.juniper_srx import JuniperSRXParser


def test_tenant_nat_names_and_references_do_not_collide():
    parser = JuniperSRXParser("""
    set tenants TSYS1 security address-book global address HOST1 192.0.2.1/32
    set tenants TSYS1 security nat source pool P1 address 203.0.113.1/32
    set tenants TSYS1 security nat source rule-set RS1 from zone trust
    set tenants TSYS1 security nat source rule-set RS1 to zone untrust
    set tenants TSYS1 security nat source rule-set RS1 rule R1 match source-address-name HOST1
    set tenants TSYS1 security nat source rule-set RS1 rule R1 then source-nat pool P1
    set tenants TSYS2 security nat source pool P1 address 203.0.113.2/32
    set tenants TSYS2 security nat source rule-set RS1 rule R1 then source-nat pool P1
    """)
    ir = parser.extract().canonical_ir
    rules = {r.name: r for r in ir.nat_rules}

    assert "TSYS1__R1" in rules and "TSYS2__R1" in rules
    assert rules["TSYS1__R1"].source_pool_references == ["P1"]
    assert rules["TSYS1__R1"].source == ["TSYS1__HOST1"]
