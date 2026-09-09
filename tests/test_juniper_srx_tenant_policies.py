from fwmigrate.parsers.juniper_srx import JuniperSRXParser


def test_tenant_policy_references_and_ordering_are_context_local():
    parser = JuniperSRXParser("""
    set security address-book global address HOST1 198.51.100.1/32
    set tenants TSYS1 security address-book global address HOST1 192.0.2.1/32
    set tenants TSYS1 security policies from-zone trust to-zone untrust policy P1 match source-address HOST1
    set tenants TSYS1 security policies from-zone trust to-zone untrust policy P1 match destination-address any
    set tenants TSYS1 security policies from-zone trust to-zone untrust policy P1 match application junos-http
    set tenants TSYS1 security policies from-zone trust to-zone untrust policy P1 then permit
    set tenants TSYS2 security address-book global address HOST1 192.0.2.2/32
    set tenants TSYS2 security policies from-zone trust to-zone untrust policy P1 match source-address HOST1
    set tenants TSYS2 security policies from-zone trust to-zone untrust policy P1 match destination-address any
    set tenants TSYS2 security policies from-zone trust to-zone untrust policy P1 match application junos-http
    set tenants TSYS2 security policies from-zone trust to-zone untrust policy P1 then permit
    set tenants TSYS1 security policies global policy GP1 match source-address HOST1
    """)
    ir = parser.extract().canonical_ir
    policies = {p.name: p for p in ir.policies}

    assert policies["TSYS1__P1"].source == ["TSYS1__HOST1"]
    assert policies["TSYS2__P1"].source == ["TSYS2__HOST1"]
    assert policies["TSYS1__P1"].service == ["junos-http"]
    assert policies["TSYS1__P1"].requires_manual_review is True
    assert any(p.name == "TSYS1__GP1" for p in ir.policies)
