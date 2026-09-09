from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser


def test_hierarchical_and_display_set_inputs_have_same_semantics():
    display_set = """
    set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
    set security address-book global address host1 10.1.1.1/32
    set security policies from-zone trust to-zone untrust policy P1 match source-address host1
    set security policies from-zone trust to-zone untrust policy P1 then permit
    """
    hierarchical = """
    interfaces {
        ge-0/0/0 { unit 0 { family inet { address 10.0.0.1/24; } } }
    }
    security {
        address-book { global { address host1 10.1.1.1/32; } }
        policies { from-zone trust { to-zone untrust {
            policy P1 { match { source-address host1; } then permit; }
        } } }
    }
    """
    set_ir = JuniperSRXParser(display_set).extract().canonical_ir
    hierarchical_ir = JuniperSRXParser(hierarchical).extract().canonical_ir
    assert [(i.name, i.ip) for i in set_ir.interfaces] == [
        (i.name, i.ip) for i in hierarchical_ir.interfaces
    ]
    assert [(a.name, a.source_list_entries) for a in set_ir.addresses] == [
        (a.name, a.source_list_entries) for a in hierarchical_ir.addresses
    ]
    assert [(p.name, p.action) for p in set_ir.policies] == [
        (p.name, p.action) for p in hierarchical_ir.policies
    ]


def test_hierarchical_inactive_child_does_not_create_active_value():
    content = """
    security { address-book { global {
        address-set hosts { address host1; inactive: address host2; }
    } } }
    """
    cfg = JuniperSRXParser(content).parse_raw()
    members = cfg.contexts["root"].address_books["global"].address_sets["hosts"].members
    assert [member.name for member in members] == ["host1"]
