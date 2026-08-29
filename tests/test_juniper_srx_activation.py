from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from fwmigrate.parsers.juniper_srx.parser import JuniperSRXParser
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_activation_and_deactivation_accounting_and_semantics():
    fixture_path = JUNIPER_FIXTURES_DIR / "activation.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)

    assert_no_silent_loss(res, total_input_commands=19, expected_unsupported=0)

    ir = res.canonical_ir
    pol_dict = {p.name: p for p in ir.policies}
    addr_dict = {a.name: a for a in ir.addresses}

    # Policy deactivation semantics
    assert pol_dict["P_Inactive"].disabled is True
    assert pol_dict["P_Active"].disabled is not True

    # Address deactivation and reactivation semantics
    raw_parser = JuniperSRXParser(content)
    raw_cfg = raw_parser.parse_raw()
    root_book = raw_cfg.contexts["root"].address_books["global"]
    assert root_book.addresses["inactive_host"].disabled is True
    assert root_book.addresses["active_host"].disabled is not True
    assert root_book.addresses["reactivated_host"].disabled is not True
    assert addr_dict["inactive_host"].source_attributes.get("disabled") is True
    assert addr_dict["active_host"].source_attributes.get("disabled") is not True

def test_activation_subtree_inheritance():
    content = """
    set version 21.4R1.12
    set system host-name Subtree-Test
    set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
    set interfaces ge-0/0/0 unit 1 family inet address 10.0.1.1/24
    deactivate interfaces ge-0/0/0
    set security address-book global address host1 10.1.1.1/32
    set security address-book global address host2 10.1.1.2/32
    deactivate security address-book global
    set security policies from-zone trust to-zone untrust policy P1 match source-address any
    set security policies from-zone trust to-zone untrust policy P1 match destination-address any
    set security policies from-zone trust to-zone untrust policy P1 match application any
    set security policies from-zone trust to-zone untrust policy P1 then permit
    deactivate security policies from-zone trust to-zone untrust
    set routing-options static route 10.5.0.0/16 next-hop 192.168.1.1
    deactivate routing-options static route 10.5.0.0/16
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    # Subtree interface deactivation -> units are disabled (status is False)
    u0 = next(i for i in ir.interfaces if i.name == "ge-0/0/0.0")
    u1 = next(i for i in ir.interfaces if i.name == "ge-0/0/0.1")
    assert u0.status is False
    assert u1.status is False

    # Subtree address-book deactivation -> addresses in that book are disabled
    a1 = next(a for a in ir.addresses if a.name == "host1")
    a2 = next(a for a in ir.addresses if a.name == "host2")
    assert a1.source_attributes.get("disabled") is True
    assert a2.source_attributes.get("disabled") is True

    # Subtree policy deactivation -> policies in zone pair are disabled
    p1 = next(p for p in ir.policies if p.name == "P1")
    assert p1.disabled is True

    # Route deactivation
    r1 = next(r for r in ir.routes if r.destination == "10.5.0.0/16")
    assert r1.enabled is False
    assert r1.source_attributes.get("disabled") is True
