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


def test_deactivated_zones_vpn_and_schedulers():
    content = """
    set version 21.4R1.12
    set system host-name SRX-Deact-Ext
    
    # 1. Deactivated zone
    set security zones security-zone dmz-zone interfaces ge-0/0/2.0
    deactivate security zones security-zone dmz-zone
    set security policies from-zone dmz-zone to-zone untrust policy P_DMZ match source-address any
    set security policies from-zone dmz-zone to-zone untrust policy P_DMZ match destination-address any
    set security policies from-zone dmz-zone to-zone untrust policy P_DMZ match application any
    set security policies from-zone dmz-zone to-zone untrust policy P_DMZ then permit
    
    # 2. Deactivated scheduler
    set schedulers scheduler inactive_sched start-date 2026-01-01.00:00:00 stop-date 2026-01-02.00:00:00
    deactivate schedulers scheduler inactive_sched
    set security policies from-zone trust to-zone untrust policy P_Sched match source-address any
    set security policies from-zone trust to-zone untrust policy P_Sched match destination-address any
    set security policies from-zone trust to-zone untrust policy P_Sched match application any
    set security policies from-zone trust to-zone untrust policy P_Sched scheduler-name inactive_sched
    set security policies from-zone trust to-zone untrust policy P_Sched then permit

    # 3. Deactivated VPN
    set interfaces st0 unit 0 family inet address 10.255.0.1/30
    set security ike proposal prop1 authentication-method pre-shared-keys
    set security ike policy pol1 mode main proposals prop1
    set security ike policy pol1 pre-shared-key ascii-text "secret123"
    set security ike gateway gw1 ike-policy pol1 address 198.51.100.2 external-interface ge-0/0/1.0
    set security ipsec proposal ipsec_prop1 protocol esp
    set security ipsec policy ipsec_pol1 proposals ipsec_prop1
    set security ipsec vpn vpn_tunnel bind-interface st0.0
    set security ipsec vpn vpn_tunnel ike gateway gw1
    set security ipsec vpn vpn_tunnel ike ipsec-policy ipsec_pol1
    deactivate security ipsec vpn vpn_tunnel
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    # Check deactivated zone provenance and policy warning
    p_dmz = next(p for p in ir.policies if p.name == "P_DMZ")
    assert p_dmz.requires_manual_review is True
    assert any("Referenced zone 'dmz-zone' is deactivated" in r for r in p_dmz.review_reasons)

    # Check deactivated scheduler policy warning
    p_sched = next(p for p in ir.policies if p.name == "P_Sched")
    assert p_sched.requires_manual_review is True
    assert any("Referenced scheduler 'inactive_sched' is deactivated" in r for r in p_sched.review_reasons)

    # Check deactivated VPN
    vpn = next(v for v in ir.vpn_tunnels if v.name == "vpn_tunnel")
    assert vpn.source_attributes.get("disabled") is True

    assert_no_silent_loss(res, total_input_commands=26)

