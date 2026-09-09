from fwmigrate.core.registry import PluginRegistry
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_logical_systems_context_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "logical_systems.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    assert any(i.name == "ge-0/0/0.100" and i.source_attributes.get("junos_context") == "LS_TENANT_A" for i in ir.interfaces)
    assert any(z.name == "LS_TENANT_A__ls_trust" for z in ir.zones)
    assert any(a.name == "LS_TENANT_A__host_app" and a.source_attributes.get("junos_context") == "LS_TENANT_A" for a in ir.addresses)
    
    p = next(p for p in ir.policies if p.name == "LS_TENANT_A__LS_P1")
    assert p.source_extra_settings.get("junos_context") == "LS_TENANT_A"
    assert p.requires_manual_review is True

    assert_no_silent_loss(res, total_input_commands=9)

def test_logical_systems_collision_isolation():
    content = """
    set version 21.4R1.12
    set system host-name SRX-MultiLS
    set logical-systems LS1 security address-book global address srv 10.1.1.1/32
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 match source-address srv
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 match destination-address any
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 match application any
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 then permit
    set logical-systems LS2 security address-book global address srv 10.2.2.2/32
    set logical-systems LS2 security policies from-zone trust to-zone untrust policy P1 match source-address srv
    set logical-systems LS2 security policies from-zone trust to-zone untrust policy P1 match destination-address any
    set logical-systems LS2 security policies from-zone trust to-zone untrust policy P1 match application any
    set logical-systems LS2 security policies from-zone trust to-zone untrust policy P1 then permit
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    addr_dict = {a.name: a for a in ir.addresses}
    assert "LS1__srv" in addr_dict
    assert "LS2__srv" in addr_dict
    assert addr_dict["LS1__srv"].subnet == "10.1.1.1/32"
    assert addr_dict["LS2__srv"].subnet == "10.2.2.2/32"
    assert addr_dict["LS1__srv"].source_attributes.get("junos_context") == "LS1"
    assert addr_dict["LS2__srv"].source_attributes.get("junos_context") == "LS2"

    pol_dict = {p.name: p for p in ir.policies}
    assert "LS1__P1" in pol_dict
    assert "LS2__P1" in pol_dict
    assert pol_dict["LS1__P1"].source == ["LS1__srv"]
    assert pol_dict["LS2__P1"].source == ["LS2__srv"]
    assert pol_dict["LS1__P1"].source_extra_settings.get("junos_context") == "LS1"
    assert pol_dict["LS2__P1"].source_extra_settings.get("junos_context") == "LS2"


def test_logical_systems_full_context_reference_isolation():
    content = """
    set version 21.4R1.12
    set system host-name SRX-Contexts-Deep
    
    # LS1 definitions
    set logical-systems LS1 security zones security-zone trust interfaces ge-0/0/0.1
    set logical-systems LS1 security zones security-zone untrust interfaces ge-0/0/0.2
    set logical-systems LS1 security address-book global address srv 10.1.1.10/32
    set logical-systems LS1 security address-book global address-set servers address srv
    set logical-systems LS1 applications application web protocol tcp destination-port 80
    set logical-systems LS1 applications application-set web_group application web
    set logical-systems LS1 schedulers scheduler biz_hours start-date 2026-01-01.08:00:00 stop-date 2026-12-31.18:00:00
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 match source-address servers
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 match destination-address srv
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 match application web_group
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 then permit
    set logical-systems LS1 security policies from-zone trust to-zone untrust policy P1 scheduler-name biz_hours
    set logical-systems LS1 security nat source rule-set rs1 from zone trust
    set logical-systems LS1 security nat source rule-set rs1 to zone untrust
    set logical-systems LS1 security nat source rule-set rs1 rule r1 match source-address-name srv
    set logical-systems LS1 security nat source rule-set rs1 rule r1 then source-nat interface

    # LS2 definitions (identical local names, distinct context)
    set logical-systems LS2 security zones security-zone trust interfaces ge-0/0/1.1
    set logical-systems LS2 security zones security-zone untrust interfaces ge-0/0/1.2
    set logical-systems LS2 security address-book global address srv 10.2.2.20/32
    set logical-systems LS2 security address-book global address-set servers address srv
    set logical-systems LS2 applications application web protocol tcp destination-port 8080
    set logical-systems LS2 applications application-set web_group application web
    set logical-systems LS2 schedulers scheduler biz_hours start-date 2026-01-01.09:00:00 stop-date 2026-12-31.17:00:00
    set logical-systems LS2 security policies from-zone trust to-zone untrust policy P1 match source-address servers
    set logical-systems LS2 security policies from-zone trust to-zone untrust policy P1 match destination-address srv
    set logical-systems LS2 security policies from-zone trust to-zone untrust policy P1 match application web_group
    set logical-systems LS2 security policies from-zone trust to-zone untrust policy P1 then permit
    set logical-systems LS2 security policies from-zone trust to-zone untrust policy P1 scheduler-name biz_hours
    set logical-systems LS2 security nat source rule-set rs1 from zone trust
    set logical-systems LS2 security nat source rule-set rs1 to zone untrust
    set logical-systems LS2 security nat source rule-set rs1 rule r1 match source-address-name srv
    set logical-systems LS2 security nat source rule-set rs1 rule r1 then source-nat interface
    """
    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    # Check Address Groups
    ag_dict = {g.name: g for g in ir.address_groups}
    assert ag_dict["LS1__servers"].members == ["LS1__srv"]
    assert ag_dict["LS2__servers"].members == ["LS2__srv"]

    # Check Service Groups
    sg_dict = {g.name: g for g in ir.service_groups}
    assert sg_dict["LS1__web_group"].members == ["LS1__web"]
    assert sg_dict["LS2__web_group"].members == ["LS2__web"]

    # Check Policies
    pol_dict = {p.name: p for p in ir.policies}
    p1 = pol_dict["LS1__P1"]
    p2 = pol_dict["LS2__P1"]

    assert p1.from_zone == ["LS1__trust"]
    assert p1.to_zone == ["LS1__untrust"]
    assert p1.source == ["LS1__servers"]
    assert p1.destination == ["LS1__srv"]
    assert p1.service == ["LS1__web_group"]
    assert p1.schedule == "LS1__biz_hours"

    assert p2.from_zone == ["LS2__trust"]
    assert p2.to_zone == ["LS2__untrust"]
    assert p2.source == ["LS2__servers"]
    assert p2.destination == ["LS2__srv"]
    assert p2.service == ["LS2__web_group"]
    assert p2.schedule == "LS2__biz_hours"

    # Check NAT Rules
    nat_dict = {n.name: n for n in ir.nat_rules}
    n1 = nat_dict["LS1__r1"]
    n2 = nat_dict["LS2__r1"]
    assert n1.from_zone == ["LS1__trust"]
    assert n1.to_zone == ["LS1__untrust"]
    assert n1.source == ["LS1__srv"]

    assert n2.from_zone == ["LS2__trust"]
    assert n2.to_zone == ["LS2__untrust"]
    assert n2.source == ["LS2__srv"]

    assert_no_silent_loss(res, total_input_commands=34)

