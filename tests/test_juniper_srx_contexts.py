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
    assert pol_dict["LS1__P1"].source_extra_settings.get("junos_context") == "LS1"
    assert pol_dict["LS2__P1"].source_extra_settings.get("junos_context") == "LS2"
