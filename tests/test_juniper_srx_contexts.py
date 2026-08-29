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

    assert any(i.name == "ge-0/0/0.100" for i in ir.interfaces)
    assert any(z.name == "ls_trust" for z in ir.zones)
    assert any(a.name == "host_app" for a in ir.addresses)
    assert any(p.name == "LS_P1" for p in ir.policies)

    assert_no_silent_loss(res, total_input_commands=9)
