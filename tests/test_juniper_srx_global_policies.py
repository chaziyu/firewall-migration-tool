from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_global_policies_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "global_policies.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    pol_dict = {p.name: p for p in ir.policies}

    assert "Global_Drop_All" in pol_dict
    g_drop = pol_dict["Global_Drop_All"]
    assert g_drop.action == PolicyAction.DENY
    assert "trust" in g_drop.from_zone
    assert "dmz" in g_drop.from_zone
    assert "untrust" in g_drop.to_zone
    assert g_drop.source_extra_settings.get("junos_policy_scope") == "global"
    assert g_drop.requires_manual_review is True

    assert "Global_Allow_Mgmt" in pol_dict
    g_allow = pol_dict["Global_Allow_Mgmt"]
    assert g_allow.action == PolicyAction.ALLOW
    assert g_allow.source == ["srv_all"]
    assert g_allow.requires_manual_review is True

    assert_no_silent_loss(res, total_input_commands=16)
