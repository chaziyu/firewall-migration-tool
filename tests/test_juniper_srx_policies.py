from fwmigrate.core.registry import PluginRegistry
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.parsers.juniper_srx.coverage import assert_no_silent_loss
from tests.fixture_paths import JUNIPER_FIXTURES_DIR

def test_security_policies_extraction():
    fixture_path = JUNIPER_FIXTURES_DIR / "policies.set"
    with open(fixture_path, "r", encoding="utf-8") as f:
        content = f.read()

    parser = PluginRegistry.get_parser("juniper_srx")
    res = parser.extract(content)
    ir = res.canonical_ir

    pol_dict = {p.name: p for p in ir.policies}

    # P1: permit, logging, count, dual-family any
    p1 = pol_dict["P1"]
    assert p1.action == PolicyAction.ALLOW
    assert p1.log_start is True
    assert p1.log_end is True
    assert p1.source_extra_settings.get("junos_count") is True
    assert "any-ipv4" in p1.destination
    assert "any-ipv6" in p1.destination

    # P2_Reject: reject -> DENY with manual review
    p2 = pol_dict["P2_Reject"]
    assert p2.action == PolicyAction.DENY
    assert p2.source_action == "reject"
    assert p2.requires_manual_review is True

    # P3_Exclude: address exclusion
    p3 = pol_dict["P3_Exclude"]
    assert p3.action == PolicyAction.DENY
    assert p3.source_address_negate_setting == "exclude"
    assert p3.requires_manual_review is True

    assert_no_silent_loss(res, total_input_commands=24)
