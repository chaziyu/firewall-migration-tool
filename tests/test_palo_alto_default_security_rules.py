from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "default_security_rules.xml"


def _result():
    return PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))


def _rule(result, scope_kind, scope_name, name):
    return next(item for item in result.inventory_items if item.domain == "default_security_rules"
                and item.name == name and item.source_attributes["scope_kind"] == scope_kind
                and item.source_attributes["scope_name"] == scope_name)


def test_untouched_built_in_default_remains_extract_only_without_fake_matches():
    result = _result()
    item = _rule(result, "vsys", "vsys1", "intrazone-default")
    assert item.status == ExtractionStatus.EXTRACT_ONLY
    assert item.source_attributes["pan_default_rule_source_state"] == "BUILT_IN_UNTOUCHED"
    for field in ("pan_from", "pan_to", "pan_source", "pan_destination", "pan_service"):
        assert field not in item.source_attributes
    assert all(policy.name != "intrazone-default" for policy in result.canonical_ir.policies)


def test_local_default_override_preserves_action_logging_profiles_and_options():
    item = _rule(_result(), "vsys", "vsys1", "interzone-default")
    attrs = item.source_attributes
    assert attrs["pan_default_rule_source_state"] == "LOCALLY_OVERRIDDEN_DEFAULT"
    assert attrs["pan_action"] == "deny" and attrs["pan_disabled"] == "yes"
    assert attrs["pan_log_end"] == "yes" and attrs["pan_log_setting"] == "traffic-log"
    assert attrs["pan_direct_profiles"] == {"virus": ["strict-av"], "vulnerability": ["strict-vuln"]}
    assert attrs["pan_option"] and attrs["pan_icmp_unreachable"] == "yes"


def test_panorama_default_overrides_preserve_scope_and_rulebase_position():
    result = _result()
    shared = _rule(result, "shared", "shared", "intrazone-default")
    dg = _rule(result, "device-group", "dg-parent", "interzone-default")
    assert shared.source_attributes["pan_default_rule_source_state"] == "PANORAMA_INHERITED_OVERRIDE"
    assert shared.source_attributes["pan_rulebase_position"] == "pre"
    assert dg.source_attributes["pan_rulebase_position"] == "post"
    assert dg.source_attributes["pan_profile_groups"] == ["strict-group"]


def test_unknown_default_rule_fields_remain_material_evidence():
    shared = _rule(_result(), "shared", "shared", "intrazone-default")
    assert "future-default" in shared.source_attributes["pan_unknown_fields"]


def test_each_default_rule_has_one_terminal_outcome():
    items = [item for item in _result().inventory_items if item.domain == "default_security_rules"]
    assert len(items) == 4
    assert len({item.source_record_id for item in items}) == 4
