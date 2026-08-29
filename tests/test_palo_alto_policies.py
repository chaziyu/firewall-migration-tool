from pathlib import Path

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser
from tests.fixture_paths import PALO_ALTO_FIXTURE


FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "policies.xml"


def _extract():
    return PANOSSourceParser().extract(FIXTURE.read_text(encoding="utf-8"))


def _policy(result, name, position=None):
    matches = [policy for policy in result.canonical_ir.policies if policy.name == name]
    if position is not None:
        matches = [policy for policy in matches if policy.source_extra_settings["pan_rulebase_position"] == position]
    return matches[0]


def _records(result, name):
    return [item for item in result.inventory_items if item.domain == "policies" and item.name == name]


def test_allow_action():
    assert _policy(_extract(), "Allow-Basic").action == PolicyAction.ALLOW


def test_deny_action():
    policy = _policy(_extract(), "Deny-Basic")
    assert policy.action == PolicyAction.DENY
    assert policy.source_action == "deny"


def test_drop_source_action_preserved():
    policy = _policy(_extract(), "Drop-Rule")
    assert policy.action == PolicyAction.DENY
    assert policy.source_action == "drop"


def test_reset_client_source_action_preserved():
    assert _policy(_extract(), "Reset-Client").source_action == "reset-client"


def test_reset_server_source_action_preserved():
    assert _policy(_extract(), "Reset-Server").source_action == "reset-server"


def test_reset_both_source_action_preserved():
    assert _policy(_extract(), "Reset-Both").source_action == "reset-both"


def test_missing_action_not_allow():
    result = _extract()
    assert all(policy.name != "Missing-Action" for policy in result.canonical_ir.policies)
    assert _records(result, "Missing-Action")[0].status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_missing_source_not_any():
    result = _extract()
    assert all(policy.name != "Missing-Source" for policy in result.canonical_ir.policies)
    assert _records(result, "Missing-Source")[0].source_attributes["pan_source"] == []


def test_missing_destination_not_any():
    result = _extract()
    assert all(policy.name != "Missing-Destination" for policy in result.canonical_ir.policies)


def test_missing_from_not_any():
    result = _extract()
    assert all(policy.name != "Missing-From" for policy in result.canonical_ir.policies)


def test_missing_to_not_any():
    result = _extract()
    assert all(policy.name != "Missing-To" for policy in result.canonical_ir.policies)


def test_missing_service_not_any():
    result = _extract()
    assert all(policy.name != "Missing-Service-Field" for policy in result.canonical_ir.policies)
    assert _records(result, "Missing-Service-Field")[0].source_attributes["pan_service"] == []


def test_unknown_action_is_unsupported_not_deny_or_allow():
    result = _extract()
    assert all(policy.name != "Future-Action" for policy in result.canonical_ir.policies)
    assert _records(result, "Future-Action")[0].status == ExtractionStatus.UNSUPPORTED


def test_malformed_supported_boolean_is_parse_error():
    result = _extract()
    assert all(policy.name != "Malformed-Log" for policy in result.canonical_ir.policies)
    record = _records(result, "Malformed-Log")[0]
    assert record.status == ExtractionStatus.PARSE_ERROR
    assert record.source_attributes["pan_log_end_value"] == "sometimes"


def test_explicit_any_preserved():
    policy = _policy(_extract(), "Explicit-Any")
    assert policy.from_zone == ["any"]
    assert policy.to_zone == ["any"]
    assert policy.source == ["any"]
    assert policy.destination == ["any"]
    assert policy.service == ["any"]
    assert policy.applications == ["any"]


def test_source_user_preserved():
    policy = _policy(_extract(), "Identity-Category-HIP")
    assert policy.source_users == ["DOMAIN\\alice", "known-user"]
    assert policy.source_extra_settings["pan_source_user"] == ["DOMAIN\\alice", "known-user"]


def test_category_preserved():
    assert _policy(_extract(), "Identity-Category-HIP").source_extra_settings["pan_category"] == ["adult", "malware"]


def test_source_hip_preserved():
    assert _policy(_extract(), "Identity-Category-HIP").source_extra_settings["pan_source_hip"] == ["hip-source"]


def test_destination_hip_preserved():
    assert _policy(_extract(), "Identity-Category-HIP").source_extra_settings["pan_destination_hip"] == ["hip-destination"]


def test_negate_source_preserved():
    policy = _policy(_extract(), "Identity-Category-HIP")
    assert policy.source_address_negate_setting == "yes"
    assert policy.source_extra_settings["pan_negate_source_explicit"] is True


def test_negate_destination_preserved():
    policy = _policy(_extract(), "Identity-Category-HIP")
    assert policy.destination_address_negate_setting == "no"
    assert policy.source_extra_settings["pan_negate_destination_value"] == "no"


def test_schedule_resolved():
    assert _policy(_extract(), "Schedule-Rule").schedule == "BusinessHours"


def test_unresolved_schedule_requires_review():
    policy = _policy(_extract(), "Unresolved-Schedule")
    assert policy.schedule == "Missing-Schedule"
    assert policy.source_extra_settings["pan_unresolved_schedule"] == ["Missing-Schedule"]
    assert policy.requires_manual_review is True


def test_tags_preserved():
    assert _policy(_extract(), "Tags-Logging").source_extra_settings["pan_tags"] == ["production", "audited"]


def test_group_tag_preserved():
    assert _policy(_extract(), "Tags-Logging").source_extra_settings["pan_group_tag"] == "policy-group"


def test_log_start_explicit_yes():
    policy = _policy(_extract(), "Tags-Logging")
    assert policy.log_start is True
    assert policy.source_extra_settings["pan_log_start_value"] == "yes"


def test_log_start_explicit_no():
    policy = _policy(_extract(), "Explicit-No")
    assert policy.log_start is False
    assert policy.source_extra_settings["pan_log_start_explicit"] is True


def test_log_start_absent_not_claimed_explicit():
    policy = _policy(_extract(), "Absent-Flags")
    assert policy.log_start is None
    assert policy.source_extra_settings["pan_log_start_explicit"] is False


def test_log_end_explicit_yes():
    assert _policy(_extract(), "Tags-Logging").log_end is True


def test_log_end_explicit_no():
    assert _policy(_extract(), "Explicit-No").log_end is False


def test_log_end_absent_not_claimed_explicit():
    policy = _policy(_extract(), "Absent-Flags")
    assert policy.log_end is None
    assert policy.source_extra_settings["pan_log_end_explicit"] is False


def test_log_setting_preserved():
    policy = _policy(_extract(), "Tags-Logging")
    assert policy.source_log_setting == "central-logging"
    assert policy.source_extra_settings["pan_log_setting"] == "central-logging"


def test_disabled_explicit_yes():
    policy = _policy(_extract(), "Tags-Logging")
    assert policy.disabled is True
    assert policy.source_extra_settings["pan_disabled_value"] == "yes"


def test_disabled_explicit_no():
    policy = _policy(_extract(), "Explicit-No")
    assert policy.disabled is False
    assert policy.source_extra_settings["pan_disabled_explicit"] is True


def test_disabled_absent_not_claimed_explicit():
    policy = _policy(_extract(), "Absent-Flags")
    assert policy.disabled is None
    assert policy.source_extra_settings["pan_disabled_explicit"] is False


def test_rule_type_preserved():
    assert _policy(_extract(), "Rule-Type").source_extra_settings["pan_rule_type"] == "interzone"


def test_profile_group_preserved():
    policy = _policy(_extract(), "Profile-Group")
    assert policy.security_profile_group == "Corporate-Profiles"
    assert policy.source_profile_group == "Corporate-Profiles"


def test_mixed_profile_assignment_preserved_and_requires_review():
    policy = _policy(_extract(), "Mixed-Profiles")
    assert policy.security_profile_group == "Corporate-Profiles"
    assert policy.source_extra_settings["pan_direct_profiles"]["virus"] == ["av-profile"]
    assert "mixed-profile-assignment" in policy.review_reasons


def test_direct_antivirus_profile_preserved():
    policy = _policy(_extract(), "Direct-Profiles")
    assert policy.antivirus == "av-profile"
    assert policy.source_extra_settings["pan_direct_profiles"]["virus"] == ["av-profile"]


def test_direct_vulnerability_profile_preserved():
    assert _policy(_extract(), "Direct-Profiles").source_extra_settings["pan_direct_profiles"]["vulnerability"] == ["vuln-profile"]


def test_direct_spyware_profile_preserved():
    assert _policy(_extract(), "Direct-Profiles").source_extra_settings["pan_direct_profiles"]["spyware"] == ["spyware-profile"]


def test_direct_url_filter_profile_preserved():
    policy = _policy(_extract(), "Direct-Profiles")
    assert policy.webfilter == "url-profile"


def test_direct_file_blocking_profile_preserved():
    assert _policy(_extract(), "Direct-Profiles").source_extra_settings["pan_direct_profiles"]["file-blocking"] == ["file-profile"]


def test_direct_wildfire_profile_preserved():
    assert _policy(_extract(), "Direct-Profiles").source_extra_settings["pan_direct_profiles"]["wildfire-analysis"] == ["wildfire-profile"]


def test_direct_data_filter_profile_preserved():
    assert _policy(_extract(), "Direct-Profiles").source_extra_settings["pan_direct_profiles"]["data-filtering"] == ["data-profile"]


def test_disable_inspect_preserved():
    policy = _policy(_extract(), "Inspection-SaaS")
    assert policy.source_extra_settings["pan_disable_inspect_value"] == "yes"


def test_disable_server_response_inspection_preserved():
    policy = _policy(_extract(), "Inspection-SaaS")
    assert policy.source_extra_settings["pan_disable_server_response_inspection_value"] == "no"


def test_saas_user_list_preserved():
    assert _policy(_extract(), "Inspection-SaaS").source_extra_settings["pan_saas_user_list"] == ["user-list-a"]


def test_saas_tenant_list_preserved():
    assert _policy(_extract(), "Inspection-SaaS").source_extra_settings["pan_saas_tenant_list"] == ["tenant-a"]


def test_address_reference_uses_scoped_canonical_name():
    assert _policy(_extract(), "Allow-Basic").source == ["vsys1::Scoped-Address"]


def test_service_reference_uses_scoped_canonical_name():
    assert _policy(_extract(), "Allow-Basic").service == ["vsys1::Scoped-Service"]


def test_custom_application_reference_preserved():
    policy = _policy(_extract(), "Custom-App")
    assert policy.applications == ["custom-app"]
    assert "pan_unresolved_applications" not in policy.source_extra_settings


def test_unresolved_address_requires_review():
    policy = _policy(_extract(), "Unresolved-Address")
    assert policy.source == ["Missing-Address"]
    assert policy.source_extra_settings["pan_unresolved_sources"] == ["Missing-Address"]
    assert policy.safe_for_target_generation is False


def test_unresolved_service_requires_review():
    policy = _policy(_extract(), "Unresolved-Service")
    assert policy.service == ["Missing-Service"]
    assert policy.source_extra_settings["pan_unresolved_services"] == ["Missing-Service"]


def test_unknown_policy_field_is_partial():
    result = _extract()
    policy = _policy(result, "Unknown-Field")
    assert "retain-me" in str(policy.source_extra_settings["pan_unknown_fields"])
    assert _records(result, "Unknown-Field")[0].status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_pre_rule_position_preserved():
    assert _policy(_extract(), "Pre-First").source_extra_settings["pan_rulebase_position"] == "pre"


def test_local_rule_position_preserved():
    assert _policy(_extract(), "Allow-Basic").source_extra_settings["pan_rulebase_position"] == "local"


def test_post_rule_position_preserved():
    assert _policy(_extract(), "Same-Name", "post").source_extra_settings["pan_rulebase_position"] == "post"


def test_source_rule_index_preserved():
    result = _extract()
    assert _policy(result, "Pre-First").source_extra_settings["pan_source_rule_index"] == 0
    assert _policy(result, "Same-Name", "pre").source_extra_settings["pan_source_rule_index"] == 1
    assert _policy(result, "Allow-Basic").source_extra_settings["pan_source_rule_index"] == 0
    assert _policy(result, "Same-Name", "post").source_extra_settings["pan_source_rule_index"] == 0


def test_same_rule_name_different_rulebases_has_unique_source_record_id():
    records = _records(_extract(), "Same-Name")
    assert len(records) == 3
    assert len({record.source_record_id for record in records}) == 3


def test_policy_has_exactly_one_terminal_status():
    result = _extract()
    assert len(_records(result, "Allow-Basic")) == 1
    assert _records(result, "Allow-Basic")[0].status == ExtractionStatus.NORMALIZED


def test_default_security_rules_are_not_included_in_phase_10():
    result = _extract()
    assert all(policy.name != "Default-Intrazone" for policy in result.canonical_ir.policies)
    assert not _records(result, "Default-Intrazone")


def test_predefined_application_remains_unresolved_without_fabrication():
    policy = _policy(_extract(), "Predefined-App")
    assert policy.applications == ["ssl"]
    assert policy.source_extra_settings["pan_unresolved_applications"] == ["ssl"]
    assert policy.requires_manual_review is True


def test_original_example_policy_still_extracts_safely():
    result = PANOSSourceParser().extract(PALO_ALTO_FIXTURE.read_text(encoding="utf-8"))
    policy = _policy(result, "Allow_LAN_To_Web")
    assert policy.from_zone == ["trust"]
    assert policy.to_zone == ["untrust"]
    assert policy.source == ["Grp_Internal"]
    assert policy.destination == ["any"]
    assert policy.service == ["sg-web"]
    assert policy.action == PolicyAction.ALLOW
    assert policy.log_end is True
    assert policy.source_extra_settings["pan_log_end_explicit"] is True
    assert policy.security_profile_group == "SPG_Corporate"
