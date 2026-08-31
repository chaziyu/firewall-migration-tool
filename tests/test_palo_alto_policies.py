from pathlib import Path
from textwrap import dedent

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


LEGACY_HIP_CONFIG = dedent("""
    <?xml version="1.0"?>
    <config>
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        <rulebase><security><rules>
          <entry name="Legacy-HIP-Any">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <hip-profiles><member>any</member></hip-profiles><action>allow</action>
          </entry>
          <entry name="Legacy-HIP-Named">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <hip-profiles><member>Corporate-HIP</member></hip-profiles><action>allow</action>
          </entry>
          <entry name="Modern-HIP">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <source-hip><member>Modern-Source-HIP</member></source-hip>
            <destination-hip><member>Modern-Destination-HIP</member></destination-hip>
            <action>allow</action>
          </entry>
          <entry name="Mixed-HIP">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <hip-profiles><member>Legacy-HIP</member></hip-profiles>
            <source-hip><member>Modern-Source-HIP</member></source-hip>
            <destination-hip><member>Modern-Destination-HIP</member></destination-hip>
            <action>allow</action>
          </entry>
        </rules></security></rulebase>
      </entry></vsys></entry></devices>
    </config>
""").strip()


def _extract_config(config):
    return PANOSSourceParser().extract(config)


def _security_rule(name, source, destination):
    return f"""
      <entry name="{name}">
        <from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>{source}</member></source>
        <destination><member>{destination}</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action>
      </entry>
    """


def _address_policy_config(rules, objects="", shared_objects=""):
    return dedent(f"""
        <?xml version="1.0"?>
        <config>
          {shared_objects}
          <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
            {objects}
            <rulebase><security><rules>{rules}</rules></security></rulebase>
          </entry></vsys></entry></devices>
        </config>
    """).strip()


UUID_CONFIG = dedent("""
    <?xml version="1.0"?>
    <config>
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        <rulebase><security><rules>
          <entry name="UUID-Rule" uuid="16a1a7c4-f1b2-4307-b898-8bdb4979d40d">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <action>allow</action>
          </entry>
          <entry name="Missing-UUID">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <action>allow</action>
          </entry>
          <entry name="Empty-UUID" uuid="">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <action>allow</action>
          </entry>
        </rules></security></rulebase>
      </entry></vsys></entry></devices>
    </config>
""").strip()


DEFAULT_AND_METADATA_CONFIG = dedent("""
    <?xml version="1.0"?>
    <config>
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        <rulebase><security><rules>
          <entry name="Category-Any">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <category><member>any</member></category><action>allow</action>
          </entry>
          <entry name="Source-HIP-Any">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <source-hip><member>any</member></source-hip><action>allow</action>
          </entry>
          <entry name="Destination-HIP-Any">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <destination-hip><member>any</member></destination-hip><action>allow</action>
          </entry>
          <entry name="Source-HIP-Empty">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <source-hip></source-hip><action>allow</action>
          </entry>
          <entry name="Destination-HIP-Empty">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <destination-hip></destination-hip><action>allow</action>
          </entry>
          <entry name="Tags-Only">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <tag><member>retained-tag</member></tag><action>allow</action>
          </entry>
          <entry name="Group-Tag-Only">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <group-tag>retained-group</group-tag><action>allow</action>
          </entry>
          <entry name="Inspection-No">
            <from><member>trust</member></from><to><member>untrust</member></to>
            <source><member>any</member></source><destination><member>any</member></destination>
            <application><member>any</member></application><service><member>any</member></service>
            <disable-inspect>no</disable-inspect>
            <option><disable-server-response-inspection>no</disable-server-response-inspection></option>
            <action>allow</action>
          </entry>
        </rules></security></rulebase>
      </entry></vsys></entry></devices>
    </config>
""").strip()


def _assert_normalized_without_review(result, name):
    policy = _policy(result, name)
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False
    assert policy.review_reasons == []
    assert _records(result, name)[0].status == ExtractionStatus.NORMALIZED
    return policy


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
    assert "source-user" in policy.review_reasons


def test_category_preserved():
    policy = _policy(_extract(), "Identity-Category-HIP")
    assert policy.source_extra_settings["pan_category"] == ["adult", "malware"]
    assert "category" in policy.review_reasons


def test_source_hip_preserved():
    policy = _policy(_extract(), "Identity-Category-HIP")
    assert policy.source_extra_settings["pan_source_hip"] == ["hip-source"]
    assert "source-hip" in policy.review_reasons


def test_destination_hip_preserved():
    policy = _policy(_extract(), "Identity-Category-HIP")
    assert policy.source_extra_settings["pan_destination_hip"] == ["hip-destination"]
    assert "destination-hip" in policy.review_reasons


def test_category_any_is_preserved_without_category_review():
    result = _extract_config(DEFAULT_AND_METADATA_CONFIG)
    policy = _assert_normalized_without_review(result, "Category-Any")

    assert policy.source_extra_settings["pan_category"] == ["any"]


def test_hip_any_is_preserved_without_hip_review():
    result = _extract_config(DEFAULT_AND_METADATA_CONFIG)
    source_policy = _assert_normalized_without_review(result, "Source-HIP-Any")
    destination_policy = _assert_normalized_without_review(result, "Destination-HIP-Any")

    assert source_policy.source_extra_settings["pan_source_hip"] == ["any"]
    assert destination_policy.source_extra_settings["pan_destination_hip"] == ["any"]


def test_empty_hip_fields_are_preserved_without_hip_review():
    result = _extract_config(DEFAULT_AND_METADATA_CONFIG)
    source_policy = _assert_normalized_without_review(result, "Source-HIP-Empty")
    destination_policy = _assert_normalized_without_review(result, "Destination-HIP-Empty")

    assert source_policy.source_extra_settings["pan_source_hip"] == []
    assert destination_policy.source_extra_settings["pan_destination_hip"] == []


def test_tags_and_group_tag_are_preserved_metadata_without_review():
    result = _extract_config(DEFAULT_AND_METADATA_CONFIG)
    tags_policy = _assert_normalized_without_review(result, "Tags-Only")
    group_tag_policy = _assert_normalized_without_review(result, "Group-Tag-Only")

    assert tags_policy.source_extra_settings["pan_tags"] == ["retained-tag"]
    assert group_tag_policy.source_extra_settings["pan_group_tag"] == "retained-group"


def test_explicit_no_inspection_flags_use_default_effective_behavior():
    result = _extract_config(DEFAULT_AND_METADATA_CONFIG)
    policy = _assert_normalized_without_review(result, "Inspection-No")

    assert policy.source_extra_settings["pan_disable_inspect_value"] == "no"
    assert policy.source_extra_settings["pan_disable_server_response_inspection_value"] == "no"


def test_security_rule_uuid_is_preserved_separately_from_generated_source_rule_id():
    result = _extract_config(UUID_CONFIG)
    policy = _policy(result, "UUID-Rule")

    assert policy.source_uuid == "16a1a7c4-f1b2-4307-b898-8bdb4979d40d"
    assert policy.source_rule_id == "palo_alto:vsys:vsys1:local:0:UUID-Rule"
    assert policy.source_rule_id != policy.source_uuid
    assert policy.source_extra_settings["pan_source_uuid"] == policy.source_uuid
    assert policy.source_extra_settings["pan_source_entry"]["entry"]["attributes"] == {
        "name": "UUID-Rule",
        "uuid": "16a1a7c4-f1b2-4307-b898-8bdb4979d40d",
    }
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False


def test_security_rule_missing_uuid_is_none_without_review_or_parse_failure():
    result = _extract_config(UUID_CONFIG)
    policy = _policy(result, "Missing-UUID")

    assert policy.source_uuid is None
    assert "pan_source_uuid" not in policy.source_extra_settings
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False
    assert _records(result, "Missing-UUID")[0].status == ExtractionStatus.NORMALIZED


def test_security_rule_empty_uuid_is_normalized_to_none():
    result = _extract_config(UUID_CONFIG)
    policy = _policy(result, "Empty-UUID")

    assert policy.source_uuid is None
    assert "pan_source_uuid" not in policy.source_extra_settings
    assert _records(result, "Empty-UUID")[0].status == ExtractionStatus.NORMALIZED


def test_legacy_hip_profiles_any_maps_to_source_hip_without_unknown_review():
    result = _extract_config(LEGACY_HIP_CONFIG)
    policy = _policy(result, "Legacy-HIP-Any")

    assert policy.source_extra_settings["pan_legacy_hip_profiles"] == ["any"]
    assert policy.source_extra_settings["pan_source_hip"] == ["any"]
    assert policy.source_extra_settings["pan_destination_hip"] == []
    assert "pan_unknown_fields" not in policy.source_extra_settings
    assert "unknown-fields" not in policy.review_reasons
    assert policy.migration_status == "NORMALIZED"
    assert policy.source_extra_settings["pan_source_entry"]["entry"]["hip-profiles"] == {
        "member": {"text": "any"}
    }


def test_non_any_legacy_hip_profile_is_extracted_with_specific_review_reason():
    result = _extract_config(LEGACY_HIP_CONFIG)
    policy = _policy(result, "Legacy-HIP-Named")

    assert policy.source_extra_settings["pan_legacy_hip_profiles"] == ["Corporate-HIP"]
    assert policy.source_extra_settings["pan_source_hip"] == ["Corporate-HIP"]
    assert policy.source_extra_settings["pan_destination_hip"] == []
    assert "legacy-hip-profile" in policy.review_reasons
    assert "unknown-fields" not in policy.review_reasons
    assert _records(result, "Legacy-HIP-Named")[0].status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_modern_hip_fields_keep_existing_behavior_without_legacy_field():
    result = _extract()
    policy = _policy(result, "Identity-Category-HIP")

    assert policy.source_extra_settings["pan_source_hip"] == ["hip-source"]
    assert policy.source_extra_settings["pan_destination_hip"] == ["hip-destination"]
    assert policy.source_extra_settings["pan_legacy_hip_profiles"] == []
    assert "source-hip" in policy.review_reasons
    assert "destination-hip" in policy.review_reasons
    assert policy.migration_status == "PARTIALLY_NORMALIZED"
    assert policy.requires_manual_review is True


def test_modern_hip_fields_take_precedence_but_legacy_value_is_preserved():
    result = _extract_config(LEGACY_HIP_CONFIG)
    policy = _policy(result, "Mixed-HIP")

    assert policy.source_extra_settings["pan_source_hip"] == ["Modern-Source-HIP"]
    assert policy.source_extra_settings["pan_destination_hip"] == ["Modern-Destination-HIP"]
    assert policy.source_extra_settings["pan_legacy_hip_profiles"] == ["Legacy-HIP"]
    assert "legacy-hip-profile" in policy.review_reasons
    assert "source-hip" in policy.review_reasons
    assert "destination-hip" in policy.review_reasons
    assert "unknown-fields" not in policy.review_reasons


def test_negate_source_preserved():
    policy = _policy(_extract(), "Identity-Category-HIP")
    assert policy.source_address_negate_setting == "yes"
    assert policy.source_extra_settings["pan_negate_source_explicit"] is True
    assert "address-negation" in policy.review_reasons


def test_negate_destination_preserved():
    policy = _policy(_extract(), "Identity-Category-HIP")
    assert policy.destination_address_negate_setting == "no"
    assert policy.source_extra_settings["pan_negate_destination_value"] == "no"
    assert "address-negation" in policy.review_reasons


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
    assert "unresolved-sources" in policy.review_reasons


def test_direct_ipv4_policy_address_is_retained_without_unresolved_review():
    result = _extract_config(_address_policy_config(_security_rule("Direct-IPv4", "10.1.4.23", "any")))
    policy = _policy(result, "Direct-IPv4")

    assert policy.source == ["10.1.4.23"]
    assert policy.source_address_references == ["10.1.4.23"]
    assert policy.source_extra_settings["pan_direct_source_addresses"] == ["10.1.4.23"]
    assert "pan_unresolved_sources" not in policy.source_extra_settings
    assert "unresolved-sources" not in policy.review_reasons
    assert policy.migration_status == "NORMALIZED"


def test_direct_ipv4_and_ipv6_cidr_policy_addresses_are_retained():
    result = _extract_config(_address_policy_config(
        _security_rule("Direct-CIDRs", "10.10.0.0/16", "2001:db8::/64")
    ))
    policy = _policy(result, "Direct-CIDRs")

    assert policy.source == ["10.10.0.0/16"]
    assert policy.destination == ["2001:db8::/64"]
    assert policy.source_address_references == ["10.10.0.0/16"]
    assert policy.destination_address_references == ["2001:db8::/64"]
    assert policy.source_extra_settings["pan_direct_source_addresses"] == ["10.10.0.0/16"]
    assert policy.source_extra_settings["pan_direct_destination_addresses"] == ["2001:db8::/64"]
    assert "pan_unresolved_sources" not in policy.source_extra_settings
    assert "pan_unresolved_destinations" not in policy.source_extra_settings
    assert policy.requires_manual_review is False


def test_predefined_policy_regions_are_retained_and_invalid_codes_remain_unresolved():
    result = _extract_config(_address_policy_config(
        _security_rule("Predefined-Regions", "AU", "DE")
        + _security_rule("Invalid-Region", "ZZ", "ZZ")
    ))
    predefined = _policy(result, "Predefined-Regions")
    invalid = _policy(result, "Invalid-Region")

    assert predefined.source == ["AU"]
    assert predefined.destination == ["DE"]
    assert predefined.source_address_references == ["AU"]
    assert predefined.destination_address_references == ["DE"]
    assert predefined.source_extra_settings["pan_predefined_source_regions"] == ["AU"]
    assert predefined.source_extra_settings["pan_predefined_destination_regions"] == ["DE"]
    assert "pan_unresolved_sources" not in predefined.source_extra_settings
    assert "pan_unresolved_destinations" not in predefined.source_extra_settings
    assert predefined.requires_manual_review is False

    assert invalid.source == ["ZZ"]
    assert invalid.destination == ["ZZ"]
    assert invalid.source_extra_settings["pan_unresolved_sources"] == ["ZZ"]
    assert invalid.source_extra_settings["pan_unresolved_destinations"] == ["ZZ"]
    assert "unresolved-sources" in invalid.review_reasons
    assert "unresolved-destinations" in invalid.review_reasons


def test_resolver_precedes_predefined_region_fallback_and_keeps_groups_resolved():
    objects = """
      <address>
        <entry name="AU"><ip-netmask>192.0.2.10/32</ip-netmask></entry>
      </address>
      <address-group>
        <entry name="Region-Group"><static><member>AU</member></static></entry>
      </address-group>
    """
    shared_objects = """
      <shared>
        <address>
          <entry name="AU"><ip-netmask>192.0.2.11/32</ip-netmask></entry>
        </address>
      </shared>
    """
    result = _extract_config(_address_policy_config(
        _security_rule("Resolver-Precedence", "AU", "Region-Group"), objects, shared_objects
    ))
    policy = _policy(result, "Resolver-Precedence")

    assert policy.source == ["vsys1::AU"]
    assert policy.destination == ["Region-Group"]
    assert policy.source_extra_settings["pan_source"] == ["AU"]
    assert policy.source_extra_settings["pan_destination"] == ["Region-Group"]
    assert "pan_predefined_source_regions" not in policy.source_extra_settings
    assert "pan_predefined_destination_regions" not in policy.source_extra_settings
    assert "pan_unresolved_sources" not in policy.source_extra_settings
    assert "pan_unresolved_destinations" not in policy.source_extra_settings


def test_policy_address_helpers_require_valid_values():
    parser = PANOSSourceParser()

    assert parser._is_direct_policy_address("10.1.4.23")
    assert parser._is_direct_policy_address("2001:db8::1")
    assert parser._is_direct_policy_address("10.10.0.0/16")
    assert parser._is_direct_policy_address("2001:db8::/64")
    assert not parser._is_direct_policy_address("Address-Object")
    assert parser._is_predefined_policy_region("AU")
    assert parser._is_predefined_policy_region("DE")
    assert not parser._is_predefined_policy_region("ZZ")


def test_unresolved_service_requires_review():
    policy = _policy(_extract(), "Unresolved-Service")
    assert policy.service == ["Missing-Service"]
    assert policy.source_extra_settings["pan_unresolved_services"] == ["Missing-Service"]


def test_unknown_policy_field_is_partial():
    result = _extract()
    policy = _policy(result, "Unknown-Field")
    assert "retain-me" in str(policy.source_extra_settings["pan_unknown_fields"])
    assert "unknown-fields" in policy.review_reasons
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


def test_predefined_application_is_classified_without_metadata_fabrication():
    policy = _policy(_extract(), "Predefined-App")
    assert policy.applications == ["ssl"]
    assert "pan_unresolved_applications" not in policy.source_extra_settings
    assert policy.source_extra_settings["pan_application_reference_classification"] == [{
        "original_name": "ssl", "classification": "PREDEFINED_REFERENCE",
        "resolved_name": "ssl", "resolved_scope": None,
    }]
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
