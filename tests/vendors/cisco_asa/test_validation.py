from .helpers import assert_source_unchanged, snapshot_source
from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source
from fwmigrate.vendors.cisco_asa.validation import validate_asa_config


def test_validation_is_repeatable_and_does_not_change_extraction_status():
    result = extract_cisco_asa_source("crypto map VPN 10 match address MISSING\n")
    snapshot = snapshot_source(result.config)

    first = validate_asa_config(result.config, result.derived)
    second = validate_asa_config(result.config, result.derived)

    assert first == second
    assert_source_unchanged(result.config, snapshot)
    assert any(issue.category == "parse" for issue in first.issues) == bool(result.config.diagnostics)


def test_unresolved_relationship_does_not_change_extracted_source_status():
    result = extract_cisco_asa_source(
        "interface Ethernet0/0\n nameif outside\n"
        "access-group MISSING in interface outside\n"
    )
    binding = result.config.acl_bindings[0]

    assert binding.extraction_status == "EXTRACTED"
    assert not result.config.diagnostics
    assert any(issue.reference_name == "MISSING" and not issue.resolved for issue in result.derived.relationship_issues)
    assert any(issue.category == "acl" and "Unresolved" in issue.message for issue in result.validation.issues)
