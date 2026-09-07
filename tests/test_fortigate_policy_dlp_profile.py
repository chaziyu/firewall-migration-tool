from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_firewall_policy_dlp_profile_is_typed_and_preserved() -> None:
    config = '''
config firewall policy
    edit 10
        set name "DLP policy"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set dlp-profile "corp-dlp"
    next
end
'''

    parsed = parse_fortigate_config(config)
    policy = parsed.policies[0]

    assert "dlp_profile" in type(policy).model_fields
    assert policy.dlp_profile == "corp-dlp"
    assert "dlp_profile" not in policy.extra_settings

    result = extract_fortigate_config(config)
    ir_policy = result.canonical_ir.policies[0]

    assert ir_policy.source_security_profile_references["dlp_profile"] == "corp-dlp"
    assert ir_policy.security_profile_reference_statuses["dlp_profile"] == "missing"
    assert (
        ir_policy.unresolved_security_profile_references["dlp_profile"]
        == "not found in context: root"
    )
    assert "dlp:corp-dlp" in ir_policy.unresolved_security_profiles

    dependency = next(
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field == "dlp-profile"
    )
    assert dependency.expected_type == "dlp profile"
    assert dependency.result == "UNRESOLVED"

    inventory = next(
        item
        for item in result.inventory_items
        if item.source_path == "firewall policy" and item.name == "10"
    )
    command = next(command for command in inventory.commands if command.key == "dlp-profile")
    assert command.operation == "set"
    assert command.values == ["corp-dlp"]


def test_firewall_policy_dlp_profile_resolves_in_same_context() -> None:
    config = '''
config dlp profile
    edit "corp-dlp"
        set comment "policy DLP profile"
    next
end
config firewall policy
    edit 20
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set dlp-profile "corp-dlp"
    next
end
'''

    result = extract_fortigate_config(config)
    policy = result.canonical_ir.policies[0]

    assert policy.source_security_profile_references["dlp_profile"] == "corp-dlp"
    assert policy.security_profile_reference_statuses["dlp_profile"] == "resolved"
    assert "dlp_profile" not in policy.unresolved_security_profile_references
    assert "dlp:corp-dlp" not in policy.unresolved_security_profiles

    dependency = next(
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field == "dlp-profile"
    )
    assert dependency.expected_type == "dlp profile"
    assert dependency.result == "RESOLVED"


def test_legacy_dlp_sensor_field_remains_available() -> None:
    config = '''
config firewall policy
    edit 30
        set dlp-sensor "legacy-dlp"
    next
end
'''

    policy = parse_fortigate_config(config).policies[0]

    assert policy.dlp_sensor == "legacy-dlp"
    assert policy.dlp_profile is None
