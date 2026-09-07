from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_firewall_policy_ips_voip_filter_is_typed_and_preserved() -> None:
    config = '''
config firewall policy
    edit 10
        set name "VoIP IPS policy"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set ips-voip-filter "voip-sec"
    next
end
'''

    parsed = parse_fortigate_config(config)
    policy = parsed.policies[0]

    assert "ips_voip_filter" in type(policy).model_fields
    assert policy.ips_voip_filter == "voip-sec"
    assert "ips_voip_filter" not in policy.extra_settings

    result = extract_fortigate_config(config)
    ir_policy = result.canonical_ir.policies[0]

    assert ir_policy.source_security_profile_references["ips_voip_filter"] == "voip-sec"
    assert ir_policy.security_profile_reference_statuses["ips_voip_filter"] == "missing"
    assert (
        ir_policy.unresolved_security_profile_references["ips_voip_filter"]
        == "not found in context: root"
    )
    assert "ips-voip-filter:voip-sec" in ir_policy.unresolved_security_profiles

    dependency = next(
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field == "ips-voip-filter"
    )
    assert dependency.expected_type == "voip profile"
    assert dependency.result == "UNRESOLVED"

    inventory = next(
        item for item in result.inventory_items
        if item.source_path == "firewall policy"
    )
    command = next(
        command for command in inventory.commands
        if command.key == "ips-voip-filter"
    )
    assert command.operation == "set"
    assert command.values == ["voip-sec"]


def test_firewall_policy_ips_voip_filter_resolves_in_same_context() -> None:
    config = '''
config voip profile
    edit "voip-sec"
        set comment "VoIP inspection profile"
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
        set ips-voip-filter "voip-sec"
    next
end
'''

    result = extract_fortigate_config(config)
    policy = result.canonical_ir.policies[0]

    assert policy.source_security_profile_references["ips_voip_filter"] == "voip-sec"
    assert policy.security_profile_reference_statuses["ips_voip_filter"] == "resolved"
    assert "ips_voip_filter" not in policy.unresolved_security_profile_references
    assert "ips-voip-filter:voip-sec" not in policy.unresolved_security_profiles

    dependency = next(
        dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall policy"
        and dependency.source_field == "ips-voip-filter"
    )
    assert dependency.expected_type == "voip profile"
    assert dependency.result == "RESOLVED"


def test_ips_voip_filter_extension_preserves_phase1_dlp_profile_support() -> None:
    config = '''
config firewall policy
    edit 30
        set dlp-profile "corp-dlp"
        set ips-voip-filter "voip-sec"
    next
end
'''

    policy = parse_fortigate_config(config).policies[0]

    assert policy.dlp_profile == "corp-dlp"
    assert policy.ips_voip_filter == "voip-sec"
