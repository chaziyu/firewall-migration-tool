from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


PHASE3_PROFILE_FIELDS = {
    "casb-profile": "casb profile",
    "cifs-profile": "cifs profile",
    "diameter-filter-profile": "diameter-filter profile",
    "dnsfilter-profile": "dnsfilter profile",
    "emailfilter-profile": "emailfilter profile",
    "file-filter-profile": "file-filter profile",
    "icap-profile": "icap profile",
    "profile-protocol-options": "firewall profile-protocol-options",
    "sctp-filter-profile": "sctp-filter profile",
    "ssh-filter-profile": "ssh-filter profile",
    "videofilter-profile": "videofilter profile",
    "virtual-patch-profile": "virtual-patch profile",
    "voip-profile": "voip profile",
    "waf-profile": "waf profile",
}


def _policy_with_phase3_profiles() -> str:
    profile_lines = "\n".join(
        f'        set {field} "{field}-obj"' for field in PHASE3_PROFILE_FIELDS
    )
    return f'''\nconfig firewall policy\n    edit 100\n        set name "phase3-profile-policy"\n        set srcintf "any"\n        set dstintf "any"\n        set srcaddr "all"\n        set dstaddr "all"\n        set action accept\n        set schedule "always"\n        set service "ALL"\n{profile_lines}\n        set dlp-profile "dlp-existing"\n        set ips-voip-filter "ips-voip-existing"\n    next\nend\n'''


def test_phase3_policy_profile_fields_are_typed_and_dependency_accounted() -> None:
    config = _policy_with_phase3_profiles()
    parsed = parse_fortigate_config(config)
    policy = parsed.policies[0]

    for cli_field in PHASE3_PROFILE_FIELDS:
        attr = cli_field.replace("-", "_")
        assert attr in type(policy).model_fields
        assert getattr(policy, attr) == f"{cli_field}-obj"
        assert attr not in policy.extra_settings

    result = extract_fortigate_config(config)
    ir_policy = result.canonical_ir.policies[0]

    dependencies = {
        record.source_field: record
        for record in result.dependencies
        if record.source_path == "firewall policy"
        and record.source_field in PHASE3_PROFILE_FIELDS
    }
    assert set(dependencies) == set(PHASE3_PROFILE_FIELDS)

    for cli_field, expected_type in PHASE3_PROFILE_FIELDS.items():
        attr = cli_field.replace("-", "_")
        expected_name = f"{cli_field}-obj"
        dependency = dependencies[cli_field]

        assert dependency.expected_type == expected_type
        assert dependency.result == "UNRESOLVED"
        assert ir_policy.source_security_profile_references[attr] == expected_name
        assert ir_policy.security_profile_reference_statuses[attr] == "missing"
        assert (
            ir_policy.unresolved_security_profile_references[attr]
            == "not found in context: root"
        )

    # Phase 3 must compose with Phase 1 and Phase 2 wrappers rather than
    # replacing their reference accounting.
    assert ir_policy.source_security_profile_references["dlp_profile"] == "dlp-existing"
    assert ir_policy.source_security_profile_references["ips_voip_filter"] == "ips-voip-existing"


def test_phase3_voip_profile_reference_resolves_in_same_context() -> None:
    config = '''
config voip profile
    edit "voice-sec"
    next
end
config firewall policy
    edit 200
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set voip-profile "voice-sec"
    next
end
'''

    result = extract_fortigate_config(config)
    policy = result.canonical_ir.policies[0]

    assert policy.source_security_profile_references["voip_profile"] == "voice-sec"
    assert policy.security_profile_reference_statuses["voip_profile"] == "resolved"
    assert "voip_profile" not in policy.unresolved_security_profile_references

    dependency = next(
        record
        for record in result.dependencies
        if record.source_path == "firewall policy"
        and record.source_field == "voip-profile"
    )
    assert dependency.expected_type == "voip profile"
    assert dependency.result == "RESOLVED"
