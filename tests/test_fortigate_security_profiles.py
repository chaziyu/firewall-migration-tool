from pathlib import Path

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def test_ips_priority_fields_and_exempt_ips_are_typed():
    result = extract_fortigate_config('''
config ips sensor
    edit "ips"
        set extended-log enable
        set replacemsg-group "ips-msg"
        config entries
            edit 1
                set application "web"
                set cve "CVE-2024-1"
                set default-action block
                set default-status enable
                set log enable
                set log-packet enable
                set log-attack-context enable
                set os "Windows"
                set rate-mode continuous
                set rate-track src-ip
                set vuln-type 12 13
                set quarantine-log enable
                config exempt-ip
                    edit 1
                        set src-ip "192.0.2.0 255.255.255.0"
                    next
                end
            next
        end
    next
end
''')
    sensor = result.canonical_ir.ips_sensors[0]
    entry = sensor.entries[0]
    assert sensor.extended_log == "enable"
    assert entry.default_action == "block"
    assert entry.vuln_type == [12, 13]
    assert entry.exempt_ips[0].src_ip == "192.0.2.0 255.255.255.0"


def test_profile_group_is_typed_while_profile_fallback_remains_visible():
    result = extract_fortigate_config('''
config firewall profile-group
    edit "secure"
        set av-profile "av"
        set ips-sensor "ips"
        set ssl-ssh-profile "deep"
        set webfilter-profile "web"
    next
end
''')
    group = result.canonical_ir.security_profile_groups[0]
    assert group.support_level == "TYPED_EXTRACT_ONLY"
    assert group.source_profile_references["av_profile"] == "av"
    section = next(item for item in result.source_sections if item.path == "firewall profile-group")
    assert any("TYPED_EXTRACT_ONLY" in note for note in section.notes)


def test_policy_security_profile_references_resolve_by_vdom_and_retain_failures():
    result = extract_fortigate_config('''
config ips sensor
    edit "IPS1"
    next
end
config firewall policy
    edit 1
        set name "root-policy"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set ips-sensor "IPS1"
        set webfilter-profile "MISSING"
    next
end
config vdom
    edit "tenant"
        config ips sensor
            edit "IPS1"
            next
        end
        config firewall policy
            edit 2
                set name "tenant-policy"
                set srcintf "any"
                set dstintf "any"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set schedule "always"
                set service "ALL"
                set ips-sensor "IPS1"
            next
        end
    next
    edit "tenant2"
        config firewall policy
            edit 3
                set name "cross-context-policy"
                set srcintf "any"
                set dstintf "any"
                set srcaddr "all"
                set dstaddr "all"
                set action accept
                set schedule "always"
                set service "ALL"
                set ips-sensor "IPS1"
            next
        end
    next
end
''')
    policies = {policy.name: policy for policy in result.canonical_ir.policies}
    root = policies["root-policy"]
    tenant = policies["tenant-policy"]
    cross_context = policies["cross-context-policy"]
    assert root.security_profile_reference_statuses == {
        "ips_sensor": "resolved", "webfilter_profile": "missing",
    }
    assert root.unresolved_security_profile_references["webfilter_profile"] == (
        "not found in context: root"
    )
    assert tenant.security_profile_reference_statuses["ips_sensor"] == "resolved"
    assert cross_context.security_profile_reference_statuses["ips_sensor"] == "cross-context"
    assert "tenant" in cross_context.unresolved_security_profile_references["ips_sensor"]


def test_phase0_security_profile_fixture_preserves_source_sections():
    fixture = Path(__file__).parent / "fixtures" / "fortigate" / "security_profiles_full.conf"
    result = extract_fortigate_config(fixture.read_text())
    paths = {section.path for section in result.source_sections}
    assert {
        "ips sensor",
        "antivirus profile",
        "webfilter profile",
        "dnsfilter profile",
        "application list",
        "dlp sensor",
        "firewall ssl-ssh-profile",
    } <= paths
