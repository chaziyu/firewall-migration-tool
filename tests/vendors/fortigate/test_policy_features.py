from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def test_security_policy_protocol_options_and_per_ip_shaper_are_typed_and_linked():
    source = """config firewall profile-protocol-options
    edit proto
        set comment explicit-profile
        config http
            set ports 8080
            set future-http-option preserve-me
        end
    next
end
config firewall shaper per-ip-shaper
    edit client-limit
        set max-bandwidth 2000
        set max-concurrent-session 5
    next
end
config firewall policy
    edit 1
        set profile-protocol-options proto
        set per-ip-shaper client-limit
    next
end
config firewall security-policy
    edit 41
        set action accept
        set app-category 2 3
        set future-policy-option preserve-me-too
    next
end
"""
    reporter = FortiGateSourceReporter()
    analysis = reporter.analyze_source(source)
    assert analysis.extracted.config.security_policies[0].policy_id == 41
    assert analysis.extracted.config.security_policies[0].app_category == [2, 3]
    assert analysis.extracted.config.security_policies[0].raw_extra["future-policy-option"] == "preserve-me-too"
    assert analysis.extracted.config.protocol_options[0].comment == "explicit-profile"
    assert analysis.extracted.config.per_ip_shapers[0].max_bandwidth == 2000
    assert not analysis.derived.broken_references
