from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config


def _policy(config: str):
    return extract_fortigate_config(config).canonical_ir.policies[0]


def _local_in(config: str):
    return extract_fortigate_config(config).canonical_ir.local_in_policies[0]


def test_firewall_policy_internet_service_withholds_ignored_fields_but_preserves_source():
    policy = _policy(
        '''config firewall policy
    edit 1
        set srcaddr "SRC-C" "SRC-A"
        set dstaddr "DST-C" "DST-A"
        set service "HTTPS" "SSH"
        set internet-service enable
        set internet-service-id 65646
        set internet-service-name "TEST-IS"
        set dstaddr-negate enable
        set service-negate enable
    next
end
'''
    )

    assert policy.source == ["SRC-C", "SRC-A"]
    assert policy.destination == []
    assert policy.service == []
    assert policy.destination_address_references == ["DST-C", "DST-A"]
    assert policy.source_service_references == ["HTTPS", "SSH"]
    assert policy.source_internet_service_settings["internet-service-id"] == "65646"
    assert policy.source_internet_service_settings["internet-service-name"] == ["TEST-IS"]
    assert policy.requires_manual_review is True
    assert any("dstaddr" in reason and "service" in reason for reason in policy.review_reasons)
    assert any("dstaddr_negate" in reason for reason in policy.review_reasons)
    assert any("service_negate" in reason for reason in policy.review_reasons)
    assert policy.safe_for_target_generation is False


def test_firewall_policy_ipv6_internet_service_withholds_ipv6_destination_and_service():
    policy = _policy(
        '''config firewall policy
    edit 2
        set srcaddr "SRC"
        set dstaddr "DST"
        set srcaddr6 "SRC6"
        set dstaddr6 "DST6-C" "DST6-A"
        set service "HTTPS"
        set internet-service6 enable
        set internet-service6-name "TEST6-IS"
        set dstaddr6-negate enable
    next
end
'''
    )

    assert policy.source == ["SRC"]
    assert policy.destination == ["DST"]
    assert policy.service == []
    assert policy.destination_ipv6_address_references == ["DST6-C", "DST6-A"]
    assert policy.source_internet_service_settings["internet-service6-name"] == ["TEST6-IS"]
    assert any("dstaddr6" in reason for reason in policy.review_reasons)
    assert any("service" in reason for reason in policy.review_reasons)


def test_firewall_policy_source_internet_service_withholds_ordinary_source_matches():
    policy = _policy(
        '''config firewall policy
    edit 5
        set srcaddr "SRC-C" "SRC-A"
        set srcaddr6 "SRC6-C" "SRC6-A"
        set dstaddr "DST"
        set service "HTTPS"
        set internet-service-src enable
        set internet-service-src-name "TEST-SOURCE-IS"
        set internet-service6-src enable
        set internet-service6-src-name "TEST6-SOURCE-IS"
        set srcaddr-negate enable
        set srcaddr6-negate enable
    next
end
'''
    )

    assert policy.source == []
    assert policy.destination == ["DST"]
    assert policy.service == ["HTTPS"]
    assert policy.source_address_references == ["SRC-C", "SRC-A"]
    assert policy.source_ipv6_address_references == ["SRC6-C", "SRC6-A"]
    assert any("srcaddr" in reason and "not effective" in reason for reason in policy.review_reasons)
    assert any("srcaddr6" in reason and "not effective" in reason for reason in policy.review_reasons)
    assert policy.source_internet_service_settings["internet-service-src-name"] == ["TEST-SOURCE-IS"]
    assert policy.source_internet_service_settings["internet-service6-src-name"] == ["TEST6-SOURCE-IS"]


def test_firewall_policy_disabled_or_omitted_internet_service_keeps_ordinary_matches():
    result = extract_fortigate_config(
        '''config firewall policy
    edit 3
        set srcaddr "SRC"
        set dstaddr "DST"
        set service "HTTPS"
        set internet-service disable
    next
    edit 4
        set srcaddr "SRC2"
        set dstaddr "DST2"
        set service "SSH"
    next
end
'''
    )

    disabled, omitted = result.canonical_ir.policies
    for policy in (disabled, omitted):
        assert policy.source
        assert policy.destination
        assert policy.service
        assert not any("ordinary portable match criteria" in reason for reason in policy.review_reasons)
        assert "internet-service" not in policy.source_internet_service_settings


def test_local_in_ipv4_internet_service_source_disables_ordinary_source_fields_only():
    result = extract_fortigate_config(
        '''config firewall local-in-policy
    edit 10
        set intf "wan1"
        set srcaddr "C" "A" "B"
        set srcaddr-negate enable
        set internet-service-src enable
        set internet-service-src-name "TEST-IS"
        set dstaddr "all"
        set service "HTTPS"
    next
end
'''
    )
    rule = result.canonical_ir.local_in_policies[0]

    assert rule.family == "local-in-policy-ipv4"
    assert rule.source_attributes["srcaddr"] == ["C", "A", "B"]
    assert rule.source_attributes["srcaddr_negate"] == "enable"
    assert rule.source_attributes["internet_service_src"] == "enable"
    assert rule.source_attributes["internet_service_src_name"] == ["TEST-IS"]
    assert any("srcaddr" in reason and "not effective" in reason for reason in rule.review_reasons)
    assert any("srcaddr_negate" in reason and "inactive" in reason for reason in rule.review_reasons)
    assert rule.family == "local-in-policy-ipv4"


def test_local_in_ipv6_internet_service_source_disables_ordinary_ipv6_source_fields():
    rule = _local_in(
        '''config firewall local-in-policy6
    edit 20
        set intf "wan6"
        set srcaddr "SRC6-C" "SRC6-A"
        set srcaddr-negate enable
        set internet-service6-src enable
        set internet-service6-src-name "TEST6-IS"
        set dstaddr "all"
        set service "HTTPS"
    next
end
'''
    )

    assert rule.family == "local-in-policy-ipv6"
    assert rule.source_attributes["srcaddr"] == ["SRC6-C", "SRC6-A"]
    assert rule.source_attributes["srcaddr_negate"] == "enable"
    assert rule.source_attributes["internet_service6_src"] == "enable"
    assert "internet_service_src" not in rule.source_attributes
    assert any("IPv6 Internet Service" in reason and "srcaddr" in reason for reason in rule.review_reasons)


def test_local_in_disabled_or_omitted_internet_service_keeps_source_and_no_synthetic_mode():
    result = extract_fortigate_config(
        '''config firewall local-in-policy
    edit 30
        set srcaddr "SRC"
        set internet-service-src disable
    next
    edit 31
        set srcaddr "SRC2"
    next
end
'''
    )

    disabled, omitted = result.canonical_ir.local_in_policies
    assert disabled.source_attributes["srcaddr"]
    assert disabled.source_attributes["internet_service_src"] == "disable"
    assert not any("ordinary source match criteria" in reason for reason in disabled.review_reasons)
    assert omitted.source_attributes["srcaddr"]
    assert "internet_service_src" not in omitted.source_attributes
    assert not any("ordinary source match criteria" in reason for reason in omitted.review_reasons)
