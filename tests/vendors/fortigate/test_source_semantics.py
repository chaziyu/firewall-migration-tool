from fwmigrate.vendors.fortigate.extraction.source_metadata import capture_source_metadata
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def test_interface_ip_is_the_explicit_source_value():
    source = '''config system interface
    edit "wan1"
        set ip 192.0.2.10 255.255.255.0
    next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(source)
    interface = next(item for item in analysis.extracted.config.interfaces if item.name == "wan1")
    assert interface.ip == "192.0.2.10 255.255.255.0"


def test_capture_source_metadata_from_config_version_header():
    tree = parse_fortigate_config(
        "# unrelated\n"
        "#config-version=FG100E-7.2.13-FW-build1762-260128:opmode=0:vdom=0\n"
    )

    assert capture_source_metadata(tree).fortios_version == "7.2.13"


def test_capture_source_metadata_rejects_missing_or_malformed_header():
    for source in (
        "# unrelated\n",
        "#config-version=FG100E-7.2.13-build1762\n",
        "#config-version=7.2.13\n",
    ):
        assert capture_source_metadata(
            parse_fortigate_config(source)
        ).fortios_version is None


def test_missing_vpn_source_fields_remain_unconfigured():
    analysis = FortiGateSourceReporter().analyze_source('''config vpn ipsec phase1-interface
    edit "MINIMAL"
        set interface "wan1"
    next
end
''')
    phase1 = analysis.extracted.config.ipsec_phase1[0]

    assert phase1.ike_version is None
    assert phase1.remote_gw is None
    assert "ike_version" not in phase1.explicit_fields
    assert "remote_gw" not in phase1.explicit_fields


def test_explicit_fields_and_unknown_safe_settings_follow_source():
    analysis = FortiGateSourceReporter().analyze_source('''config system interface
    edit "wan1"
        set ip 192.0.2.10 255.255.255.0
        set vendor-option preserve-me
    next
end
''')
    interface = analysis.extracted.config.interfaces[0]

    assert interface.explicit_fields == {"ip"}
    assert interface.raw_extra == {"vendor-option": "preserve-me"}


def test_policy_absent_selectors_remain_unconfigured():
    analysis = FortiGateSourceReporter().analyze_source('''config firewall policy
    edit 1
        set srcaddr "all"
        append srcaddr "trusted"
    next
end
''')
    policy = analysis.extracted.config.policies[0]

    assert policy.srcintf is None
    assert policy.dstintf is None
    assert policy.srcaddr == ["all", "trusted"]
    assert policy.dstaddr is None
    assert policy.service is None
    assert policy.explicit_fields == {"srcaddr"}


def test_policy_unset_removes_the_source_value():
    analysis = FortiGateSourceReporter().analyze_source('''config firewall policy
    edit 1
        set srcaddr "all"
        unset srcaddr
    next
end
''')
    policy = analysis.extracted.config.policies[0]

    assert policy.srcaddr is None
    assert "srcaddr" not in policy.explicit_fields


def test_group_membership_absence_survives_extraction_and_derived_views():
    analysis = FortiGateSourceReporter().analyze_source('''config firewall addrgrp
    edit "empty-source-group"
    next
end
config firewall service group
    edit "empty-source-services"
    next
end
''')

    assert analysis.extracted.config.address_groups[0].members is None
    assert analysis.extracted.config.service_groups[0].members is None
    assert analysis.derived.services.groups[0].members is None


def test_unknown_secret_command_is_redacted_at_extraction_boundary():
    analysis = FortiGateSourceReporter().analyze_source('''config system interface
    edit "wan1"
        set vendor-secret "do-not-retain-this"
    next
end
''')
    interface = analysis.extracted.config.interfaces[0]

    assert interface.raw_extra == {"vendor-secret": "[REDACTED]"}
    assert "do-not-retain-this" not in repr(analysis.extracted.config)


def test_unknown_secret_set_then_unset_leaves_no_source_value():
    analysis = FortiGateSourceReporter().analyze_source('''config system interface
    edit "wan1"
        set vendor-secret "do-not-retain-this"
        unset vendor-secret
    next
end
''')

    assert analysis.extracted.config.interfaces[0].raw_extra == {}
    assert "do-not-retain-this" not in repr(analysis)
