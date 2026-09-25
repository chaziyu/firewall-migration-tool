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
