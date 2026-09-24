from fwmigrate.vendors.palo_alto.source_builder import build_panos_config


def test_security_profile_xml_reaches_typed_profile_group_and_rule():
    config = build_panos_config("""<config><shared>
      <profile-group><entry name='strict-profiles'><virus><member>av-default</member></virus></entry></profile-group>
      <rulebase><security><rules><entry name='allow-web'><profile-setting><group><member>strict-profiles</member></group></profile-setting><action>allow</action></entry></rules></security></rulebase>
    </shared></config>""")

    profile_group = config.security_profile_groups[0]
    rule = config.security_rules[0]
    assert profile_group.name == "strict-profiles"
    assert profile_group.antivirus == ["av-default"]
    assert rule.name == "allow-web"
    assert rule.profile_setting.groups == ["strict-profiles"]
    assert rule.action == "allow"


def test_security_profile_unknown_source_is_retained_separately():
    config = build_panos_config("<config><shared><profile-group><entry name='strict'><future-setting>retain-me</future-setting></entry></profile-group></shared></config>")
    assert config.source_inventory
    assert config.security_profile_groups[0].raw_extra["future-setting"] == "retain-me"


def test_vulnerability_block_ip_and_exempt_ips_are_extracted_explicitly():
    config = build_panos_config("""<config><shared><profiles><vulnerability><entry name='vulnerability-main'>
      <rules><entry name='block-threat'><threat-name>critical-threat</threat-name><vendor-id><member>123</member></vendor-id><severity><member>critical</member></severity><action><block-ip><track-by>source</track-by><duration>3600</duration><future-action>retain-me</future-action></block-ip></action><future-rule-field>retain-rule</future-rule-field></entry><entry name='reset-threat'><action><reset-both/></action></entry></rules>
      <exceptions><entry name='allow-known'><action><block-ip><track-by>source-and-destination</track-by><duration>60</duration></block-ip></action><exempt-ips><member>192.0.2.10</member><member>192.0.2.11</member></exempt-ips></entry></exceptions>
    </entry></vulnerability></profiles></shared></config>""")

    profile = config.vulnerability_profiles[0]
    rule = profile.rules[0]
    exception = profile.exceptions[0]
    assert (rule.block_ip.track_by, rule.block_ip.duration) == ("source", "3600")
    assert (rule.vendor_ids, rule.severities, rule.action) == (["123"], ["critical"], "block-ip")
    assert {"vendor_ids", "severities", "action", "block_ip"} <= rule.explicit_fields
    assert profile.rules[1].action == "reset-both"
    assert rule.block_ip.raw_extra["future-action"] == "retain-me"
    assert rule.raw_extra["future-rule-field"] == "retain-rule"
    assert (exception.block_ip.track_by, exception.block_ip.duration) == ("source-and-destination", "60")
    assert exception.exempt_ips == ["192.0.2.10", "192.0.2.11"]


def test_vulnerability_missing_and_empty_nested_sections_preserve_source_presence():
    config = build_panos_config("""<config><shared><profiles><vulnerability>
      <entry name='missing'/><entry name='empty'><rules/><exceptions/></entry>
    </vulnerability></profiles></shared></config>""")

    missing, empty = config.vulnerability_profiles
    assert missing.rules is None
    assert missing.exceptions is None
    assert "rules" not in missing.explicit_fields
    assert "exceptions" not in missing.explicit_fields
    assert empty.rules == []
    assert empty.exceptions == []
    assert {"rules", "exceptions"} <= empty.explicit_fields


def test_selected_threat_exception_time_attribute_and_exempt_ip_are_extracted():
    config = build_panos_config("""<config><shared><profiles><vulnerability><entry name='vulnerability-main'>
      <threat-exception><entry name='allow-known'><action><alert/></action>
        <time-attribute><interval>60</interval><threshold>10</threshold><track-by>source-and-destination</track-by><future-time>keep-time</future-time></time-attribute>
        <exempt-ip><member>192.0.2.10</member></exempt-ip><future-exception>keep-exception</future-exception>
      </entry></threat-exception>
    </entry></vulnerability></profiles></shared></config>""")
    profile, = config.vulnerability_profiles
    exception, = profile.exceptions
    assert (exception.action, exception.time_interval, exception.time_threshold, exception.time_track_by) == ("alert", "60", "10", "source-and-destination")
    assert exception.exempt_ips == ["192.0.2.10"]
    assert {"time_interval", "time_threshold", "time_track_by", "exempt_ips"} <= exception.explicit_fields
    assert "time_attribute" not in exception.explicit_fields
    assert exception.raw_extra["time-attribute"]["future-time"] == "keep-time"
    assert exception.raw_extra["future-exception"] == "keep-exception"
