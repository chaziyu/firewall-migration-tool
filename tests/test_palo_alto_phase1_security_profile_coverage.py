from fwmigrate.parsers.palo_alto import PANOSSourceParser


PROFILE_DEFINITIONS = """
<profiles>
  <gtp>
    <entry name="gtp-a"><description>GTP A</description></entry>
    <entry name="gtp-b"/>
  </gtp>
  <sctp>
    <entry name="sctp-a"><description>SCTP A</description></entry>
    <entry name="sctp-b"/>
  </sctp>
  <ai-security>
    <entry name="ai-a">
      <description>AI A</description>
      <data-privacy><enabled>yes</enabled></data-privacy>
    </entry>
    <entry name="ai-b"/>
  </ai-security>
</profiles>
"""


def _rule(profile_setting: str, *, name: str = "Rule1") -> str:
    return f"""
    <entry name="{name}">
      <from><member>trust</member></from>
      <to><member>untrust</member></to>
      <source><member>10.0.0.1</member></source>
      <destination><member>8.8.8.8</member></destination>
      <application><member>any</member></application>
      <service><member>application-default</member></service>
      {profile_setting}
      <action>allow</action>
    </entry>
    """


def _local_config(*, profiles: str = PROFILE_DEFINITIONS, profile_groups: str = "", rule: str) -> str:
    return f"""<?xml version="1.0"?>
    <config version="12.1.0">
      <devices>
        <entry name="localhost.localdomain">
          <vsys>
            <entry name="vsys1">
              {profiles}
              {profile_groups}
              <rulebase><security><rules>{rule}</rules></security></rulebase>
            </entry>
          </vsys>
        </entry>
      </devices>
    </config>
    """


def test_direct_gtp_sctp_ai_security_profiles_are_inventory_resolved_and_ordered():
    setting = """
    <profile-setting><profiles>
      <gtp><member>gtp-a</member><member>gtp-b</member></gtp>
      <sctp><member>sctp-a</member><member>sctp-b</member></sctp>
      <ai-security><member>ai-a</member><member>ai-b</member></ai-security>
    </profiles></profile-setting>
    """
    result = PANOSSourceParser().extract(
        _local_config(rule=_rule(setting))
    )

    definitions = {
        (profile.source_family, profile.name)
        for profile in result.canonical_ir.security_profile_definitions
    }
    assert ("gtp", "gtp-a") in definitions
    assert ("sctp", "sctp-a") in definitions
    assert ("ai-security", "ai-a") in definitions

    policy = result.canonical_ir.policies[0]
    assert policy.source_security_profile_references == {
        "gtp[0]": "gtp-a",
        "gtp[1]": "gtp-b",
        "sctp[0]": "sctp-a",
        "sctp[1]": "sctp-b",
        "ai-security[0]": "ai-a",
        "ai-security[1]": "ai-b",
    }
    assert set(policy.security_profile_reference_statuses.values()) == {"resolved"}
    assert policy.unresolved_security_profile_references == {}
    assert policy.source_profile_type == "profiles"
    assert policy.source_extra_settings["pan_additional_security_profiles"] == {
        "gtp": ["gtp-a", "gtp-b"],
        "sctp": ["sctp-a", "sctp-b"],
        "ai-security": ["ai-a", "ai-b"],
    }
    assert "pan_unknown_direct_profile_types" not in policy.source_extra_settings
    assert "unknown-profile-fields" not in policy.review_reasons
    assert "source-specific-security-profile-family" in policy.review_reasons


def test_profile_group_gtp_sctp_ai_security_members_are_resolved_without_unknown_classification():
    groups = """
    <profile-group>
      <entry name="mobile-profiles">
        <gtp><member>gtp-a</member><member>gtp-b</member></gtp>
        <sctp><member>sctp-a</member><member>sctp-b</member></sctp>
        <ai-security><member>ai-a</member><member>ai-b</member></ai-security>
      </entry>
    </profile-group>
    """
    setting = """
    <profile-setting><group><member>mobile-profiles</member></group></profile-setting>
    """
    result = PANOSSourceParser().extract(
        _local_config(profile_groups=groups, rule=_rule(setting))
    )

    group = result.canonical_ir.security_profile_groups[0]
    assert group.source_profile_references["gtp[0]"] == "gtp-a"
    assert group.source_profile_references["gtp[1]"] == "gtp-b"
    assert group.source_profile_references["sctp[0]"] == "sctp-a"
    assert group.source_profile_references["ai-security[1]"] == "ai-b"
    assert group.source_attributes["pan_additional_profile_members"] == {
        "gtp": ["gtp-a", "gtp-b"],
        "sctp": ["sctp-a", "sctp-b"],
        "ai-security": ["ai-a", "ai-b"],
    }
    assert set(
        group.source_attributes["pan_additional_profile_reference_statuses"].values()
    ) == {"resolved"}
    assert "pan_unknown_fields" not in group.source_attributes

    policy = result.canonical_ir.policies[0]
    assert policy.security_profile_reference_statuses == {
        "profile-group[0]": "resolved"
    }


def test_shared_new_profile_definitions_resolve_from_vsys_policy_scope():
    setting = """
    <profile-setting><profiles>
      <gtp><member>gtp-shared</member></gtp>
      <sctp><member>sctp-shared</member></sctp>
      <ai-security><member>ai-shared</member></ai-security>
    </profiles></profile-setting>
    """
    xml = f"""<?xml version="1.0"?>
    <config version="12.1.0">
      <shared>
        <profiles>
          <gtp><entry name="gtp-shared"/></gtp>
          <sctp><entry name="sctp-shared"/></sctp>
          <ai-security><entry name="ai-shared"/></ai-security>
        </profiles>
      </shared>
      <devices>
        <entry name="localhost.localdomain">
          <vsys><entry name="vsys1">
            <rulebase><security><rules>{_rule(setting)}</rules></security></rulebase>
          </entry></vsys>
        </entry>
      </devices>
    </config>
    """
    result = PANOSSourceParser().extract(xml)
    policy = result.canonical_ir.policies[0]

    assert policy.security_profile_reference_statuses == {
        "gtp[0]": "resolved",
        "sctp[0]": "resolved",
        "ai-security[0]": "resolved",
    }
    assert policy.unresolved_security_profile_references == {}


def test_unknown_future_direct_profile_family_remains_unknown_and_reviewable():
    setting = """
    <profile-setting><profiles>
      <future-security><member>future-1</member></future-security>
    </profiles></profile-setting>
    """
    result = PANOSSourceParser().extract(
        _local_config(rule=_rule(setting))
    )
    policy = result.canonical_ir.policies[0]

    assert "future-security" in policy.source_extra_settings[
        "pan_unknown_direct_profile_types"
    ]
    assert "unknown-profile-fields" in policy.review_reasons
