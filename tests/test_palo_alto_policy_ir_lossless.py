import pytest

from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fwmigrate.generators.palo_alto.transformer import IRToPANOSTransformer
from fwmigrate.ir.migrations import migrate_ir_payload
from fwmigrate.ir.enums import PolicyAction
from fwmigrate.ir.version import IR_SCHEMA_VERSION
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def _extract(*, profiles="", profile_groups="", profile_setting="", categories="", action="allow"):
    xml = f"""<?xml version="1.0"?>
    <config version="11.2.0">
      <devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
        {profiles}
        {profile_groups}
        <rulebase><security><rules><entry name="Rule1">
          <from><member>trust</member></from>
          <to><member>untrust</member></to>
          <source><member>10.0.0.1</member></source>
          <destination><member>8.8.8.8</member></destination>
          <application><member>any</member></application>
          <service><member>application-default</member></service>
          {categories}
          <action>{action}</action>
          {profile_setting}
        </entry></rules></security></rulebase>
      </entry></vsys></entry></devices>
    </config>"""
    return PANOSSourceParser().extract(xml)


def _profile_definitions():
    return """
    <profiles>
      <virus><entry name="av1"/><entry name="av2"/></virus>
      <vulnerability><entry name="v1"/><entry name="v2"/></vulnerability>
      <spyware><entry name="as1"/><entry name="as2"/></spyware>
      <custom-url-category><entry name="custom-cat">
        <list><member>example.com</member></list>
      </entry></custom-url-category>
    </profiles>
    """


def test_multiple_security_profile_groups_and_members_are_canonical():
    groups = """
    <profile-group>
      <entry name="g1">
        <virus><member>av1</member><member>av2</member></virus>
        <vulnerability><member>v1</member><member>v2</member></vulnerability>
      </entry>
      <entry name="g2"><spyware><member>as1</member><member>as2</member></spyware></entry>
    </profile-group>
    """
    result = _extract(
        profiles=_profile_definitions(),
        profile_groups=groups,
        profile_setting="<profile-setting><group><member>g1</member><member>g2</member></group></profile-setting>",
    )

    assert len(result.canonical_ir.policies) == 1
    policy = result.canonical_ir.policies[0]
    assert policy.security_profile_groups == ["g1", "g2"]
    assert policy.security_profile_group is None
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False
    assert policy.security_profile_reference_statuses == {
        "profile-group[0]": "resolved",
        "profile-group[1]": "resolved",
    }

    by_name = {group.name: group for group in result.canonical_ir.security_profile_groups}
    assert by_name["g1"].antivirus_profiles == ["av1", "av2"]
    assert by_name["g1"].vulnerability_profiles == ["v1", "v2"]
    assert by_name["g1"].antivirus is None
    assert by_name["g1"].vulnerability is None
    assert by_name["g1"].migration_status == "NORMALIZED"
    assert by_name["g2"].antispyware_profiles == ["as1", "as2"]
    assert by_name["g2"].anti_spyware is None


def test_multiple_direct_profiles_are_ordered_and_normalized():
    setting = """
    <profile-setting><profiles>
      <virus><member>av1</member><member>av2</member></virus>
      <vulnerability><member>v1</member><member>v2</member></vulnerability>
      <spyware><member>as1</member><member>as2</member></spyware>
    </profiles></profile-setting>
    """
    result = _extract(profiles=_profile_definitions(), profile_setting=setting)
    policy = result.canonical_ir.policies[0]

    assert policy.antivirus_profiles == ["av1", "av2"]
    assert policy.vulnerability_profiles == ["v1", "v2"]
    assert policy.antispyware_profiles == ["as1", "as2"]
    assert policy.antivirus is None
    assert policy.ips_sensor is None
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False
    assert "security-profiles" not in policy.review_reasons


def test_url_category_match_is_canonical_and_preserved_for_panos():
    result = _extract(
        profiles=_profile_definitions(),
        categories="<category><member>custom-cat</member><member>malware</member></category>",
    )
    policy = result.canonical_ir.policies[0]

    assert policy.url_categories == ["custom-cat", "malware"]
    assert policy.url_category_reference_statuses == {
        "category[0]": "custom-resolved",
        "category[1]": "predefined",
    }
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False

    pan = IRToPANOSTransformer(result.canonical_ir).transform()
    assert pan.vsys.security_rules[0].category == ["custom-cat", "malware"]


@pytest.mark.parametrize(
    ("source_action", "expected"),
    [
        ("allow", PolicyAction.ALLOW),
        ("deny", PolicyAction.DENY),
        ("drop", PolicyAction.DROP),
        ("reset-client", PolicyAction.RESET_CLIENT),
        ("reset-server", PolicyAction.RESET_SERVER),
        ("reset-both", PolicyAction.RESET_BOTH),
    ],
)
def test_exact_pan_actions_are_canonical(source_action, expected):
    result = _extract(action=source_action)
    policy = result.canonical_ir.policies[0]
    assert policy.action == expected
    assert policy.source_action == source_action
    assert policy.migration_status == "NORMALIZED"
    assert policy.requires_manual_review is False

    pan = IRToPANOSTransformer(result.canonical_ir).transform()
    assert pan.vsys.security_rules[0].action == source_action


def test_unsupported_target_action_is_withheld_not_collapsed_to_deny():
    result = _extract(action="reset-both")
    artifacts = FortiGateCLIGenerator().generate(result.canonical_ir)
    output = artifacts[0].content

    assert "Policy Rule1 withheld: target capability does not support policy action reset-both" in output
    assert 'set name "Rule1"' not in output


def test_schema_149_migrates_legacy_scalar_profile_projections():
    migrated = migrate_ir_payload({
        "schema_version": "1.49",
        "metadata": {"source_vendor": "palo_alto"},
        "policies": [{
            "name": "p1",
            "from_zone": ["trust"],
            "to_zone": ["untrust"],
            "source": ["any"],
            "destination": ["any"],
            "service": ["any"],
            "action": "allow",
            "security_profile_group": "g1",
            "antivirus": "av1",
        }],
        "security_profile_groups": [{"name": "g1", "antivirus": "av1"}],
    })

    assert migrated["schema_version"] == IR_SCHEMA_VERSION
    assert migrated["policies"][0]["security_profile_groups"] == ["g1"]
    assert migrated["policies"][0]["antivirus_profiles"] == ["av1"]
    assert migrated["policies"][0]["url_categories"] == []
    assert migrated["security_profile_groups"][0]["antivirus_profiles"] == ["av1"]
