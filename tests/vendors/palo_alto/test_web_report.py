from pathlib import Path

from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_web_report_has_expected_sections():
    source = (Path(__file__).parents[2] / "fixtures" / "example_palo_alto.xml").read_text()
    sections = PaloAltoSourceReporter().build_preview(PaloAltoSourceReporter().analyze_source(source))["sections"]
    assert {"interfaces", "policies", "nat", "validation"}.issubset(sections)


def test_web_report_counts_and_sections_include_identity_and_sdwan_domains():
    source = """<config><shared>
      <local-user><entry name='alice'><disabled>no</disabled><password>do-not-export</password></entry></local-user>
      <local-user-group><entry name='admins'><members><member>alice</member></members></entry></local-user-group>
      <group-mapping><entry name='ldap'><server-profile>ldap-main</server-profile></entry></group-mapping>
      <admin-role><entry name='operator'/></admin-role>
      <network><sdwan><interface-profile><entry name='wan'/></interface-profile><rules><entry name='prefer'/></rules></sdwan></network>
    </shared></config>"""
    reporter = PaloAltoSourceReporter()
    analysis = reporter.analyze_source(source)
    preview = reporter.build_preview(analysis)

    objects = preview["summary"]["objects"]
    assert analysis.derived.counts["local-user"] == 1
    assert analysis.derived.counts["local-user-group"] == 1
    assert analysis.derived.counts["group-mapping"] == 1
    assert objects["local_users"] == 1
    assert objects["local_user_groups"] == 1
    assert objects["group_mappings"] == 1
    assert objects["admin_roles"] == 1
    assert objects["sdwan_interface_profiles"] == 1
    assert preview["summary"]["local_users"] == 1
    assert {"local_users", "local_user_groups", "group_mappings"} <= set(preview["sections"])
    assert preview["sections"]["local_users"][0]["password_configured"] is True
    assert "do-not-export" not in str(preview)
