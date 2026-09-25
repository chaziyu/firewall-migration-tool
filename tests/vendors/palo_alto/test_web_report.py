from pathlib import Path

from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter


def test_web_report_has_expected_sections():
    source = (Path(__file__).parents[2] / "fixtures" / "example_palo_alto.xml").read_text()
    preview = PaloAltoSourceReporter().build_preview(PaloAltoSourceReporter().analyze_source(source))
    sections = preview["sections"]
    assert {"interfaces", "policies", "nat", "validation"}.issubset(sections)
    assert preview["vendor"] == "palo_alto"
    assert isinstance(preview["summary"]["objects"], dict)
    assert isinstance(preview["summary"]["validation"], dict)
    assert isinstance(preview["summary"]["scopes"], list)
    assert preview["summary"]["scopes"] == preview["summary"]["vdoms"]
    assert preview["summary"]["scope_count"] >= len(preview["summary"]["scopes"])


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


def test_same_named_scoped_policies_keep_review_reasons_in_their_scope():
    source = """<config><devices><entry name='panorama'><device-group>
      <entry name='dg-a'><pre-rulebase><security><rules><entry name='Allow-Web'><from><member>any</member></from><to><member>any</member></to><source><member>missing-a</member></source><destination><member>any</member></destination><action>allow</action></entry></rules></security></pre-rulebase></entry>
      <entry name='dg-b'><pre-rulebase><security><rules><entry name='Allow-Web'><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source><destination><member>any</member></destination><action>allow</action></entry></rules></security></pre-rulebase></entry>
    </device-group></entry></devices></config>"""
    reporter = PaloAltoSourceReporter()
    preview = reporter.build_preview(reporter.analyze_source(source))
    rows = preview["sections"]["policies"]
    assert len(rows) == 2
    assert rows[0]["name"] == rows[1]["name"] == "Allow-Web"
    assert rows[0]["review"]
    assert rows[1]["review"] == []


def test_preview_includes_logical_router_routes_with_ownership():
    source = """<config><shared><network>
      <virtual-router><entry name='vr'><routing-table><ip><static-route><entry name='vr-route'><destination>0.0.0.0/0</destination></entry></static-route></ip></routing-table></entry></virtual-router>
      <logical-router><entry name='lr'><vrf><entry name='production'><routing-table><ip><static-route><entry name='lr-route'><destination>10.0.0.0/8</destination></entry></static-route></ip></routing-table></entry></vrf></entry></logical-router>
    </network></shared></config>"""
    reporter = PaloAltoSourceReporter()
    preview = reporter.build_preview(reporter.analyze_source(source))
    routes = preview["sections"]["routes"]
    assert {(row["route_id"], row["router_type"], row["router"], row["vrf"]) for row in routes} == {
        ("vr-route", "virtual-router", "vr", None), ("lr-route", "logical-router", "lr", "production")
    }
    assert preview["summary"]["objects"]["routes"] == preview["summary"]["routes"] == 2


def test_preview_serializes_interface_topology_rows():
    source = """<config><devices><entry name='fw'><network><interface>
      <ethernet><entry name='ethernet1/1'><layer3><aggregate-group>ae1</aggregate-group></layer3></entry></ethernet>
      <aggregate-ethernet><entry name='ae1'><layer3/></entry></aggregate-ethernet>
    </interface></network></entry></devices></config>"""
    preview = PaloAltoSourceReporter().build_preview(PaloAltoSourceReporter().analyze_source(source))
    rows = preview["sections"]["interface_topology"]
    assert any(row["name"] == "ethernet1/1" and row["aggregate"] == "ae1" for row in rows)
