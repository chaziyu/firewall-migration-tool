from pathlib import Path

from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.source_reporting.web_report import normalize_web_report


def test_reference_findings_keep_exact_owner_identity_in_normalized_preview():
    source = """<config><shared><profile-group><entry name='same'><vulnerability><member>missing-profile</member></vulnerability></entry></profile-group>
      <pre-rulebase><security><rules><entry name='same'><source><member>missing-address</member></source></entry></rules></security></pre-rulebase>
      <post-rulebase><security><rules><entry name='same'><source><member>any</member></source></entry></rules></security></post-rulebase>
    </shared></config>"""
    reporter = PaloAltoSourceReporter()
    preview = normalize_web_report(reporter.build_preview(reporter.analyze_source(source)), "palo_alto")
    sections = preview["sections"]
    assert len(sections["unresolved_references"]) == 2
    assert all(isinstance(item, str) for item in sections["unresolved_references"])
    targets = {"policy": sections["policies"], "security-profile-group": sections["security_profile_groups"]}
    for finding in sections["validation"]:
        matches = [row for row in targets[finding["object_type"]]
                   if row["source_identity"] == finding["source_identity"]]
        assert len(matches) == 1
        assert matches[0]["source_path"] == finding["source_path"]
        if finding["object_type"] == "policy":
            assert matches[0]["rulebase_position"] == "pre"


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
    assert isinstance(preview["summary"]["scope_identities"], list)
    assert len(preview["summary"]["scope_identities"]) == preview["summary"]["scope_count"]
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
    assert rows[0]["scope_type"] == rows[1]["scope_type"] == "device-group"
    assert rows[0]["scope_name"] == "dg-a"
    assert rows[0]["rulebase_position"] == "pre"
    assert "vdom" not in rows[0] and "nat" not in rows[0]


def test_preview_reports_shared_scope_and_keeps_security_and_nat_separate():
    source = """<config><shared>
      <rulebase><security><rules><entry name='allow-web'><action>allow</action></entry></rules></security>
        <nat><rules><entry name='snat'><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface></interface-address></dynamic-ip-and-port></source-translation></entry></rules></nat>
      </rulebase>
    </shared></config>"""
    preview = PaloAltoSourceReporter().build_preview(PaloAltoSourceReporter().analyze_source(source))
    policy = preview["sections"]["policies"][0]
    nat = preview["sections"]["nat"][0]
    assert (policy["scope_type"], policy["scope_name"], policy["rulebase_position"]) == ("shared", "shared", "local")
    assert (nat["scope_type"], nat["scope_name"], nat["rulebase_position"]) == ("shared", "shared", "local")
    assert "nat" not in policy


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


def test_preview_preserves_interface_address_snat_semantics():
    source = """<config><shared><rulebase><nat><rules><entry name='snat'>
      <from><member>trust</member></from><to><member>untrust</member></to>
      <source><member>any</member></source><destination><member>any</member></destination>
      <source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface><ip>192.0.2.10/32</ip></interface-address></dynamic-ip-and-port></source-translation>
    </entry></rules></nat></rulebase></shared></config>"""
    preview = PaloAltoSourceReporter().build_preview(PaloAltoSourceReporter().analyze_source(source))
    row = preview["sections"]["nat"][0]
    assert row["translation_type"] == "dynamic-ip-and-port"
    assert row["translated_addresses"] == []
    assert row["source_translation_interface"] == "ethernet1/1"
    assert row["source_translation_ip"] == "192.0.2.10/32"


def test_preview_reports_source_inventory_truncation_explicitly():
    entries = "".join(
        f"<entry name='a-{index}'><ip-netmask>192.0.2.{index % 254 + 1}/32</ip-netmask></entry>"
        for index in range(205)
    )
    source = f"<config><shared><address>{entries}</address></shared></config>"
    reporter = PaloAltoSourceReporter()
    preview = reporter.build_preview(reporter.analyze_source(source))

    assert preview["summary"]["records"] == 205
    assert preview["records_total"] == 205
    assert preview["records_returned"] == 200
    assert preview["records_truncated"] is True
    assert len(preview["records"]) == 200
    assert len(preview["sections"]["source_inventory"]) == 205
    assert preview["sections"]["source_inventory"][-1]["name"] == "a-204"


def test_vulnerability_preview_preserves_count_fields_and_adds_serializable_details():
    import json

    source = """<config><shared><profiles><vulnerability><entry name="ips"><rules>
      <entry name="rule1"><severity><member>critical</member></severity></entry>
      </rules></entry></vulnerability></profiles></shared></config>"""
    reporter = PaloAltoSourceReporter()
    preview = reporter.build_preview(reporter.analyze_source(source))
    row = preview["sections"]["vulnerability_profiles"][0]
    assert row["rules"] == 1 and row["exceptions"] == 0
    assert row["rule_details"][0]["name"] == "rule1"
    assert row["exception_details"] == []
    json.dumps(preview)


def test_extended_panos_sections_and_omitted_models_reach_preview_safely():
    source = """<config version="11.1.0">
      <shared>
        <application-group><entry name="web-apps"><members><member>ssl</member><member>web-browsing</member></members></entry></application-group>
        <dynamic-user-group><entry name="risky-users"><filter>'high-risk'</filter></entry></dynamic-user-group>
        <external-list><entry name="bad-ips"><type><ip><url>https://edl.example.test/list.txt</url><auth><username>edl-user</username><password>PAN_SECRET_EDL</password></auth></ip></type></entry></external-list>
        <custom-url-category><entry name="blocked-urls"><type>URL List</type><list><member>bad.example.test</member></list></entry></custom-url-category>
        <profiles>
          <virus><entry name="strict-av"><packet-capture>yes</packet-capture></entry></virus>
          <spyware><entry name="strict-as"><cloud-inline-analysis>yes</cloud-inline-analysis></entry></spyware>
          <url-filtering><entry name="corp-url"><block><member>malware</member></block></entry></url-filtering>
          <file-blocking><entry name="corp-fb"><description>block exe</description></entry></file-blocking>
          <wildfire-analysis><entry name="corp-wf"><description>wf</description></entry></wildfire-analysis>
          <data-filtering><entry name="corp-df"><data-capture>yes</data-capture></entry></data-filtering>
          <dos-protection><entry name="corp-dos"><type>classified</type></entry></dos-protection>
          <decryption><entry name="corp-decrypt"><ssl-forward-proxy><block-expired-certificate>yes</block-expired-certificate></ssl-forward-proxy></entry></decryption>
        </profiles>
        <server-profile>
          <radius><entry name="rad-1"><timeout>5</timeout><server><entry name="r1"><ip-address>10.0.0.20</ip-address><secret>PAN_SECRET_RADIUS</secret></entry></server></entry></radius>
          <ldap><entry name="ldap-1"><ldap-type>active-directory</ldap-type><bind-password>PAN_SECRET_LDAP</bind-password></entry></ldap>
        </server-profile>
        <certificate><entry name="web-cert"><common-name>fw.example.test</common-name><private-key>PAN_SECRET_PRIVKEY</private-key></entry></certificate>
        <authentication-profile><entry name="auth-ldap"><user-domain>CORP</user-domain></entry></authentication-profile>
      </shared>
      <devices><entry name="fw1">
        <deviceconfig>
          <system><hostname>fw1</hostname><ip-address>10.0.0.1</ip-address><timezone>UTC</timezone></system>
          <high-availability><enabled>yes</enabled><group><group-id>5</group-id></group></high-availability>
        </deviceconfig>
        <network>
          <profiles><interface-management-profile><entry name="mgmt-https"><https>yes</https><ping>yes</ping></entry></interface-management-profile></profiles>
          <vlan><entry name="vlan-100"><virtual-interface><interface>vlan.100</interface></virtual-interface></entry></vlan>
          <virtual-wire><entry name="vw-1"><interface1>ethernet1/1</interface1><interface2>ethernet1/2</interface2></entry></virtual-wire>
          <virtual-router><entry name="vr-default"><ecmp><enable>yes</enable></ecmp></entry></virtual-router>
        </network>
        <vsys><entry name="vsys1">
          <import><network><interface><member>ethernet1/1</member></interface></network></import>
          <rulebase>
            <pbf><rules><entry name="pbf-1"><from><zone><member>trust</member></zone></from><action><forward><egress-interface>ethernet1/2</egress-interface></forward></action></entry></rules></pbf>
            <decryption><rules><entry name="dec-1"><action>decrypt</action><profile>corp-decrypt</profile></entry></rules></decryption>
            <qos><rules><entry name="qos-1"><class>4</class></entry></rules></qos>
          </rulebase>
        </entry></vsys>
      </entry></devices>
    </config>"""
    reporter = PaloAltoSourceReporter()
    preview = reporter.build_preview(reporter.analyze_source(source))
    sections = preview["sections"]
    assert sections["management_profiles"][0]["name"] == "mgmt-https"
    assert sections["interface_imports"][0]["interfaces"] == ["ethernet1/1"]
    assert sections["virtual_routers"][0]["ecmp"]["enable"] == "yes"
    assert sections["system_settings"][0]["timezone"] == "UTC"
    assert sections["ha_configs"][0]["enabled"] == "yes"
    assert sections["pbf_rules"][0]["egress_interface"] == "ethernet1/2"
    assert sections["decryption_rules"][0]["profile"] == "corp-decrypt"
    assert sections["qos_rules"][0]["qos_class"] == "4"
    assert sections["application_groups"][0]["members"] == ["ssl", "web-browsing"]
    assert sections["external_lists"][0]["password_configured"] is True
    assert sections["radius_server_profiles"][0]["secret_configured"] is True
    assert sections["ldap_server_profiles"][0]["bind_password_configured"] is True
    assert sections["certificates"][0]["private_key_configured"] is True
    assert sections["vlans"][0]["virtual_interface"] == "vlan.100"
    assert sections["virtual_wires"][0]["interface1"] == "ethernet1/1"
    import json
    assert "PAN_SECRET_" not in json.dumps(preview)


def test_panos_dhcp_relay_device_objects_scp_ssh_references_and_excel():
    import io
    import json
    from openpyxl import load_workbook
    from fwmigrate.vendors.palo_alto.export.excel import export_panos_excel

    source = """<config>
      <shared>
        <devices><entry name="managed-dev"><source>mac</source><description>Printer</description></entry></devices>
        <profiles>
          <decryption><entry name="dec-prof"/></decryption>
        </profiles>
        <certificate><entry name="srv-cert"><common-name>fw.test</common-name></entry></certificate>
        <ssl-tls-service-profile><entry name="tls-ok"><certificate>srv-cert</certificate></entry><entry name="tls-miss"><certificate>no-such-cert</certificate></entry></ssl-tls-service-profile>
        <server-profile>
          <scp><entry name="scp-1"><hostname>10.0.0.50</hostname><username>scpuser</username><password>PAN_SECRET_SCP</password></entry></scp>
          <ssh><entry name="ssh-1"><hostname>10.0.0.51</hostname><username>sshuser</username><password>PAN_SECRET_SSH</password></entry></ssh>
        </server-profile>
        <log-settings><system><match-list><entry name="sys-all"/></match-list></system></log-settings>
      </shared>
      <devices><entry name="fw1">
        <deviceconfig><setting><alarm><enable>yes</enable></alarm></setting></deviceconfig>
        <network><dhcp><interface><entry name="ethernet1/1"><relay><ip><member>10.0.0.254</member></ip></relay></entry></interface></dhcp></network>
        <vsys><entry name="vsys1">
          <user-identification><enable>yes</enable></user-identification>
          <rulebase><decryption><rules><entry name="dec-rule"><action>decrypt</action><profile>missing-dec</profile></entry></rules></decryption></rulebase>
        </entry></vsys>
      </entry></devices>
    </config>"""
    reporter = PaloAltoSourceReporter()
    analysis = reporter.analyze_source(source)
    preview = reporter.build_preview(analysis)
    sections = preview["sections"]

    assert sections["device_objects"][0]["name"] == "managed-dev"
    assert sections["scp_server_profiles"][0]["password_configured"] is True
    assert sections["ssh_server_profiles"][0]["password_configured"] is True
    assert sections["user_id_settings"][0]["setting_type"] == "user-identification"
    assert sections["log_setting_categories"][0]["category"] == "system"
    assert sections["device_setup_settings"][0]["alarm"]["enable"] == "yes"
    assert sections["dhcp_servers"][0]["relay"]["ip"]["member"] == "10.0.0.254"
    assert "PAN_SECRET_" not in json.dumps(preview)

    unresolved = {(r["owner_family"], r["reference_name"], r["status"]) for r in preview["unresolved_references"]}
    assert ("decryption-rule", "missing-dec", "UNRESOLVED") in unresolved
    assert ("ssl-tls-service-profile", "no-such-cert", "UNRESOLVED") in unresolved

    buf = io.BytesIO()
    export_panos_excel(analysis, buf, source_name="test.xml")
    buf.seek(0)
    wb = load_workbook(buf, read_only=True)
    for sheet_name in ("Device Objects", "SCP Server Profiles", "SSH Server Profiles", "Decryption Rules", "Log Setting Categories"):
        assert sheet_name in wb.sheetnames
    wb.close()
