import io
from pathlib import Path

from openpyxl import load_workbook

from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.vendors.palo_alto.export.excel_schema import SHEET_HEADERS


def test_excel_report_contains_native_domain_sheets():
    source = (Path(__file__).parents[2] / "fixtures" / "example_palo_alto.xml").read_text()
    output = io.BytesIO()
    reporter = PaloAltoSourceReporter()
    reporter.export_excel(reporter.analyze_source(source), output)
    sheetnames = set(load_workbook(io.BytesIO(output.getvalue()), read_only=True).sheetnames)
    assert {"Summary", "Review Required", "Validation", "Interfaces", "Security Policies"}.issubset(sheetnames)


def test_excel_report_activates_typed_dhcp_sdwan_identity_and_globalprotect_sheets():
    source = """<config><shared>
      <network><dhcp><entry name='dhcp-main'><interface>ethernet1/1</interface><mode>auto</mode><ip-pool><entry name='pool-1'><start-ip>192.0.2.10</start-ip><end-ip>192.0.2.20</end-ip><future-field>retain-pool</future-field></entry></ip-pool><reservations><entry name='printer'><ip-address>192.0.2.30</ip-address><mac-address>00:11:22:33:44:55</mac-address></entry></reservations><options><entry name='dns'><code>6</code><ip-values><member>192.0.2.2</member></ip-values></entry></options></entry></dhcp>
      <sdwan><interface-profile><entry name='wan-primary'><link-tag>primary</link-tag></entry></interface-profile><path-quality-profile><entry name='quality'><latency-threshold>50</latency-threshold></entry></path-quality-profile><traffic-distribution-profile><entry name='balanced'><distribution-mode>weighted</distribution-mode><link><entry><link-tag>primary</link-tag><weight>80</weight></entry></link></entry></traffic-distribution-profile><saas-quality-profile><entry name='saas'><monitor-mode>active</monitor-mode></entry></saas-quality-profile><error-correction-profile><entry name='ec'><mode>fec</mode></entry></error-correction-profile><rules><entry name='prefer-primary'><from><member>trust</member></from></entry></rules></sdwan>
      <local-user><entry name='alice'><disabled>no</disabled><password>local-secret</password></entry></local-user><local-user-group><entry name='admins'><members><member>alice</member></members></entry></local-user-group><group-mapping><entry name='ldap-groups'><server-profile>ldap-main</server-profile><disabled>no</disabled><nested-group-level>2</nested-group-level></entry></group-mapping>
      <global-protect><portal><entry name='portal-main'><client-config><entry name='managed'><internal-host-detection><ip-address>10.0.0.10</ip-address></internal-host-detection><gateways><entry><gateway-type>external</gateway-type><gateway>gateway-main</gateway></entry></gateways><authentication-override><cookie-encrypt-decrypt><password>portal-secret</password></cookie-encrypt-decrypt></authentication-override></entry></client-config><clientless-vpn><hostname>vpn.example</hostname><security-zone>vpn</security-zone></clientless-vpn></entry></portal><gateway><entry name='gateway-main'><client-authentication><entry name='users'><operating-system>Windows</operating-system><authentication-profile>ldap</authentication-profile><password>gateway-secret</password></entry></client-authentication><remote-user-tunnel><entry name='tunnel'><ip-pools><member>pool-a</member></ip-pools></entry></remote-user-tunnel></entry></gateway></global-protect></network>
    </shared><devices><entry name='fw'><network><interface><ethernet><entry name='ethernet1/1'><layer3><sdwan-link-settings><enable>yes</enable><ipv6-enable>no</ipv6-enable><sdwan-interface-profile>wan-primary</sdwan-interface-profile><upstream-nat><enable>yes</enable></upstream-nat></sdwan-link-settings></layer3></entry></ethernet></interface></network></entry></devices></config>"""
    reporter = PaloAltoSourceReporter()
    output = io.BytesIO()
    reporter.export_excel(reporter.analyze_source(source), output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True)
    expected = {"DHCP Servers", "DHCP IP Pools", "DHCP Reservations", "DHCP Options", "SD-WAN Interface Profiles", "SD-WAN Interface Bindings", "SD-WAN Path Quality", "SD-WAN Traffic Distribution", "SD-WAN Distribution Links", "SD-WAN SaaS Quality", "SD-WAN Error Correction", "SD-WAN Rules", "Local Users", "Local User Groups", "Group Mappings", "GlobalProtect Portals", "GP Portal Client Configs", "GP Portal Gateway Entries", "GP Clientless VPN", "GlobalProtect Gateways", "GP Gateway Client Auth", "GP Remote User Tunnels"}
    assert expected <= set(workbook.sheetnames)
    assert "Route Path Monitors" in workbook.sheetnames
    for name in expected:
        assert tuple(workbook[name].iter_rows(min_row=3, max_row=3, values_only=True))[0] == SHEET_HEADERS[name]
        assert workbook[name].max_row > 3
    assert workbook["DHCP IP Pools"].cell(4, 1).value == "ethernet1/1"
    assert workbook["DHCP IP Pools"].cell(4, 2).value == "pool-1"
    assert workbook["GP Portal Gateway Entries"].cell(4, 1).value == "portal-main"
    assert workbook["GP Portal Gateway Entries"].cell(4, 2).value == "managed"
    assert workbook["GP Gateway Client Auth"].cell(4, 1).value == "gateway-main"
    assert workbook["GP Remote User Tunnels"].cell(4, 1).value == "gateway-main"
    assert workbook["DHCP IP Pools"].cell(4, 9).value == "future-field: retain-pool"
    values = " ".join(str(cell.value) for sheet in workbook.worksheets for row in sheet.iter_rows() for cell in row)
    assert all(secret not in values for secret in ("local-secret", "portal-secret", "gateway-secret"))


def test_declared_source_columns_and_path_monitor_sheet_are_populated():
    source = """<config><shared>
      <tag><entry name='tag-a'/></tag>
      <address><entry name='tagged'><ip-netmask>192.0.2.1</ip-netmask><tag><member>tag-a</member></tag></entry><entry name='translated'><ip-netmask>192.0.2.2</ip-netmask></entry></address>
      <service><entry name='svc'><protocol><tcp><override><no/></override></tcp></protocol></entry></service>
      <zone><entry name='inside'><network><zone-protection-profile>protect</zone-protection-profile><enable-packet-buffer-protection>yes</enable-packet-buffer-protection><net-inspection>yes</net-inspection><prenat-identification><enable-prenat-user-identification>yes</enable-prenat-user-identification></prenat-identification></network><user-acl><include-list><member>u1</member></include-list></user-acl></entry></zone>
      <rulebase><security><rules><entry name='allow'><source-hip><member>hip-a</member></source-hip><destination-hip><member>hip-b</member></destination-hip><group-tag>group-a</group-tag><icmp-unreachable>yes</icmp-unreachable><disable-inspect>yes</disable-inspect><profile-setting><profiles><virus><member>av-a</member></virus><url-filtering><member>url-a</member></url-filtering><data-filtering><member>df-a</member></data-filtering><file-blocking><member>fb-a</member></file-blocking><wildfire-analysis><member>wf-a</member></wildfire-analysis><spyware><member>as-a</member></spyware><vulnerability><member>vuln-a</member></vulnerability></profiles></profile-setting></entry></rules></security>
        <nat><rules><entry name='dnat'><destination-translation><translated-address>translated</translated-address><translated-port>443</translated-port><dns-rewrite><direction>reverse</direction></dns-rewrite></destination-translation></entry><entry name='dynamic'><dynamic-destination-translation><translated-address><member>translated</member></translated-address><translated-port>8443</translated-port><distribution><round-robin/></distribution></dynamic-destination-translation></entry></rules></nat></rulebase>
      <profiles><vulnerability><entry name='vuln'><rules><entry name='threat'><action><block-ip><track-by>source</track-by><duration>60</duration></block-ip></action></entry></rules><exceptions><entry name='exception'><action><block-ip><track-by>source-and-destination</track-by><duration>120</duration></block-ip></action></entry></exceptions></entry></vulnerability></profiles>
      <network><virtual-router><entry name='vr-main'><routing-table><ip><static-route><entry name='vr-route'><destination>0.0.0.0/0</destination><path-monitor><enable>yes</enable><failure-condition>any</failure-condition><hold-time>5</hold-time><monitor-destinations><entry name='probe-vr'><enable>yes</enable><source>192.0.2.1</source><destination>192.0.2.2</destination><interval>5</interval><count>3</count></entry></monitor-destinations></path-monitor></entry></static-route></ip></routing-table></entry></virtual-router>
        <logical-router><entry name='lr-main'><vrf><entry name='production'><routing-table><ip><static-route><entry name='lr-route'><destination>10.0.0.0/8</destination><path-monitor><monitor-destinations><entry name='probe-lr'><destination-fqdn>probe.example</destination-fqdn></entry></monitor-destinations></path-monitor></entry></static-route></ip></routing-table></entry></vrf></entry></logical-router></network>
    </shared></config>"""
    reporter = PaloAltoSourceReporter()
    analysis = reporter.analyze_source(source)
    output = io.BytesIO()
    reporter.export_excel(analysis, output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True, data_only=True)

    def rows(name):
        headers = next(workbook[name].iter_rows(min_row=3, max_row=3, values_only=True))
        return [dict(zip(headers, row)) for row in workbook[name].iter_rows(min_row=4, values_only=True)]

    policy = next(row for row in rows("Security Policies") if row["Name"] == "allow")
    assert (policy["Source HIP"], policy["Destination HIP"], policy["ICMP Unreachable"], policy["Disable Inspect"], policy["Group Tag"]) == ("hip-a", "hip-b", "yes", "yes", "group-a")
    assert (policy["Antivirus"], policy["Anti-Spyware"], policy["Vulnerability Profile"], policy["URL Filtering"], policy["Data Filtering"], policy["File Blocking"], policy["WildFire Analysis"]) == ("av-a", "as-a", "vuln-a", "url-a", "df-a", "fb-a", "wf-a")
    nat = {row["Name"]: row for row in rows("NAT Rules")}
    assert (nat["dnat"]["Destination Translation Type"], nat["dnat"]["Destination DNS Rewrite"], nat["dnat"]["DNS Rewrite Direction"]) == ("destination-translation", "yes", "reverse")
    assert "translated -> RESOLVED" in nat["dnat"]["Resolved Translation References"]
    assert "translated -> RESOLVED" in nat["dynamic"]["Resolved Translation References"]
    zone = next(row for row in rows("Zones") if row["Name"] == "inside")
    assert (zone["Zone Protection Profile"], zone["Packet Buffer Protection"], zone["Network Inspection"], zone["Pre-NAT User Identification"], zone["User ACL Include"]) == ("protect", "yes", "yes", "yes", "u1")
    rule = next(row for row in rows("Vulnerability Rules") if row["Rule Name"] == "threat")
    exception = next(row for row in rows("Vulnerability Exceptions") if row["Exception Name"] == "exception")
    assert (rule["Block IP Track By"], rule["Block IP Duration"]) == ("source", "60")
    assert (exception["Block IP Track By"], exception["Block IP Duration"]) == ("source-and-destination", "120")
    assert {(row["Router Type"], row["Router"], row["VRF"], row["Route Name"], row["Monitor Name"]) for row in rows("Route Path Monitors")} == {
        ("virtual-router", "vr-main", None, "vr-route", "probe-vr"), ("logical-router", "lr-main", "production", "lr-route", "probe-lr")
    }
    route = next(row for row in rows("Virtual Router Routes") if row["Route Name"] == "vr-route")
    assert (route["Path Monitor Enabled"], route["Path Monitor Failure Condition"], route["Path Monitor Hold Time"]) == ("yes", "any", "5")


def test_excel_validation_sheet_contains_validation_issue():
    source = "<config><shared><address><entry name='bad'><ip-netmask>999.999.999.999</ip-netmask></entry></address></shared></config>"
    output = io.BytesIO()
    reporter = PaloAltoSourceReporter()
    reporter.export_excel(reporter.analyze_source(source), output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True, data_only=True)
    rows = list(workbook["Validation"].iter_rows(min_row=4, values_only=True))
    assert any("malformed ip_netmask" in str(row) for row in rows)


def test_partial_extraction_status_and_source_appendix_evidence():
    source = """<config><shared><network><dhcp><interface><entry name='ethernet1/1'><mode>auto</mode><server><future-setting>retain-me</future-setting></server></entry></interface></dhcp>
      <service><entry name='web'><protocol><tcp><port>443</port><future-tcp-setting>retain-protocol-source</future-tcp-setting></tcp></protocol></entry></service>
      <sdwan><traffic-distribution-profile><entry name='malformed'><link><entry><weight><member>not-a-scalar</member></weight></entry></link></entry></traffic-distribution-profile></sdwan>
    </network></shared></config>"""
    reporter = PaloAltoSourceReporter()
    analysis = reporter.analyze_source(source)
    output = io.BytesIO()
    reporter.export_excel(analysis, output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True, data_only=True)
    inventory = list(workbook["PAN-OS Source Inventory"].iter_rows(min_row=4, values_only=True))
    dhcp = next(row for row in inventory if row[7] == "ethernet1/1")
    assert dhcp[-1] == "PARTIAL"
    coverage = list(workbook["Extraction Coverage"].iter_rows(min_row=4, values_only=True))
    assert next(row for row in coverage if row[0] == "dhcp_interface")[4] == "PARTIAL"
    appendix = list(workbook["PAN-OS Source Appendix"].iter_rows(min_row=4, values_only=True))
    assert any(row[7].endswith("server/future-setting") and row[9] == "retain-me" for row in appendix)
    assert any(row[7].endswith("protocol/tcp/future-tcp-setting") and row[9] == "retain-protocol-source" for row in appendix)
    assert "Services" in workbook.sheetnames and workbook["Services"].max_row > 3
    validation = list(workbook["Validation"].iter_rows(min_row=4, values_only=True))
    assert any(row[0] == "warning" and row[1] == "extraction" and "ValidationError" in str(row) for row in validation)
    unsupported = list(workbook["Unsupported"].iter_rows(min_row=4, values_only=True))
    assert any("not-a-scalar" in str(row) for row in unsupported)
