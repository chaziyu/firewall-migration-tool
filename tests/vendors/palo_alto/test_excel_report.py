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
    expected = {"DHCP Servers", "DHCP IP Pools", "DHCP Reservations", "DHCP Options", "SD-WAN Interface Profiles", "SD-WAN Interface Bindings", "SD-WAN Path Quality", "SD-WAN Traffic Distribution", "SD-WAN Traffic Distribution Links", "SD-WAN SaaS Quality", "SD-WAN Error Correction", "SD-WAN Rules", "Local Users", "Local User Groups", "Group Mappings", "GlobalProtect Portals", "GP Portal Client Configs", "GP Portal Gateway Entries", "GP Clientless VPN", "GlobalProtect Gateways", "GP Gateway Client Auth", "GP Remote User Tunnels"}
    assert expected <= set(workbook.sheetnames)
    assert "Route Path Monitors" not in workbook.sheetnames
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


def test_excel_validation_sheet_contains_validation_issue():
    source = "<config><shared><address><entry name='bad'><ip-netmask>999.999.999.999</ip-netmask></entry></address></shared></config>"
    output = io.BytesIO()
    reporter = PaloAltoSourceReporter()
    reporter.export_excel(reporter.analyze_source(source), output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True, data_only=True)
    rows = list(workbook["Validation"].iter_rows(min_row=4, values_only=True))
    assert any("malformed ip_netmask" in str(row) for row in rows)
