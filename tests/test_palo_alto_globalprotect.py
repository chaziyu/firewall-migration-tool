import io
import json

from openpyxl import load_workbook

from fwmigrate.ir.migrations import migrate_ir_payload
from fwmigrate.ir.version import IR_SCHEMA_VERSION
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser
from fwmigrate.report.excel_exporter import IRExcelExporter


def _xml(global_protect: str = "", network_gateway: str = "") -> str:
    return f"""<config>
      <shared>
        <certificate><entry name="GP_Cert"><ca>yes</ca></entry></certificate>
        <ssl-tls-service-profile><entry name="GP_SSL_TLS_Profile"><certificate>GP_Cert</certificate></entry></ssl-tls-service-profile>
      </shared>
      <devices><entry name="fw1"><network>
        <interface><loopback><units><entry name="loopback.78"/></units></loopback><tunnel><units><entry name="tunnel.78"/></units></tunnel></interface>
        <tunnel>{network_gateway}</tunnel>
      </network></entry></devices>
      <vsys><entry name="vsys1"><address>
        <entry name="211.25.233.78_SSLVPN"><ip-netmask>211.25.233.78</ip-netmask></entry>
        <entry name="P-LAN_10.0.0.0"><ip-netmask>10.0.0.0/8</ip-netmask></entry>
      </address><authentication-profile>
        <entry name="GPVPN Profile"><method><local-database/></method></entry>
      </authentication-profile><global-protect>{global_protect}</global-protect></entry></vsys>
    </config>"""


def _portal_and_gateway() -> str:
    auth = """<client-auth><entry name="ldap"><os>Windows</os><authentication-profile>GPVPN Profile</authentication-profile><authentication-message>Sign in</authentication-message><username-label>User</username-label><password-label>Password</password-label></entry></client-auth>"""
    return f"""
      <global-protect-portal><entry name="GPVPN_Portal"><agent-user-override-key>PORTAL_SECRET_MARKER</agent-user-override-key><portal-config>
        <local-address><interface>loopback.78</interface><ip><ipv4>211.25.233.78_SSLVPN</ipv4></ip></local-address>
        <ssl-tls-service-profile>GP_SSL_TLS_Profile</ssl-tls-service-profile>{auth}
        <client-config><entry name="default"><source-user><member>any</member></source-user><os><member>any</member></os>
          <external-gateway-priority-cutoff-time>60</external-gateway-priority-cutoff-time>
          <external-gateway><entry name="External_Gateway"><ipv4>211.25.233.78</ipv4><manual>no</manual><priority-rule><entry name="p1"><priority>1</priority></entry></priority-rule></entry></external-gateway>
          <gp-app-config><entry name="first"><member>a</member><member>b</member></entry><entry name="second"/></gp-app-config>
          <authentication-override><generate-cookie>yes</generate-cookie></authentication-override><save-user-credentials>1</save-user-credentials>
        </entry></client-config><root-ca><entry name="root"><certificate>GP_Cert</certificate><install-in-cert-store>yes</install-in-cert-store></entry></root-ca>
      </portal-config></entry></global-protect-portal>
      <global-protect-gateway><entry name="GP_Gateway"><gateway-config><ssl-tls-service-profile>GP_SSL_TLS_Profile</ssl-tls-service-profile><tunnel-mode>yes</tunnel-mode><remote-user-tunnel>tunnel.78</remote-user-tunnel>{auth}
        <roles><entry name="default"><login-lifetime>30</login-lifetime><inactivity-logout>3</inactivity-logout><disconnect-on-idle>180</disconnect-on-idle></entry></roles>
        <remote-user-tunnel-config><entry name="GP_Test"><source-user><member>any</member></source-user><os><member>any</member></os><ip-pool><member>10.3.38.20-10.3.38.250</member></ip-pool><split-tunnel><access-route><member>P-LAN_10.0.0.0</member></access-route></split-tunnel><retrieve-framed-ip-address>no</retrieve-framed-ip-address><no-direct-access-to-local-network>no</no-direct-access-to-local-network></entry></remote-user-tunnel-config>
      </gateway-config></entry></global-protect-gateway>
    """


def test_globalprotect_extracts_separate_portal_gateway_and_dependencies():
    result = PANOSSourceParser().extract(_xml(_portal_and_gateway()))
    ir = result.canonical_ir
    assert ir.global_protect_portals[0].name == "GPVPN_Portal"
    assert ir.global_protect_portals[0].local_address_resolved is True
    assert ir.global_protect_portals[0].local_ipv4 == "211.25.233.78_SSLVPN"
    assert ir.global_protect_portals[0].resolved_local_address == "211.25.233.78_SSLVPN"
    assert ir.global_protect_portals[0].client_authentication[0].authentication_profile_resolved is True
    assert ir.global_protect_portals[0].client_authentication[0].password_label == "Password"
    assert ir.global_protect_portals[0].ssl_tls_service_profile_resolved is True
    assert ir.global_protect_portals[0].root_ca_certificates[0].certificate_resolved is True
    assert ir.global_protect_gateways[0].tunnel_mode is True
    assert ir.global_protect_gateways[0].remote_user_tunnel_resolved is True
    tunnel = ir.global_protect_gateways[0].remote_user_tunnel_configs[0]
    assert tunnel.ip_pools == ["10.3.38.20-10.3.38.250"]
    assert tunnel.resolved_split_include_routes == ["P-LAN_10.0.0.0"]
    assert ir.global_protect_portals[0].has_agent_user_override_key is True
    assert "PORTAL_SECRET_MARKER" not in json.dumps(ir.model_dump(), default=str)


def test_globalprotect_network_gateway_is_not_vsys_gateway_and_redacts_password():
    network = """<global-protect-gateway><entry name="GP_Gateway-N"><local-address><interface>loopback.78</interface></local-address><tunnel-interface>tunnel.78</tunnel-interface><client-dns><primary>10.1.4.2</primary><secondary>10.1.4.1</secondary><dns-suffix><member>prasarana.com.my</member></dns-suffix><dns-suffix-inherited>no</dns-suffix-inherited></client-dns><third-party-client><enable>yes</enable><group-name>SubangVPN</group-name><group-password>NETWORK_SECRET_MARKER</group-password></third-party-client></entry></global-protect-gateway>"""
    result = PANOSSourceParser().extract(_xml(_portal_and_gateway(), network))
    ir = result.canonical_ir
    assert [item.name for item in ir.global_protect_gateways] == ["GP_Gateway"]
    network_gateway = ir.global_protect_network_gateways[0]
    assert network_gateway.name == "GP_Gateway-N"
    assert network_gateway.local_interface_resolved is True
    assert network_gateway.tunnel_interface_resolved is True
    assert network_gateway.client_dns_primary == "10.1.4.2"
    assert network_gateway.third_party_group_password_configured is True
    assert "NETWORK_SECRET_MARKER" not in result.model_dump_json()


def test_globalprotect_strict_booleans_and_unresolved_references_require_review():
    xml = _xml("""<global-protect-portal><entry name="p"><portal-config><local-address><interface>missing</interface><ip><ipv4>missing-address</ipv4></ip></local-address><client-config><entry name="c"><external-gateway><entry name="g"><manual>maybe</manual></entry></external-gateway></entry></client-config></portal-config></entry></global-protect-portal>""")
    result = PANOSSourceParser().extract(xml)
    portal = result.canonical_ir.global_protect_portals[0]
    assert portal.local_interface_resolved is False
    assert portal.local_address_resolved is False
    assert portal.requires_manual_review is True
    assert any("unresolved" in reason for reason in portal.review_reasons)


def test_globalprotect_excel_and_schema_migration():
    result = PANOSSourceParser().extract(_xml(_portal_and_gateway()))
    workbook = load_workbook(io.BytesIO(IRExcelExporter(result.canonical_ir, result).generate()))
    assert "GlobalProtect Portals" in workbook.sheetnames
    assert "GlobalProtect Gateways" in workbook.sheetnames
    assert "GlobalProtect Network Gateways" in workbook.sheetnames
    assert workbook["GlobalProtect App Settings"].max_row == 5
    assert "Group Password" not in [cell.value for cell in workbook["GlobalProtect Network Gateways"][3]]
    migrated = migrate_ir_payload({"schema_version": "1.45", "metadata": {"source_vendor": "palo_alto"}})
    assert migrated["schema_version"] == IR_SCHEMA_VERSION
    assert migrated["global_protect_portals"] == []


def test_globalprotect_scopes_do_not_deduplicate_and_unknown_site_to_site_is_visible():
    result = PANOSSourceParser().extract("""<config><vsys>
      <entry name="vsys1"><global-protect><global-protect-portal><entry name="same"><portal-config/></entry></global-protect-portal></global-protect></entry>
      <entry name="vsys2"><global-protect><global-protect-portal><entry name="same"><portal-config/></entry></global-protect-portal><global-protect-site-to-site><entry name="future"><peer>configured</peer></entry></global-protect-site-to-site></global-protect></entry>
    </vsys></config>""")
    assert [portal.source_context for portal in result.canonical_ir.global_protect_portals] == ["vsys:vsys1", "vsys:vsys2"]
    assert any(item.status == ExtractionStatus.UNSUPPORTED and item.name == "future" for item in result.inventory_items)
