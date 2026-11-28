"""Flask API tests for Phase 4 FortiGate SSL-VPN -> Dial-up IPSec Assistant."""

from __future__ import annotations

from fwmigrate.web import create_app

_FG_SSL_CONF = """#config-version=FGT60F-7.4.9-FW-build2829-250101:opmode=0:vdom=0:user=admin
config vpn ssl web portal
    edit "full-access"
        set tunnel-mode enable
        set ip-pools "SSLVPN_ADDR"
    next
end
config vpn ssl settings
    set servercert "Fortinet_Factory"
    set source-interface "wan1"
    set tunnel-ip-pools "SSLVPN_ADDR"
    set dns-server1 10.10.0.53
end
config firewall policy
    edit 5
        set name "SSL_Access"
        set srcintf "ssl.root"
        set dstintf "internal"
        set action accept
        set srcaddr "SSLVPN_ADDR"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
    next
end
"""

_PA_XML = """<config version="11.1.0">
  <devices><entry name="fw"><vsys><entry name="vsys1"/></vsys></entry></devices>
</config>"""


def test_ssl_to_ipsec_endpoint_fortigate_and_validation():
    client = create_app({"TESTING": True, "WEB_MODE": "public"}).test_client()

    resp = client.post(
        "/api/source/ssl-to-ipsec",
        json={
            "source_vendor": "fortigate",
            "source": {"vendor": "fortigate", "source_text": _FG_SSL_CONF, "source_name": "fg.conf"},
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["has_ssl_vpn"] is True
    assert data["vdom"] == "root"
    assert data["primary_pool"] == "SSLVPN_ADDR"
    assert len(data["ssl_policies"]) == 1
    assert "config vpn ipsec phase1-interface" in data["cli_draft"]
    assert len(data["gui_rows"]) > 0
    assert len(data["forticlient_rows"]) > 0
    assert len(data["cutover_rows"]) == 5

    pa_resp = client.post(
        "/api/source/ssl-to-ipsec",
        json={
            "source_vendor": "palo_alto",
            "source": {"vendor": "palo_alto", "source_text": _PA_XML, "source_name": "pa.xml"},
        },
    )
    assert pa_resp.status_code == 400
    assert pa_resp.get_json()["success"] is False

    bad_resp = client.post("/api/source/ssl-to-ipsec", data="not json", content_type="application/json")
    assert bad_resp.status_code == 400
    assert bad_resp.get_json()["success"] is False
