"""Tests for Phase 2 Security Audit, Certificate Inspector, Exposure Probe, Posture, Hygiene, and HTML Report."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from fwmigrate.source_reporting.certificates import parse_pem_certificate
from fwmigrate.source_reporting.exposure import is_public_ip, probe_exposure_targets
from fwmigrate.vendors.fortigate.derived import build_derived_views as build_fg_derived
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.fortigate.security_audit import build_fortigate_security_audit
from fwmigrate.vendors.palo_alto.native import build_derived_views as build_pa_derived
from fwmigrate.vendors.palo_alto.security_audit import build_paloalto_security_audit
from fwmigrate.vendors.palo_alto.source_builder import build_panos_config
from fwmigrate.web import create_app

_NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
_TEST_KEY = ec.generate_private_key(ec.SECP256R1())


def _make_self_signed_pem(cn: str, not_before: datetime, not_after: datetime) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_TEST_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn), x509.IPAddress(ipaddress.IPv4Address("1.1.1.2"))]),
            critical=False,
        )
        .sign(_TEST_KEY, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii").strip()


_EXPIRED_PEM = _make_self_signed_pem("expired.example.test", _NOW - timedelta(days=400), _NOW - timedelta(days=5))
_SOON_PEM = _make_self_signed_pem("soon.example.test", _NOW - timedelta(days=60), _NOW + timedelta(days=10))
_VALID_PEM = _make_self_signed_pem("valid.example.test", _NOW - timedelta(days=10), _NOW + timedelta(days=180))

_FG_AUDIT_SAMPLE = f"""#config-version=FGT60F-7.4.4-FW-build2662-240501:opmode=0:vdom=0:user=admin
config system global
    set hostname "<script>alert('xss')</script>"
end
config system interface
    edit "wan1"
        set vdom "root"
        set ip 1.1.1.2 255.255.255.0
        set allowaccess https ssh
    next
    edit "wan2"
        set vdom "root"
        set role wan
        set ip 192.168.100.2 255.255.255.0
        set allowaccess https
    next
    edit "lan"
        set vdom "root"
        set ip 10.10.0.1 255.255.255.0
    next
end
config firewall address
    edit "UNUSED_NET"
        set subnet 10.99.0.0 255.255.255.0
    next
end
config firewall vip
    edit "RDP_VIP"
        set extip 1.1.1.20
        set extintf "wan1"
        set mappedip "10.10.0.5"
        set portforward enable
        set extport 3389
        set mappedport 3389
    next
end
config firewall policy
    edit 1
        set name "ALLOW_ANY"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
        set action accept
        set logtraffic disable
    next
    edit 2
        set name "ALLOW_RDP_VIP"
        set srcintf "wan1"
        set dstintf "lan"
        set srcaddr "all"
        set dstaddr "RDP_VIP"
        set service "ALL"
        set schedule "always"
        set action accept
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 1.1.1.1
        set device "wan1"
    next
end
config vpn ipsec phase1-interface
    edit "vpn-legacy"
        set interface "wan1"
        set ike-version 1
        set proposal 3des-md5
        set dhgrp 2
        set remote-gw 9.9.9.5
        set psksecret ENC SECRET_PSK
    next
end
config vpn certificate local
    edit "gw-expired"
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
SUPER-SECRET-KEY-NEVER-EXPOSED
-----END ENCRYPTED PRIVATE KEY-----"
        set certificate "{_EXPIRED_PEM}"
    next
    edit "gw-soon"
        set certificate "{_SOON_PEM}"
    next
end
config log disk setting
    set status enable
end
"""

_PA_AUDIT_SAMPLE = f"""<config version="11.1.0">
  <shared>
    <certificate>
      <entry name="pa-valid"><public-key>{_VALID_PEM}</public-key></entry>
      <entry name="pa-expired"><common-name>old.pa.test</common-name><not-valid-after>Jan 01 00:00:00 2024 GMT</not-valid-after></entry>
    </certificate>
    <server-profile>
      <syslog><entry name="sys1"><server><entry name="s1"><server>10.0.0.5</server></entry></server></entry></syslog>
    </server-profile>
  </shared>
  <devices><entry name="fw">
    <deviceconfig><system>
      <hostname>PA-AUDIT</hostname>
      <ip-address>8.8.8.8</ip-address>
      <service><disable-http>yes</disable-http><disable-https>no</disable-https><disable-ssh>no</disable-ssh></service>
    </system></deviceconfig>
    <network>
      <profiles><interface-management-profile><entry name="pub-mgmt"><https>yes</https><permitted-ip><entry name="1.1.1.0/24"/></permitted-ip></entry></interface-management-profile></profiles>
      <interface><ethernet>
        <entry name="ethernet1/1"><link-state>up</link-state><layer3><interface-management-profile>pub-mgmt</interface-management-profile><ip><entry name="1.1.1.5/24"/></ip></layer3></entry>
        <entry name="ethernet1/2"><link-state>down</link-state><layer3><units><entry name="ethernet1/2.10"><interface-management-profile>pub-mgmt</interface-management-profile><ip><entry name="1.1.1.99/24"/></ip></entry></units></layer3></entry>
      </ethernet></interface>
      <virtual-router><entry name="default"><interface><member>ethernet1/1</member></interface><routing-table><ip><static-route><entry name="def"><destination>0.0.0.0/0</destination><interface>ethernet1/1</interface><nexthop><ip-address>1.1.1.1</ip-address></nexthop></entry></static-route></ip></routing-table></entry></virtual-router>
    </network>
    <vsys><entry name="vsys1">
      <address>
        <entry name="used-addr"><ip-netmask>10.1.1.1/32</ip-netmask></entry>
        <entry name="unused-addr"><ip-netmask>10.9.9.9/32</ip-netmask></entry>
      </address>
      <rulebase><security><rules>
        <entry name="broad-rule"><from><member>any</member></from><to><member>any</member></to><source><member>used-addr</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>allow</action></entry>
      </rules></security></rulebase>
    </entry></vsys>
  </entry></devices>
</config>"""


def test_certificate_and_public_ip_helpers():
    parsed = parse_pem_certificate(_VALID_PEM, now=_NOW)
    assert parsed is not None
    assert parsed["common_name"] == "valid.example.test"
    assert "1.1.1.2" in parsed["san"]
    assert parsed["status"] == "Valid"

    assert is_public_ip("1.1.1.2/24") is True
    assert is_public_ip("10.0.0.1/24") is False
    assert is_public_ip("100.64.1.1/24") is False

    class _FakeSock:
        def settimeout(self, _t):
            pass

        def recv(self, _n):
            return b"SSH-2.0-OpenSSH_9.6\r\n"

        def close(self):
            pass

    def fake_connect(addr, _timeout):
        if addr[1] == 22:
            return _FakeSock()
        raise ConnectionRefusedError()

    res = probe_exposure_targets(
        [
            {
                "interface": "wan1",
                "severity": "critical",
                "restricted": False,
                "targets": [
                    {"ip": "1.1.1.2", "port": 22, "protocol": "SSH"},
                    {"ip": "1.1.1.2", "port": 443, "protocol": "HTTPS"},
                    {"ip": "10.0.0.1", "port": 22, "protocol": "SSH"},  # ignored private IP
                ],
            }
        ],
        connect_fn=fake_connect,
    )
    assert res["total"] == 2
    assert res["open_count"] == 1
    assert any("SSH-2.0-OpenSSH_9.6" in r["detail"] for r in res["results"])


def test_fortigate_and_paloalto_security_audit_analyzers():
    extracted = extract_fortigate_config(parse_fortigate_config(_FG_AUDIT_SAMPLE))
    fg_audit = build_fortigate_security_audit(
        extracted.config,
        build_fg_derived(extracted.config, source_metadata=extracted.source_metadata),
        metadata=extracted.source_metadata,
        now=_NOW,
    )
    assert fg_audit["certificate_summary"] == {"total": 2, "expired": 1, "expiring_soon": 1, "valid": 0, "no_pem": 0}
    assert "SUPER-SECRET-KEY-NEVER-EXPOSED" not in str(fg_audit)
    assert any(item["interface"] == "wan1" and item["severity"] == "critical" for item in fg_audit["exposure"])
    assert any(item["interface"] == "wan2" and "WAN Behind NAT" in item["note"] for item in fg_audit["exposure"])
    assert any("RDP_VIP" in item["interface"] and item["severity"] == "critical" for item in fg_audit["exposure"])
    assert fg_audit["posture"]["internet"] == "Connected (Direct Public IP)"
    assert fg_audit["posture"]["disk"] == "Yes (Log Disk Configured)"
    assert any(obj["name"] == "UNUSED_NET" for obj in fg_audit["hygiene"]["unused_objects"])
    assert 'delete "UNUSED_NET"' in fg_audit["hygiene"]["cleanup_cli"]
    assert fg_audit["quick_audit"]["high_count"] >= 2

    pa_cfg = build_panos_config(_PA_AUDIT_SAMPLE)
    pa_audit = build_paloalto_security_audit(pa_cfg, build_pa_derived(pa_cfg), now=_NOW)
    assert pa_audit["certificate_summary"] == {"total": 2, "expired": 1, "expiring_soon": 0, "valid": 1, "no_pem": 0}
    exp_ifaces = {item["interface"] for item in pa_audit["exposure"]}
    assert {"Management (MGT)", "ethernet1/1"} <= exp_ifaces
    assert "ethernet1/2.10" not in exp_ifaces  # parent link-state is down
    assert "1 Syslog profile(s)" in pa_audit["posture"]["disk_sub"]
    assert [obj["name"] for obj in pa_audit["hygiene"]["unused_objects"]] == ["unused-addr"]


def test_diagnostics_endpoints_enforce_security_boundaries_and_csp():
    public_client = create_app({"TESTING": True, "WEB_MODE": "public"}).test_client()
    payload = {"source_vendor": "fortigate", "source": {"vendor": "fortigate", "source_text": _FG_AUDIT_SAMPLE, "source_name": "edge.conf"}}

    audit_resp = public_client.post("/api/source/audit", json=payload)
    assert audit_resp.status_code == 200
    assert audit_resp.get_json()["success"] is True
    assert public_client.post("/api/source/audit", json={"source_vendor": "cisco_asa", "source": {"vendor": "cisco_asa", "source_text": ""}}).status_code == 400

    # Live exposure probe fails closed in public mode, non-loopback local mode, and passes with local loopback.
    assert public_client.post("/api/source/exposure-probe", json=payload).status_code == 403

    local_client = create_app({
        "TESTING": True,
        "WEB_MODE": "local",
        "EXPOSURE_PROBE_CONNECT_FN": lambda _addr, _timeout: (_ for _ in ()).throw(ConnectionRefusedError()),
    }).test_client()
    assert local_client.post("/api/source/exposure-probe", json=payload, environ_overrides={"REMOTE_ADDR": "192.0.2.50"}).status_code == 403
    probe_resp = local_client.post("/api/source/exposure-probe", json=payload)
    assert probe_resp.status_code == 200
    probe_data = probe_resp.get_json()
    assert probe_data["total"] >= 2
    assert probe_data["open_count"] == 0


def test_admin_hardening_quick_audit_checks():
    fg_hardening_conf = """#config-version=FGT60F-7.4.4-FW-build2662-240501:opmode=0:vdom=0:user=admin
config system global
    set hostname "fg-admin-audit"
    set admin-lockout-threshold 0
end
config system admin
    edit "admin"
        set accprofile "super_admin"
    next
end
"""
    extracted = extract_fortigate_config(parse_fortigate_config(fg_hardening_conf))
    fg_audit = build_fortigate_security_audit(
        extracted.config,
        build_fg_derived(extracted.config, source_metadata=extracted.source_metadata),
        metadata=extracted.source_metadata,
        now=_NOW,
    )
    fg_cats = {f["category"] for f in fg_audit["quick_audit"]["findings"]}
    assert "Admin Accounts Without Trusted Hosts" in fg_cats
    assert "Super-Admin Accounts Without 2FA" in fg_cats
    assert "Admin Password Policy Disabled" in fg_cats
    assert "Admin Login Lockout Disabled or Weak" in fg_cats

    pa_hardening_xml = """<config version="11.1.0">
  <mgt-config>
    <password-complexity><enabled>no</enabled></password-complexity>
    <users>
      <entry name="admin">
        <permissions><role-based><superuser>yes</superuser></role-based></permissions>
      </entry>
    </users>
  </mgt-config>
  <devices><entry name="fw">
    <deviceconfig><system>
      <hostname>PA-ADMIN-AUDIT</hostname>
      <ip-address>192.0.2.10</ip-address>
    </system></deviceconfig>
  </entry></devices>
</config>"""
    pa_cfg = build_panos_config(pa_hardening_xml)
    pa_audit = build_paloalto_security_audit(pa_cfg, build_pa_derived(pa_cfg), now=_NOW)
    pa_cats = {f["category"] for f in pa_audit["quick_audit"]["findings"]}
    assert "Management Interface Unrestricted (Permitted IPs: Any)" in pa_cats
    assert "Admin Password Complexity Disabled" in pa_cats
    assert "Admin Login Lockout Not Configured" in pa_cats
    assert "Local Superuser Without External Auth Profile" in pa_cats
