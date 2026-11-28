"""Unit tests for FortiGate SSL-VPN -> Dial-up IPSec (IKEv2) Migration Assistant."""

from __future__ import annotations

from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.fortigate.ssl_to_ipsec import analyze_fortigate_ssl_to_ipsec


def _analyze(conf_text: str, *, vdom: str | None = None) -> dict:
    extracted = extract_fortigate_config(parse_fortigate_config(conf_text))
    return analyze_fortigate_ssl_to_ipsec(
        extracted.config,
        metadata=extracted.source_metadata,
        vdom=vdom,
    )


def test_no_ssl_vpn_returns_inactive():
    conf = """#config-version=FGT60F-7.4.9-FW-build2829-250101:opmode=0:vdom=0:user=admin
config system interface
    edit "internal"
        set vdom "root"
        set ip 10.10.0.1 255.255.255.0
    next
end
"""
    res = _analyze(conf)
    assert res["has_ssl_vpn"] is False
    assert res["vdom"] is None
    assert res["vdoms"] == []
    assert res["model"] == "FGT60F"
    assert res["firmware"] == "7.4.9"


def test_eap_ldap_ssl_vpn_warnings_and_utm_policy_cloning():
    conf = """#config-version=FGT100F-7.2.10-FW-build1706-240901:opmode=0:vdom=0:user=admin
config vpn certificate local
    edit "OtherCert"
    next
end
config user ldap
    edit "CorpLDAP"
        set server "10.0.0.10"
        set cnid "sAMAccountName"
        set dn "dc=corp,dc=local"
        set password ENC VERY_SECRET_LDAP_PW
    next
end
config user group
    edit "VPN_Staff"
        set member "CorpLDAP"
    next
end
config vpn ssl web portal
    edit "full-access"
        set tunnel-mode enable
        set web-mode enable
        set ip-pools "SSLVPN_POOL_1"
        set split-tunneling enable
        set split-tunneling-routing-address "CORP_LAN" "CORP_DMZ"
        set host-check av
    next
    edit "web-only"
        set web-mode enable
    next
end
config vpn ssl settings
    set servercert "Fortinet_Factory"
    set tunnel-ip-pools "SSLVPN_POOL_1"
    set source-interface "wan1" "wan2"
    set dns-server1 10.0.0.53
    set dns-server2 10.0.0.54
    set default-portal "full-access"
    config authentication-rule
        edit 1
            set groups "VPN_Staff"
            set portal "full-access"
        next
    end
end
config firewall policy
    edit 10
        set name "SSL_To_LAN"
        set srcintf "ssl.root"
        set dstintf "internal"
        set action accept
        set srcaddr "SSLVPN_POOL_1"
        set dstaddr "CORP_LAN"
        set service "ALL"
        set schedule "always"
        set groups "VPN_Staff"
        set nat enable
        set utm-status enable
        set av-profile "default"
        set webfilter-profile "corp-web"
        set ips-sensor "high_security"
        set ssl-ssh-profile "certificate-inspection"
    next
    edit 11
        set name "Disabled_Rule"
        set status disable
        set srcintf "ssl.root"
        set dstintf "dmz"
        set action deny
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
    next
end
"""
    res = _analyze(conf)
    assert res["has_ssl_vpn"] is True
    assert res["vdom"] == "root"
    assert res["auth_mode"] == "eap"
    assert res["is_factory_cert"] is True
    assert res["wan_intf"] == "wan1"
    assert res["primary_pool"] == "SSLVPN_POOL_1"
    assert res["portals_count"] == 2
    assert res["ssl_policies_count"] == 2

    warnings_text = "\n".join(res["warnings"])
    infos_text = "\n".join(res["infos"])
    assert "Fortinet_Factory" in warnings_text
    assert "Web-Mode / Bookmarks" in warnings_text
    assert "Host-Check" in warnings_text
    assert "Multiple SSL portals detected (2)" in infos_text
    assert "1 LDAP, 0 RADIUS" in infos_text

    cli = res["cli_draft"]
    assert "VERY_SECRET_LDAP_PW" not in cli
    assert "set psksecret <REPLACE_WITH_STRONG_PSK>" in cli
    assert 'set ipv4-name "SSLVPN_POOL_1"' in cli
    assert "set ipv4-dns-server1 10.0.0.53" in cli
    assert "set ipv4-dns-server2 10.0.0.54" in cli
    assert 'set ipv4-split-include "CORP_LAN" "CORP_DMZ"' in cli
    assert 'set authusrgrp "VPN_Staff"' in cli
    assert 'set name "IPSec-SSL_To_LAN"' in cli
    assert 'set srcintf "RA-IPSec-IKEv2"' in cli
    assert "set utm-status enable" in cli
    assert 'set av-profile "default"' in cli
    assert 'set webfilter-profile "corp-web"' in cli
    assert 'set ips-sensor "high_security"' in cli
    assert 'set ssl-ssh-profile "certificate-inspection"' in cli
    assert 'set groups "VPN_Staff"' in cli


def test_saml_and_client_cert_detection_and_missing_cert_warning():
    saml_conf = """config vpn certificate local
    edit "vpn.corp.com"
    next
end
config user saml
    edit "EntraID_SAML"
        set entity-id "https://vpn.corp.com/saml"
    next
end
config user group
    edit "SAML_Users"
        set member "EntraID_SAML"
    next
end
config vpn ssl settings
    set servercert "vpn.corp.com"
    set source-interface "port1"
    set tunnel-ip-pools "SSLVPN_POOL"
    config authentication-rule
        edit 1
            set groups "SAML_Users"
            set portal "full-access"
        next
    end
end
"""
    saml_res = _analyze(saml_conf)
    assert saml_res["auth_mode"] == "saml"
    assert "EntraID_SAML" in saml_res["auth_label"]
    assert 'set ike-saml-server "EntraID_SAML"' in saml_res["cli_draft"]
    assert "No firewall policies found with an ssl.* source interface" in "\n".join(saml_res["warnings"])

    cert_conf = """config vpn certificate local
    edit "OtherLocalCert"
    next
end
config vpn ssl settings
    set status disable
    set servercert "Missing_Cert"
    set reqclientcert enable
    set source-interface "wan2"
end
"""
    cert_res = _analyze(cert_conf)
    assert cert_res["auth_mode"] == "cert"
    assert cert_res["require_client_cert"] is True
    assert "config user peer" in cert_res["cli_draft"]
    assert "set authmethod signature" in cert_res["cli_draft"]
    assert 'set certificate "Missing_Cert"' in cert_res["cli_draft"]
    assert "not found in 'config vpn certificate local'" in "\n".join(cert_res["warnings"])
    assert "currently disabled" in "\n".join(cert_res["infos"])


def test_multi_vdom_isolation():
    conf = """config vdom
    edit root
        config vpn ssl settings
            set servercert "RootCert"
            set source-interface "wan1"
            set tunnel-ip-pools "ROOT_POOL"
        end
        config firewall policy
            edit 1
                set name "Root_SSL"
                set srcintf "ssl.root"
                set dstintf "lan"
                set action accept
                set srcaddr "all"
                set dstaddr "all"
                set service "ALL"
                set schedule "always"
            next
        end
    next
    edit corp
        config vpn ssl settings
            set servercert "CorpCert"
            set source-interface "wan-corp"
            set tunnel-ip-pools "CORP_POOL"
        end
        config firewall policy
            edit 2
                set name "Corp_SSL"
                set srcintf "ssl.corp"
                set dstintf "corp-lan"
                set action accept
                set srcaddr "all"
                set dstaddr "all"
                set service "ALL"
                set schedule "always"
            next
        end
    next
end
"""
    root_res = _analyze(conf)
    assert root_res["vdoms"] == ["root", "corp"]
    assert root_res["vdom"] == "root"
    assert root_res["primary_pool"] == "ROOT_POOL"
    assert [p["name"] for p in root_res["ssl_policies"]] == ["Root_SSL"]

    corp_res = _analyze(conf, vdom="corp")
    assert corp_res["vdom"] == "corp"
    assert corp_res["primary_pool"] == "CORP_POOL"
    assert corp_res["wan_intf"] == "wan-corp"
    assert [p["name"] for p in corp_res["ssl_policies"]] == ["Corp_SSL"]
