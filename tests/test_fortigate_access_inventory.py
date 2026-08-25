import io

from openpyxl import load_workbook

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.report.excel_exporter import IRExcelExporter


SECRET = "identity-secret-must-not-survive"


ACCESS_CONFIG = f"""
config user ldap
    edit "corp-ldap"
        set server "ldap.example.test"
        set cnid "sAMAccountName"
        set dn "dc=example,dc=test"
        set type regular
        set username "bind-user"
        set password "{SECRET}"
        set secure ldaps
    next
end
config user saml
    edit "corp-saml"
        set entity-id "https://fw.example.test/saml"
        set single-sign-on-url "https://fw.example.test/login"
        set single-logout-url "https://fw.example.test/logout"
        set idp-entity-id "https://idp.example.test"
        set idp-single-sign-on-url "https://idp.example.test/sso"
        set idp-single-logout-url "https://idp.example.test/slo"
        set idp-cert "IDP_CERT"
        set user-name "username"
        set group-name "group"
        set digest-method sha256
    next
end
config user local
    edit "local-review"
        set status enable
        set type password
        set passwd "{SECRET}"
        set seed "{SECRET}"
        set activation-code "{SECRET}"
    next
end
config user group
    edit "remote-users"
        set type firewall
        set member "local-review"
        set authtimeout 30
        config match
            edit 1
                set server-name "corp-ldap"
                set group-name "CN=VPN,DC=example,DC=test"
            next
        end
    next
end
config vpn ssl web portal
    edit "full-access"
        set tunnel-mode enable
        set ipv6-tunnel-mode enable
        set ip-pools "SSLVPN_POOL"
        set ipv6-pools "SSLVPN_POOL6"
        set split-tunneling enable
        set limit-user-logins enable
        set forticlient-download disable
        set display-bookmark enable
        config host-check-software
            edit "endpoint-agent"
                set type antivirus
                set guid "agent-guid"
                set version "1.2.3"
                set os-type windows
            next
        end
    next
end
config vpn ssl settings
    set status enable
    set ssl-min-proto-ver tls1-2
    set banned-cipher RSA 3DES
    set servercert "VPN_CERT"
    set source-interface "wan1" "wan2"
    set source-address "allowed-admins"
    set tunnel-ip-pools "SSLVPN_POOL"
    set default-portal "full-access"
    set login-attempt-limit 3
    config authentication-rule
        edit 1
            set groups "remote-users"
            set portal "full-access"
            set client-cert enable
        next
    end
end
config firewall DoS-policy
    edit 10
        set status enable
        set interface "wan1"
        set srcaddr "all"
        set dstaddr "VIP_A"
        set service "ALL"
        set comments "Protect published service"
        set policyid 10
        config anomaly
            edit "tcp_syn_flood"
                set status enable
                set log enable
                set action block
                set threshold 2000
                set quarantine attacker
            next
        end
    next
end
config firewall sniffer
    edit 5
        set uuid "sniffer-uuid"
        set logtraffic all
        set ipv6 enable
        set non-ip disable
        set application-list-status enable
        set application-list "monitor-apps"
        set ips-sensor-status enable
        set ips-sensor "strict-ips"
        set av-profile-status enable
        set av-profile "strict-av"
        set webfilter-profile-status enable
        set webfilter-profile "strict-web"
        set interface "port1"
    next
end
config authentication scheme
    edit "browser-auth"
        set method basic
        set user-database "remote-users"
        set require-tfa enable
    next
end
config authentication rule
    edit "admin-auth"
        set srcintf "wan1" "wan2"
        set srcaddr "allowed-admins"
        set active-auth-method "browser-auth"
        set protocol http
    next
end
"""


def test_identity_inventory_strips_credentials_and_preserves_safe_metadata():
    fg = parse_fortigate_config(ACCESS_CONFIG)
    result = extract_fortigate_config(ACCESS_CONFIG)
    ir = result.canonical_ir

    assert fg.user_ldap_servers[0].has_password is True
    assert fg.local_users[0].has_password is True
    assert SECRET not in fg.model_dump_json()
    assert SECRET not in ir.model_dump_json()
    assert SECRET not in result.model_dump_json()

    ldap = ir.user_ldap_servers[0]
    assert (ldap.server, ldap.cnid, ldap.dn, ldap.username) == (
        "ldap.example.test", "sAMAccountName", "dc=example,dc=test", "bind-user"
    )
    assert ldap.has_password is True
    assert ldap.source_attributes == {"secure": "ldaps"}
    saml = ir.user_saml_servers[0]
    assert saml.idp_single_sign_on_url == "https://idp.example.test/sso"
    assert saml.idp_cert == "IDP_CERT"
    group = ir.user_groups[0]
    assert group.group_type == "firewall"
    assert group.members == ["local-review"]
    assert group.matches[0].server_name == "corp-ldap"
    assert group.matches[0].group_name == "CN=VPN,DC=example,DC=test"
    assert group.source_attributes == {"authtimeout": "30"}


def test_ssl_vpn_dos_sniffer_and_authentication_stay_separate_inventory():
    ir = extract_fortigate_config(ACCESS_CONFIG).canonical_ir
    portal = ir.ssl_vpn_portals[0]
    assert portal.ip_pools == ["SSLVPN_POOL"]
    assert portal.ipv6_pools == ["SSLVPN_POOL6"]
    assert portal.split_tunneling == "enable"
    assert portal.host_checks[0].name == "endpoint-agent"
    assert portal.host_checks[0].source_attributes == {"os_type": "windows"}
    assert ir.vpn_tunnels == []

    settings = ir.ssl_vpn_settings
    assert settings is not None
    assert settings.status == "enable"
    assert settings.ssl_min_proto_ver == "tls1-2"
    assert settings.banned_cipher == ["RSA", "3DES"]
    assert settings.source_interfaces == ["wan1", "wan2"]
    assert settings.authentication_rules[0].groups == ["remote-users"]
    assert settings.authentication_rules[0].portal == "full-access"
    assert settings.authentication_rules[0].source_attributes == {"client_cert": "enable"}

    dos = ir.dos_policies[0]
    assert dos.source_id == 10
    assert dos.source_addresses == ["all"]
    assert dos.destination_addresses == ["VIP_A"]
    assert dos.services == ["ALL"]
    assert dos.anomalies[0].name == "tcp_syn_flood"
    assert dos.anomalies[0].threshold == 2000
    assert dos.anomalies[0].source_attributes == {"quarantine": "attacker"}

    sniffer = ir.firewall_sniffers[0]
    assert sniffer.source_id == 5
    assert sniffer.application_list == "monitor-apps"
    assert sniffer.ips_sensor == "strict-ips"
    assert sniffer.av_profile == "strict-av"
    assert sniffer.webfilter_profile == "strict-web"
    assert sniffer.source_attributes == {"interface": "port1"}
    assert ir.policies == []

    assert ir.authentication_schemes[0].user_database == "remote-users"
    assert ir.authentication_schemes[0].source_attributes == {"require_tfa": "enable"}
    rule = ir.authentication_rules[0]
    assert rule.source_interfaces == ["wan1", "wan2"]
    assert rule.source_addresses == ["allowed-admins"]
    assert rule.active_auth_method == "browser-auth"
    assert rule.source_attributes == {"protocol": "http"}


def test_access_inventory_excel_contains_no_credentials():
    result = extract_fortigate_config(ACCESS_CONFIG)
    workbook = load_workbook(
        io.BytesIO(
            IRExcelExporter(
                result.canonical_ir,
                extraction_result=result,
            ).generate()
        )
    )
    all_text = "\n".join(
        str(cell.value)
        for sheet in workbook.worksheets
        for row in sheet.iter_rows()
        for cell in row
        if cell.value is not None
    )
    assert SECRET not in all_text
    for sheet_name in (
        "LDAP Servers",
        "SAML Servers",
        "Local Users",
        "User Groups",
        "User Group Matches",
        "SSL VPN Settings",
        "SSL VPN Portals",
        "SSL VPN Authentication Rules",
        "SSL VPN Host Checks",
        "DoS Policies",
        "DoS Anomalies",
        "Firewall Sniffer",
        "Authentication Schemes",
        "Authentication Rules",
    ):
        assert sheet_name in workbook.sheetnames
