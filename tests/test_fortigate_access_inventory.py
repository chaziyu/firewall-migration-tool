import io

from openpyxl import load_workbook

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.model import FGSSLVPNHostCheckSoftware
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
config user fsso
    edit "corp-fsso"
        set server "10.10.10.10"
        set password "{SECRET}"
        set custom-option test
    next
end
config user adgrp
    edit "CORP/DOMAIN USERS"
        set server-name "corp-fsso"
    next
    edit "CORP/IT"
        set server-name "corp-fsso"
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
    edit "corp-fsso-users"
        set group-type fsso-service
        set member "CORP/DOMAIN USERS" "CORP/IT"
    next
end
config firewall policy
    edit 100
        set name "FSSO policy"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set groups "corp-fsso-users"
        set action accept
        set schedule "always"
        set service "ALL"
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
    assert len(fg.fsso_servers) == 1
    assert len(fg.ad_groups) == 2
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

    provider = fg.fsso_servers[0]
    assert provider.name == "corp-fsso"
    assert provider.server == "10.10.10.10"
    assert provider.has_password is True
    assert provider.extra_settings == {"custom_option": "test"}
    assert fg.ad_groups[0].name == "CORP/DOMAIN USERS"
    assert fg.ad_groups[0].server_name == "corp-fsso"

    assert len(ir.fsso_providers) == 1
    assert len(ir.fsso_ad_groups) == 2
    ir_provider = ir.fsso_providers[0]
    assert ir_provider.name == "corp-fsso"
    assert ir_provider.server == "10.10.10.10"
    assert ir_provider.has_password is True
    ad_group = ir.fsso_ad_groups[0]
    assert ad_group.name == "CORP/DOMAIN USERS"
    assert ad_group.provider_name == "corp-fsso"
    assert ad_group.provider_resolved is True
    assert ad_group.migration_status == "EXTRACT_ONLY"
    fsso_user_group = next(
        item for item in ir.user_groups if item.name == "corp-fsso-users"
    )
    assert fsso_user_group.group_type == "fsso-service"
    assert fsso_user_group.members == ["CORP/DOMAIN USERS", "CORP/IT"]
    assert ir.policies[0].source_user_groups == ["corp-fsso-users"]

    coverage = {item.path: item for item in result.source_sections}
    for path, count in (("user fsso", 1), ("user adgrp", 2)):
        assert coverage[path].status.value == "EXTRACT_ONLY"
        assert coverage[path].object_count_source == count
        assert coverage[path].object_count_parsed == count
        assert coverage[path].object_count_normalized == count


def test_ssl_vpn_dos_sniffer_and_authentication_stay_separate_inventory():
    result = extract_fortigate_config(ACCESS_CONFIG)
    fg = parse_fortigate_config(ACCESS_CONFIG)
    assert isinstance(fg.ssl_vpn_portals[0].host_checks[0], FGSSLVPNHostCheckSoftware)
    assert fg.ssl_vpn_portals[0].host_checks[0].extra_settings == {"os_type": "windows"}

    ir = result.canonical_ir
    portal = ir.ssl_vpn_portals[0]
    assert portal.ip_pools == ["SSLVPN_POOL"]
    assert portal.ipv6_pools == ["SSLVPN_POOL6"]
    assert portal.split_tunneling == "enable"
    assert portal.host_checks[0].name == "endpoint-agent"
    assert portal.host_checks[0].source_type == "antivirus"
    assert portal.host_checks[0].version == "1.2.3"
    assert portal.host_checks[0].guid == "agent-guid"
    assert portal.host_checks[0].migration_status == "EXTRACT_ONLY"
    assert portal.host_checks[0].requires_manual_review is True
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
    assert [policy.name for policy in ir.policies] == ["FSSO policy"]

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
        "FSSO Servers",
        "FSSO AD Groups",
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

    host_checks = workbook["SSL VPN Host Checks"]
    host_check_headers = {cell.value: cell.column for cell in host_checks[3]}
    assert host_checks.max_row == 4
    assert host_checks.cell(4, host_check_headers["Portal"]).value == "full-access"
    assert host_checks.cell(4, host_check_headers["Type"]).value == "antivirus"
    assert host_checks.cell(4, host_check_headers["Version"]).value == "1.2.3"
    assert host_checks.cell(4, host_check_headers["GUID"]).value == "agent-guid"
    assert host_checks.cell(4, host_check_headers["Migration Status"]).value == "EXTRACT_ONLY"
    assert host_checks.cell(4, host_check_headers["Manual Review"]).value == "Yes"
    assert "os-type=windows" in host_checks.cell(4, host_check_headers["Additional Settings"]).value

    fsso_servers = workbook["FSSO Servers"]
    server_headers = {cell.value: cell.column for cell in fsso_servers[3]}
    assert fsso_servers.cell(4, server_headers["Name"]).value == "corp-fsso"
    assert fsso_servers.cell(4, server_headers["Server"]).value == "10.10.10.10"
    assert fsso_servers.cell(4, server_headers["Password Configured"]).value == "Yes"

    fsso_groups = workbook["FSSO AD Groups"]
    group_headers = {cell.value: cell.column for cell in fsso_groups[3]}
    assert fsso_groups.cell(4, group_headers["Name"]).value == "CORP/DOMAIN USERS"
    assert fsso_groups.cell(4, group_headers["FSSO Server"]).value == "corp-fsso"
    assert fsso_groups.cell(4, group_headers["Server Resolved"]).value == "Yes"
    assert fsso_groups.cell(4, group_headers["Extraction Status"]).value == "EXTRACT_ONLY"

    user_groups = workbook["User Groups"]
    user_group_headers = {cell.value: cell.column for cell in user_groups[3]}
    fsso_group_row = next(
        row for row in range(4, user_groups.max_row + 1)
        if user_groups.cell(row, user_group_headers["Name"]).value == "corp-fsso-users"
    )
    assert user_groups.cell(fsso_group_row, user_group_headers["Members"]).value == (
        "CORP/DOMAIN USERS\nCORP/IT"
    )

    policies = workbook["Policies"]
    policy_headers = {cell.value: cell.column for cell in policies[3]}
    assert policies.cell(4, policy_headers["User Groups"]).value == "corp-fsso-users"

    summary = {
        workbook["Summary"].cell(row, 1).value:
        workbook["Summary"].cell(row, 2).value
        for row in range(1, workbook["Summary"].max_row + 1)
    }
    assert summary["FSSO Servers"] == 1
    assert summary["FSSO AD Groups"] == 2


def test_missing_fsso_identity_references_are_preserved_and_audited():
    config = """
config user adgrp
    edit "CORP/MISSING"
        set server-name "missing-fsso"
    next
end
config user group
    edit "broken-fsso-users"
        set group-type fsso-service
        set member "CORP/MISSING" "CORP/UNKNOWN"
    next
end
"""
    ir = extract_fortigate_config(config).canonical_ir

    ad_group = ir.fsso_ad_groups[0]
    assert ad_group.name == "CORP/MISSING"
    assert ad_group.provider_name == "missing-fsso"
    assert ad_group.provider_resolved is False
    assert ad_group.requires_manual_review is True
    assert ir.user_groups[0].members == ["CORP/MISSING", "CORP/UNKNOWN"]

    messages = [entry.message for entry in ir.audit_entries]
    assert (
        "FSSO AD group 'CORP/MISSING' references missing FSSO provider "
        "'missing-fsso'."
    ) in messages
    assert (
        "User group 'broken-fsso-users' references missing FSSO AD group "
        "'CORP/UNKNOWN'."
    ) in messages
