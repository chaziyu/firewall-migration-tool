from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_phase32_ssl_vpn_portal_uses_fortios_746_supported_structure() -> None:
    secret = "PHASE32_FORM_SECRET"
    content = f"""
config vpn ssl web portal
    edit "phase32-portal"
        set tunnel-mode enable
        set web-mode enable
        set ip-pools "POOL-B" "POOL-A"
        set ipv6-pools "POOL6-B" "POOL6-A"
        set split-tunneling enable
        set split-tunneling-routing-address "ROUTE-B" "ROUTE-A"
        set heading "temporary heading"
        unset heading
        config split-dns
            edit 20
                set domains "b.example.test"
                set dns-server1 10.0.0.20
                set ipv6-dns-server1 2001:db8::20
            next
            edit 10
                set domains "a.example.test"
                set dns-server1 10.0.0.10
                set ipv6-dns-server1 2001:db8::10
            next
        end
        config bookmark-group
            edit "group-b"
                config bookmarks
                    edit "ssh-b"
                        set apptype ssh
                        set url "ssh://10.0.0.20"
                    next
                    edit "web-a"
                        set apptype web
                        set url "https://intranet.example.test"
                    next
                end
            next
            edit "group-a"
                config bookmarks
                    edit "rdp-a"
                        set apptype rdp
                        set host "10.0.0.10"
                        config form-data
                            edit "credential-placeholder"
                                set value "{secret}"
                            next
                        end
                    next
                end
            next
        end
    next
end
"""
    fg = parse_fortigate_config(content)
    portal = fg.ssl_vpn_portals[0]

    assert portal.name == "phase32-portal"
    assert portal.ip_pools == ["POOL-B", "POOL-A"]
    assert portal.ipv6_pools == ["POOL6-B", "POOL6-A"]
    assert portal.split_tunneling_routing_address == ["ROUTE-B", "ROUTE-A"]
    assert portal.heading is None
    assert [item.id for item in portal.split_dns] == [20, 10]
    assert [item.domains for item in portal.split_dns] == [
        "b.example.test", "a.example.test"
    ]
    assert [item.name for item in portal.bookmark_groups] == ["group-b", "group-a"]
    assert [item.name for item in portal.bookmark_groups[0].bookmarks] == [
        "ssh-b", "web-a"
    ]
    assert portal.bookmark_groups[1].bookmarks[0].form_data[0].value_configured is True
    assert secret not in fg.model_dump_json()


def test_phase33_user_groups_preserve_official_local_and_remote_mappings() -> None:
    content = """
config user local
    edit "alice"
        set type password
    next
end
config user group
    edit "local-group"
        set type firewall
        set member "alice" "missing-local-user"
    next
    edit "remote-group"
        set type firewall
        config match
            edit 20
                set server-name "missing-ldap-b"
                set group-name "CN=VPN-B,DC=example,DC=test"
            next
            edit 10
                set server-name "missing-ldap-a"
                set group-name "CN=VPN-A,DC=example,DC=test"
            next
        end
    next
end
"""
    fg = parse_fortigate_config(content)
    local_group, remote_group = fg.user_groups

    assert local_group.group_type == "firewall"
    assert local_group.member == ["alice", "missing-local-user"]
    assert [item.id for item in remote_group.match] == [20, 10]
    assert [item.server_name for item in remote_group.match] == [
        "missing-ldap-b", "missing-ldap-a"
    ]
    assert [item.group_name for item in remote_group.match] == [
        "CN=VPN-B,DC=example,DC=test", "CN=VPN-A,DC=example,DC=test"
    ]

    result = extract_fortigate_config(content)
    assert any(
        dependency.source_path == "user group"
        and dependency.reference == "missing-local-user"
        and dependency.result == "UNRESOLVED"
        for dependency in result.dependencies
    )


def test_phase34_local_user_keeps_supported_auth_metadata_without_secrets() -> None:
    password_secret = "PHASE34_PASSWORD_SECRET"
    ppk_secret = "PHASE34_PPK_SECRET"
    content = f"""
config user local
    edit "phase34-user"
        set status enable
        set type password
        set passwd "{password_secret}"
        set ppk-secret "{ppk_secret}"
        set two-factor fortitoken
        set two-factor-authentication fortitoken
        set two-factor-notification email
        set fortitoken "FTK-PHASE34"
        set email-to "phase34@example.test"
        set ldap-server "corp-ldap"
        set radius-server "corp-radius"
        set tacacs+-server "corp-tacacs"
        set auth-concurrent-override enable
        set auth-concurrent-value 2
        set authtimeout 30
        set passwd-policy "strong-password-policy"
        set workstation "phase34-ws"
    next
end
"""
    fg = parse_fortigate_config(content)
    user = fg.local_users[0]

    assert (user.status, user.type) == ("enable", "password")
    assert user.has_password is True
    assert user.has_ppk_secret is True
    assert (user.two_factor, user.two_factor_authentication, user.two_factor_notification) == (
        "fortitoken", "fortitoken", "email"
    )
    assert user.fortitoken == "FTK-PHASE34"
    assert user.email_to == "phase34@example.test"
    assert (user.ldap_server, user.radius_server, user.tacacs_server) == (
        "corp-ldap", "corp-radius", "corp-tacacs"
    )
    assert (user.auth_concurrent_override, user.auth_concurrent_value, user.authtimeout) == (
        "enable", 2, 30
    )
    assert user.passwd_policy == "strong-password-policy"
    assert user.workstation == "phase34-ws"

    result = extract_fortigate_config(content)
    serialized = "\n".join((
        fg.model_dump_json(),
        result.model_dump_json(),
        result.canonical_ir.model_dump_json(),
    ))
    assert password_secret not in serialized
    assert ppk_secret not in serialized


def test_phase35_ldap_uses_fortios_746_password_and_supported_fields() -> None:
    password_secret = "PHASE35_BIND_PASSWORD_SECRET"
    content = f"""
config user ldap
    edit "phase35-ldap"
        set server "ldap-primary.example.test"
        set secondary-server "ldap-secondary.example.test"
        set tertiary-server "ldap-tertiary.example.test"
        set username "bind-user"
        set password "{password_secret}"
        set port 636
        set secure ldaps
        set ca-cert "LDAP-ROOT-CA"
        set client-cert "LDAP-CLIENT-CERT"
        set client-cert-auth enable
        set server-identity-check enable
        set source-ip "192.0.2.35"
        set source-port 49135
        set interface-select-method specify
        set interface "mgmt"
        set group-filter "(objectClass=group)"
        set group-search-base "ou=Groups,dc=example,dc=test"
        set group-member-check user-attr
        set group-object-filter "(objectClass=group)"
        set member-attr member
        set search-type recursive
        set ssl-min-proto-version tls1-2
    next
end
"""
    fg = parse_fortigate_config(content)
    ldap = fg.user_ldap_servers[0]

    assert (ldap.server, ldap.secondary_server, ldap.tertiary_server) == (
        "ldap-primary.example.test",
        "ldap-secondary.example.test",
        "ldap-tertiary.example.test",
    )
    assert ldap.has_password is True
    assert (ldap.port, ldap.source_port) == (636, 49135)
    assert (ldap.secure, ldap.ca_cert, ldap.client_cert, ldap.client_cert_auth) == (
        "ldaps", "LDAP-ROOT-CA", "LDAP-CLIENT-CERT", "enable"
    )
    assert ldap.server_identity_check == "enable"
    assert (ldap.source_ip, ldap.interface_select_method, ldap.interface) == (
        "192.0.2.35", "specify", "mgmt"
    )
    assert (ldap.group_filter, ldap.group_search_base, ldap.group_member_check) == (
        "(objectClass=group)", "ou=Groups,dc=example,dc=test", "user-attr"
    )
    assert ldap.group_object_filter == "(objectClass=group)"
    assert ldap.member_attr == "member"
    assert ldap.search_type == ["recursive"]
    assert ldap.ssl_min_proto_version == "tls1-2"

    result = extract_fortigate_config(content)
    ir_ldap = result.canonical_ir.user_ldap_servers[0]
    assert ir_ldap.has_password is True
    assert (ir_ldap.server, ir_ldap.secondary_server, ir_ldap.tertiary_server) == (
        "ldap-primary.example.test",
        "ldap-secondary.example.test",
        "ldap-tertiary.example.test",
    )
    serialized = "\n".join((
        fg.model_dump_json(),
        result.model_dump_json(),
        result.canonical_ir.model_dump_json(),
    ))
    assert password_secret not in serialized
