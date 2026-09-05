from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


CONFIG = r'''
config vpn ipsec phase1-interface
    edit "route-p1"
        set interface "wan1"
    next
end
config vpn ipsec phase2-interface
    edit "route-subnet"
        set phase1name "route-p1"
        set proposal aes256-sha256
        set pfs enable
        set dhgrp 14 19
        set keylife-type seconds
        set keylifeseconds 3600
        set replay enable
        set src-addr-type subnet
        set src-subnet 10.0.0.0 255.255.255.0
        set dst-addr-type subnet
        set dst-subnet 10.1.0.0 255.255.255.0
    next
    edit "route-ipv6-name"
        set phase1name "route-p1"
        set src-addr-type name
        set src-name "local-v6"
        set dst-addr-type subnet
        set dst-subnet6 2001:db8:2:: 64
        set src-port 443
        set dst-port 8443
        set protocol 6
        set initiator-autoclose 30
    next
end
config vpn ipsec phase2
    edit 10
        set phase1name "policy-p1"
        set proposal aes128-sha1
        set pfs enable
        set dhgrp 20
        set src-addr-type name
        set src-name "policy-local"
        set dst-addr-type subnet
        set dst-subnet6 2001:db8:10:: 64
    next
end

config vpn ssl settings
    set status enable
    set servercert "SSL_CERT"
    set port 10443
    set source-interface "wan1" "wan2"
    set source-address "SSL_SOURCE"
    set tunnel-ip-pools "SSL_POOL"
    set tunnel-ipv6-pools "SSL_POOL6"
    set default-portal "full"
    config authentication-rule
        edit 1
            set auth local
            set groups "vpn-users"
            set portal "full"
        next
        edit 2
            set auth ldap
            set source-address6 "2001:db8:20::/64"
            set portal "restricted"
        next
    end
    config future-listener
        edit "future"
            set nested-value retained
        next
    end
end
config vpn ssl web portal
    edit "full"
        set tunnel-mode enable
        set ip-pools "SSL_POOL"
        config split-dns
            edit 1
                set domains "corp.example"
                set dns-server1 10.0.0.2
            next
        end
        config mac-addr-check-rule
            edit 1
                set mac-addr "00:11:22:33:44:55"
                set action allow
            next
        end
        config os-check-list
            edit 1
                set os-type windows
                set os-version "11"
                set action allow
            next
        end
        config bookmark-group
            edit "apps"
                config bookmarks
                    edit "ssh"
                        set apptype ssh
                        set host 10.0.0.10
                        set port 22
                        set sso enable
                    next
                end
            next
        end
        config landing-page
            edit "welcome"
                set heading "Welcome"
                set theme dark
            next
        end
    next
end

config user ldap
    edit "simple-ldap"
        set server "ldap.example.test"
        set type simple
        set username "bind-user"
        set password "LDAP_SECRET"
        set dn "dc=example,dc=test"
        set cnid uid
        set group-search-base "ou=Groups,dc=example,dc=test"
        set group-member-check user-attr
        set member-attr member
    next
    edit "secure-ldap"
        set server "ldaps.example.test"
        set secure ldaps
        set ca-cert "LDAP_CA"
        set client-cert "LDAP_CLIENT"
        set source-ip 192.0.2.10
        set source-port 636
        set ssl-min-proto-version tls1-2
        set schema active-directory
        set timeout 5
    next
end
config user radius
    edit "radius"
        set server "radius-1.example.test"
        set secondary-server "radius-2.example.test"
        set tertiary-server "radius-3.example.test"
        set auth-type ms_chap_v2
        set auth-port 1812
        set acct-port 1813
        set timeout 10
        set retries 3
        set source-ip 192.0.2.20
        set interface-select-method specify
        set interface "mgmt"
        set secret "RADIUS_SECRET"
        config accounting-server
            edit "primary"
                set status enable
                set server "acct.example.test"
                set port 1813
                set source-ip 192.0.2.21
                set secret "ACCOUNTING_SECRET"
            next
        end
    next
end
config user tacacs+
    edit "tacacs"
        set server "tacacs-1.example.test"
        set secondary-server "tacacs-2.example.test"
        set authen-type pap
        set authorization enable
        set source-ip 192.0.2.30
        set interface-select-method specify
        set interface "mgmt"
        set timeout 10
        set retries 3
        set connect-timeout 4
        set key "TACACS_SECRET"
    next
end
'''


def test_phases_12_to_17_keep_typed_source_semantics_and_secrets_safe():
    parsed = parse_fortigate_config(CONFIG)

    route_subnet, route_ipv6 = parsed.phase2_interfaces
    assert route_subnet.phase1name == "route-p1"
    assert route_subnet.pfs == "enable"
    assert route_subnet.dhgrp == [14, 19]
    assert route_subnet.keylifeseconds == 3600
    assert route_subnet.replay == "enable"
    assert route_subnet.src_subnet == "10.0.0.0 255.255.255.0"
    assert route_ipv6.src_name == ["local-v6"]
    assert route_ipv6.dst_subnet6 == "2001:db8:2:: 64"
    assert (route_ipv6.src_port, route_ipv6.dst_port, route_ipv6.protocol) == (
        "443", "8443", "6"
    )
    assert route_ipv6.initiator_autoclose == 30

    policy = parsed.phase2_policies[0]
    assert policy.phase1name == "policy-p1"
    assert policy.src_name == ["policy-local"]
    assert policy.dst_subnet6 == "2001:db8:10:: 64"
    assert policy.dhgrp == [20]

    settings = parsed.ssl_vpn_settings
    assert settings is not None
    assert settings.port == 10443
    assert len(settings.authentication_rules) == 2
    portal = parsed.ssl_vpn_portals[0]
    assert portal.mac_address_check_rules[0].mac_addr == "00:11:22:33:44:55"
    assert portal.os_check_list[0].os_version == "11"
    assert portal.bookmark_groups[0].bookmarks[0].host == "10.0.0.10"
    assert portal.landing_pages[0].heading == "Welcome"

    ldap = {item.name: item for item in parsed.user_ldap_servers}
    assert ldap["simple-ldap"].has_password is True
    assert ldap["secure-ldap"].secure == "ldaps"
    assert ldap["secure-ldap"].schema == "active-directory"
    assert ldap["secure-ldap"].timeout == 5

    radius = parsed.radius_servers[0]
    assert (radius.secondary_server, radius.auth_port, radius.acct_port) == (
        "radius-2.example.test", 1812, 1813
    )
    assert radius.accounting_servers[0].port == 1813
    tacacs = parsed.tacacs_servers[0]
    assert (tacacs.secondary_server, tacacs.timeout, tacacs.connect_timeout) == (
        "tacacs-2.example.test", 10, 4
    )

    serialized = parsed.model_dump_json()
    for secret in ("LDAP_SECRET", "RADIUS_SECRET", "ACCOUNTING_SECRET", "TACACS_SECRET"):
        assert secret not in serialized


def test_phase2_coverage_is_typed_extract_only_for_both_modes():
    result = extract_fortigate_config(CONFIG)
    sections = {section.path: section for section in result.source_sections}
    for path in ("vpn ipsec phase2-interface", "vpn ipsec phase2"):
        assert sections[path].status == ExtractionStatus.EXTRACT_ONLY
        assert sections[path].object_count_source == sections[path].object_count_parsed
