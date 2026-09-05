from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_ipv6_policy_and_dual_stack_profile_references_are_typed():
    config = '''config firewall policy
    edit 26
        set srcaddr6 "v6-src"
        set dstaddr6 "v6-dst"
        set internet-service6 enable
        set av-profile "av"
        set webfilter-profile "web"
    next
    edit 27
        set srcaddr "v4-src"
        set srcaddr6 "v6-src"
        set ssl-ssh-profile "deep"
    next
end
'''
    policies = parse_fortigate_config(config).policies
    assert policies[0].address_family == "ipv6"
    assert policies[0].srcaddr6 == ["v6-src"]
    assert policies[0].dstaddr6 == ["v6-dst"]
    assert policies[0].av_profile == "av"
    assert policies[0].webfilter_profile == "web"
    assert policies[1].address_family == "dual-stack"
    assert policies[1].ssl_ssh_profile == "deep"


def test_access_proxy_nested_families_and_recursive_source_are_retained():
    config = '''config firewall access-proxy6
    edit "ztna6"
        set vip "vip6"
        set client-cert enable
        config realservers
            edit "server-a"
                set address "2001:db8::10"
                set port 8443
            next
        end
        config virtual-host
            edit "host-a"
                set host "app.example.test"
            next
        end
    next
end
'''
    parsed = parse_fortigate_config(config)
    proxy = parsed.access_proxies[0]
    assert proxy.family == "ipv6"
    assert proxy.client_cert == "enable"
    assert proxy.servers[0].address == "2001:db8::10"
    assert proxy.servers[0].port == 8443
    assert proxy.virtual_hosts[0].name == "host-a"
    assert proxy.nested_configs


def test_access_proxy_types_all_nested_object_families():
    parsed = parse_fortigate_config('''config firewall access-proxy
    edit "ztna"
        set port 443
        set srcintf "port1" "port2"
        config destinations
            edit "app-a"
                set server "backend-a"
                set protocol https
                set port 8443
                set ssl-min-proto-version tlsv1-2
            next
            edit "app-b"
                set host app-b.example.test
                set path /portal
            next
        end
        config realservers
            edit "backend-a"
                set address 192.0.2.10
                set port 8443
                set weight 10
            next
            edit "backend-b"
                set address 192.0.2.11
            next
        end
        config virtual-host
            edit "vh-a"
                set host app.example.test
                set ssl-certificate "cert-a"
                set ssl-min-proto-version tlsv1-2
                set alias app-alt.example.test
            next
            edit "vh-b"
                set host other.example.test
            next
        end
        config mappings
            edit "map-a"
                set source /api
                set destination app-a
                set virtual-host vh-a
                set realservers "backend-a" "backend-b"
                set url-map /v1
            next
        end
    next
end
''')
    proxy = parsed.access_proxies[0]
    assert proxy.port == 443
    assert proxy.srcintf == ["port1", "port2"]
    assert [item.name for item in proxy.destinations] == ["app-a", "app-b"]
    assert proxy.destinations[0].ssl_min_proto_version == "tlsv1-2"
    assert [item.name for item in proxy.servers] == ["backend-a", "backend-b"]
    assert proxy.servers[0].weight == 10
    assert [item.name for item in proxy.virtual_hosts] == ["vh-a", "vh-b"]
    assert proxy.virtual_hosts[0].ssl_certificate == "cert-a"
    assert proxy.virtual_hosts[0].alias == ["app-alt.example.test"]
    assert proxy.mappings[0].realservers == ["backend-a", "backend-b"]
    assert proxy.mappings[0].url_map == "/v1"


def test_top_level_certificates_ngfw_context_and_management_controls_are_safe():
    config = '''config system global
    set admin-http-port 80
    set admin-sport 443
    set admin-ssh-port 2222
    set admin-https-redirect enable
end
config system admin
    edit "audit"
        set ip6-trusthost1 2001:db8::/32
        set passwd "DO_NOT_SERIALIZE"
    next
end
config system settings
    set ngfw-mode policy-based
end
config firewall policy
    edit 1
        set srcaddr6 "all6"
    next
end
config certificate local
    edit "top-local"
        set password ENC SECRET
        set private-key "PRIVATE KEY SECRET"
        set certificate "PUBLIC CERTIFICATE"
    next
end
'''
    parsed = parse_fortigate_config(config)
    assert parsed.system_global.admin_http_port == 80
    assert parsed.system_global.admin_https_port == 443
    assert parsed.system_global.admin_ssh_port == 2222
    assert parsed.system_global.admin_https_redirect == "enable"
    assert parsed.administrators[0].ip6_trusthost1 == "2001:db8::/32"
    assert parsed.policies[0].ngfw_mode == "policy-based"
    assert parsed.policies[0].address_family == "ipv6"
    assert parsed.certificates[0].certificate_type == "local"
    serialized = parsed.model_dump_json()
    assert "DO_NOT_SERIALIZE" not in serialized
    assert "SECRET" not in serialized
    assert "PRIVATE KEY SECRET" not in serialized

    result = extract_fortigate_config(config)
    assert result.canonical_ir.execution_contexts[0].ngfw_mode == "policy-based"
    assert next(section for section in result.source_sections if section.path == "certificate local")
