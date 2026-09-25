from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


def _analysis(source):
    return FortiGateSourceReporter().analyze_source(source)


def test_address6_template_preserves_nested_segments():
    config = _analysis('''config firewall address6-template
    edit lan-template
        set ip6 2001:db8::/48
        config subnet-segment
            edit 1
                set bits 16
                set name site
                config values
                    edit main
                        set value 10
                    next
                end
            next
        end
    next
end
''').extracted.config

    assert config.address6_templates[0].segments[0].values[0].value == "10"


def test_nac_policy_keeps_source_references():
    analysis = _analysis('''config user nac-policy
    edit known-device
        set firewall-address addr
        set user-group staff
    next
end
config firewall address
    edit addr
        set subnet 192.0.2.1 255.255.255.255
    next
end
config user group
    edit staff
        set group-type firewall
    next
end
''')

    assert analysis.extracted.config.nac_policies[0].firewall_address == "addr"
    assert analysis.extracted.config.nac_policies[0].user_group == "staff"
    assert not analysis.derived.broken_references


def test_selected_system_sections_keep_source_values():
    config = _analysis('''config ips settings
    set ips-packet-quota 100
    set packet-log-history 30
end
config router setting
    set hostname edge-a
    set show-filter routes
end
config firewall on-demand-sniffer
    edit capture
        set hosts 192.0.2.10
        set interface port1
        set max-packet-count 100
        set ports 80 443
        set protocols 6 17
    next
end
config system affinity-interrupt
    edit 5
        set interrupt irq5
        set affinity-cpumask 0x03
    next
end
config system serial-port
    edit console
    next
end
config firewall region
    edit 7
        set name region-a
        set city 3 4
    next
end
config firewall vendor-mac
    edit 100
        set name vendor-a
        set mac-number 200
        set obsolete 0
    next
end
config system session-helper
    edit 18
        set name ftp
        set protocol 6
        set port 2121
        set future-setting preserve-me
    next
end
''').extracted.config

    assert config.ips_settings[0].ips_packet_quota == 100
    assert config.router_settings[0].hostname == "edge-a"
    assert (config.on_demand_sniffers[0].hosts, config.on_demand_sniffers[0].interface) == ("192.0.2.10", "port1")
    assert config.on_demand_sniffers[0].max_packet_count == 100
    assert config.on_demand_sniffers[0].ports == [80, 443]
    assert config.affinity_interrupts[0].id == 5
    assert config.serial_ports[0].name == "console"
    assert config.firewall_regions[0].city == [3, 4]
    assert config.vendor_macs[0].mac_number == 200
    helper = config.session_helpers[0]
    assert (helper.id, helper.name, helper.protocol, helper.port) == (18, "ftp", 6, 2121)
    assert helper.raw_extra["future-setting"] == "preserve-me"


def test_selected_secret_models_expose_presence_flags_only():
    config = _analysis('''config vpn kmip-server
    edit kmip
        set password kmip-secret
        config server-list
            edit 1
                set server kmip.example.test
                set port 5696
            next
        end
    next
end
config user krb-keytab
    edit service-account
        set principal svc/example
        set ldap-server ldap1
        set keytab keytab-secret
    next
end
config system sdn-proxy
    edit cloud
        set password proxy-secret
        set server proxy.example.test
        set server-port 443
    next
end
''').extracted.config

    assert config.kmip_servers[0].password_configured
    assert (config.kmip_servers[0].server_list[0].server, config.kmip_servers[0].server_list[0].port) == (
        "kmip.example.test", 5696
    )
    assert config.kerberos_keytabs[0].keytab_configured
    assert (config.kerberos_keytabs[0].principal, config.kerberos_keytabs[0].ldap_server) == (
        "svc/example", ["ldap1"]
    )
    assert config.sdn_proxies[0].password_configured
    assert (config.sdn_proxies[0].server, config.sdn_proxies[0].server_port) == ("proxy.example.test", 443)
