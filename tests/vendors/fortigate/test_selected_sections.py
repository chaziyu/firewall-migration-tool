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


def test_wifi_switch_and_nac_parity_fields_preserve_source_values_and_redact_secrets():
    analysis = _analysis('''config wireless-controller wtp-profile
    edit "FAP231F-custom"
        set ap-country US
        set dtls-policy clear-text
        set login-passwd SUPER_SECRET_AP_PWD
        set comment "Office profile"
        config platform
            set type 231F
        end
    next
end
config wireless-controller wtp
    edit "FP231F-01"
        set admin disable
        set wtp-profile "FAP231F-custom"
        set location "Floor 2"
        set comment "Lobby AP"
        set login-passwd SUPER_SECRET_WTP_PWD
    next
    edit "FP231F-02"
        set wtp-profile "MISSING-PROFILE"
    next
end
config wireless-controller vap
    edit "Corp-SSID"
        set ssid "CorpNet"
        set local-bridging enable
        set vlanid 120
        set security wpa2-only-personal
        set schedule "always"
        set status enable
        set passphrase SUPER_SECRET_WIFI_PASS
    next
end
config wireless-controller wids-profile
    edit "wids-strict"
        set ap-scan enable
        set sensor-mode foreign
        set comment "Rogue detection"
    next
end
config switch-controller managed-switch
    edit "S248E-01"
        set name "Core-SW1"
        set switch-group "Floor-Switches"
        set status enable
        set platform FS-248E
        set sn "S248EF123456"
        set firmware-provision-version "7.4.3"
    next
end
config switch-controller port-policy
    edit "dot1x-port"
        set user-group "staff"
        set guest-vlan "guest-vlan"
        set guest-auth-delay 45
        set mac-auth-bypass enable
        set eap-passthru enable
        set radius-timeout-overwrite enable
    next
end
config switch-controller nac-settings
    set mode local
    set onboarding-vlan "onboarding"
    set hw-vendor "Apple"
    set assign-vlan 200
    set matched-devices 5
end
config user nac-policy
    edit "corp-mac"
        set hw-vendor "Cisco"
        set assign-vlan 300
        set matched-devices 12
        set status enable
    next
end
''')
    config = analysis.extracted.config
    assert config.wtp_profiles[0].platform == "231F"
    assert config.wtp_profiles[0].platform_config.type == "231F"
    assert config.wtp_profiles[0].login_passwd_configured is True
    assert config.wireless_wtps[0].admin == "disable"
    assert config.wireless_wtps[0].location == "Floor 2"
    assert config.wireless_wtps[0].login_passwd_configured is True
    assert config.wireless_vaps[0].local_bridging == "enable"
    assert config.wireless_vaps[0].schedule == "always"
    assert config.wireless_vaps[0].passphrase_configured is True
    assert config.wids_profiles[0].ap_scan == "enable"
    assert config.managed_switches[0].switch_group == "Floor-Switches"
    assert config.managed_switches[0].status == "enable"
    assert config.managed_switches[0].platform == "FS-248E"
    assert config.managed_switches[0].firmware_provision_version == "7.4.3"
    assert config.switch_port_policies[0].user_group == ["staff"]
    assert config.switch_port_policies[0].guest_vlan == "guest-vlan"
    assert config.switch_port_policies[0].guest_auth_delay == 45
    assert config.switch_port_policies[0].mac_auth_bypass == "enable"
    assert config.switch_port_policies[0].eap_passthru == "enable"
    assert config.switch_port_policies[0].radius_timeout_overwrite == "enable"
    assert len(config.nac_policies) == 2
    assert config.nac_policies[0].assign_vlan == "300"
    assert config.nac_policies[0].matched_devices == 12
    assert config.nac_policies[1].source_path == "switch-controller nac-settings"
    assert config.nac_policies[1].assign_vlan == "200"
    assert config.nac_policies[1].matched_devices == 5
    serialized = str(config.model_dump())
    assert "SUPER_SECRET_" not in serialized
    assert any(
        ref.source_kind == "wireless_wtp" and ref.reference == "MISSING-PROFILE"
        for ref in analysis.derived.broken_references
    )


def test_sdwan_extracts_nested_sla_thresholds_and_rule_ports_without_defaults():
    analysis = _analysis('''config system sdwan
    set status enable
    config zone
        edit "virtual-wan-link"
        next
    end
    config members
        edit 1
            set interface "wan1"
            set gateway 192.0.2.1
            set status enable
        next
    end
    config health-check
        edit "PingCheck"
            set server "8.8.8.8"
            set protocol ping
            set members 1
            config sla
                edit 1
                    set latency-threshold 300
                    set jitter-threshold 40
                    set packetloss-threshold 5
                next
            end
        next
        edit "DnsCheck"
            set system-dns enable
        next
    end
    config service
        edit 1
            set name "VideoConferencing"
            set mode priority
            set link-cost-factor bibandwidth
            set protocol 17
            set start-port 5000
            set end-port 5010
            set health-check "PingCheck"
            set priority-members 1
            set status enable
        next
    end
end
''')
    sdwan = analysis.extracted.config.sdwans[0]
    assert sdwan.status == "enable"
    hc = sdwan.health_checks[0]
    assert hc.sla[0].latency_threshold == 300
    assert hc.sla[0].jitter_threshold == 40
    assert hc.sla[0].packetloss_threshold == 5
    assert sdwan.health_checks[1].system_dns == "enable"
    assert sdwan.health_checks[1].protocol is None
    svc = sdwan.services[0]
    assert svc.link_cost_factor == "bibandwidth"
    assert svc.protocol == 17
    assert svc.start_port == 5000
    assert svc.end_port == 5010
