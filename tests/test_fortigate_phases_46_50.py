from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_phase46_ips_uses_operation_aware_filter_and_signature_semantics() -> None:
    text = '''
config ips sensor
    edit "phase46"
        config entries
            edit 1
                set severity critical
                set severity high
                set application "Web.Client" "Web.Server"
                append application "Web.Other"
                set cve "CVE-2026-1"
                append cve "CVE-2026-2"
                unset severity
                set severity medium
                config exempt-ip
                    edit 10
                        set src-ip "192.0.2.0 255.255.255.0"
                    next
                    edit 20
                        set dst-ip "198.51.100.0 255.255.255.0"
                    next
                end
            next
            edit 2
                set rule 1001 1002 malformed-id
                append rule 1003
                set rate-count malformed-count
            next
        end
    next
end
'''
    fg = parse_fortigate_config(text)
    assert len(fg.ips_sensors) == 1
    filter_entry, signature_entry = fg.ips_sensors[0].entries

    assert filter_entry.rules == []
    assert filter_entry.signature_criteria.rule_ids == []
    assert filter_entry.selector_criteria.severity == ["medium"]
    assert filter_entry.selector_criteria.application == [
        "Web.Client", "Web.Server", "Web.Other",
    ]
    assert filter_entry.selector_criteria.cve == ["CVE-2026-1", "CVE-2026-2"]
    assert [item.id for item in filter_entry.exempt_ips] == [10, 20]

    assert signature_entry.rules == [1001, 1002, 1003]
    assert signature_entry.signature_criteria.rule_ids == [1001, 1002, 1003]
    assert signature_entry.selector_criteria.severity == []
    assert signature_entry.selector_criteria.cve == []
    assert signature_entry.extra_settings["unparsed_rule_values"] == ["malformed-id"]
    assert signature_entry.rate_count is None
    assert signature_entry.extra_settings["unparsed_rate_count"] == "malformed-count"

    result = extract_fortigate_config(text)
    item = next(
        item for item in result.inventory_items
        if item.source_path == "ips sensor" and item.name == "phase46"
    )
    entries_node = next(child for child in item.children if child.source_path.endswith(" entries"))
    filter_inventory = next(child for child in entries_node.children if child.name == "1")
    assert [command.operation for command in filter_inventory.commands] == [
        "set", "set", "set", "append", "set", "append", "unset", "set",
    ]


def test_phase47_ssl_ssh_uses_exact_hierarchy_and_shared_list_operations() -> None:
    text = '''
config firewall ssl-ssh-profile
    edit "deep"
        set caname "Fortinet_CA_SSL"
        set server-cert "server-cert-a"
        append server-cert "server-cert-b"
        config https
            set ports 443
            append ports 8443
            append ports 9443
            set cert-probe-failure block
        end
        config ssl-exempt
            edit 1
                set fortiguard-category 52
                set type fortiguard-category
            next
        end
        config ssl-server
            edit "mail.example.com"
                set ip "203.0.113.10"
                set smtps-client-certificate "mail-client-cert"
            next
        end
        config certificate-looking-future-section
            edit "future"
                set status enable
            next
        end
    next
    edit "cleared"
        config https
            set ports 443
            append ports 8443
            unset ports
        end
    next
end
'''
    fg = parse_fortigate_config(text)
    deep, cleared = fg.ssl_ssh_profiles

    assert deep.caname == "Fortinet_CA_SSL"
    assert deep.server_cert == ["server-cert-a", "server-cert-b"]
    assert deep.protocols[0].name == "https"
    assert deep.protocols[0].ports == ["443", "8443", "9443"]
    assert deep.protocols[0].cert_probe_failure == "block"
    assert deep.exemptions[0].fortiguard_category == 52
    assert deep.servers[0].ip == "203.0.113.10"
    assert deep.servers[0].smtps_client_certificate == "mail-client-cert"
    assert deep.certificates == []
    assert [entry.name for entry in deep.entries] == ["certificate-looking-future-section"]

    assert cleared.protocols[0].name == "https"
    assert cleared.protocols[0].ports == []


def test_phase48_profile_group_builds_dependency_for_every_effective_reference() -> None:
    text = '''
config firewall profile-group
    edit "corp"
        set av-profile "av"
        set dnsfilter-profile "dns"
        set webfilter-profile "web"
        set application-list "app"
        set ips-sensor "ips"
        set ssl-ssh-profile "deep"
        set emailfilter-profile "email"
        set file-filter-profile "file"
        set dlp-profile "dlp"
        set icap-profile "icap"
        set waf-profile "waf"
        set voip-profile "voip"
        set ips-voip-filter "ips-voip"
        set profile-protocol-options "proto"
        set ssh-filter-profile "ssh-filter"
        set sctp-filter-profile "sctp-filter"
        set diameter-filter-profile "diameter-filter"
        set videofilter-profile "video"
        set virtual-patch-profile "virtual-patch"
        set casb-profile "casb"
        set cifs-profile "cifs"
        set av-profile "av-replaced"
        unset cifs-profile
    next
end
'''
    result = extract_fortigate_config(text)
    group = result.canonical_ir.security_profile_groups[0]
    assert group.source_profile_references["av_profile"] == "av-replaced"
    assert "cifs_profile" not in group.source_profile_references
    assert group.source_profile_references["ips_voip_filter"] == "ips-voip"

    dependencies = {
        dependency.source_field: dependency
        for dependency in result.dependencies
        if dependency.source_path == "firewall profile-group"
        and dependency.source_object == "corp"
    }
    expected_fields = {
        "application-list", "av-profile", "casb-profile", "diameter-filter-profile",
        "dlp-profile", "dnsfilter-profile", "emailfilter-profile", "file-filter-profile",
        "icap-profile", "ips-sensor", "ips-voip-filter", "profile-protocol-options",
        "sctp-filter-profile", "ssh-filter-profile", "ssl-ssh-profile",
        "videofilter-profile", "virtual-patch-profile", "voip-profile", "waf-profile",
        "webfilter-profile",
    }
    assert set(dependencies) == expected_fields
    assert all(record.result == "UNRESOLVED" for record in dependencies.values())
    assert dependencies["ips-sensor"].expected_type == "ips sensor"
    assert dependencies["ssl-ssh-profile"].expected_type == "firewall ssl-ssh-profile"
    assert dependencies["ips-voip-filter"].expected_type == "voip profile"


def test_phase49_ipv6_interface_nested_operations_are_typed_and_prefixes_preserved() -> None:
    text = '''
config system interface
    edit "port1"
        config ipv6
            set ip6-address "2001:db8::1/64"
            set ip6-allowaccess ping
            append ip6-allowaccess https
            set dhcp6-relay-ip "2001:db8::53"
            append dhcp6-relay-ip "2001:db8::54"
            config ip6-extra-addr
                edit "2001:db8:10::1/64"
                next
            end
            config ip6-prefix-list
                edit "2001:db8:20::/64"
                    set dnssl "example.com"
                    append dnssl "corp.example.com"
                    set preferred-life-time 600
                    unset preferred-life-time
                    set valid-life-time 1200
                next
            end
            config dhcp6-iapd-list
                edit 7
                    set prefix-hint "2001:db8:30::/56"
                    set prefix-hint-plt malformed
                    set prefix-hint-vlt 3600
                next
            end
            config vrrp6
                edit 9
                    set vrip6 "2001:db8::9"
                    set priority 120
                next
            end
        end
    next
end
'''
    result = extract_fortigate_config(text)
    interface = result.canonical_ir.interfaces[0]
    assert interface.ipv6_address == "2001:db8::1/64"

    fg = parse_fortigate_config(text)
    source_interface = fg.interfaces[0]
    assert source_interface.ip6_address == "2001:db8::1/64"
    assert source_interface.ip6_allowaccess == ["ping", "https"]
    assert source_interface.dhcp6_relay_ip == ["2001:db8::53", "2001:db8::54"]
    assert source_interface.ipv6_extra_addresses[0].source_address == "2001:db8:10::1/64"
    prefix = source_interface.ipv6_prefix_advertisements[0]
    assert prefix.prefix == "2001:db8:20::/64"
    assert prefix.dnssl == ["example.com", "corp.example.com"]
    assert prefix.preferred_life_time is None
    assert prefix.valid_life_time == 1200
    iapd = source_interface.dhcp6_iapd[0]
    assert iapd.prefix_hint == "2001:db8:30::/56"
    assert iapd.prefix_hint_plt is None
    assert iapd.extra_settings["unparsed_prefix_hint_plt"] == "malformed"
    assert source_interface.vrrp6[0].vrid == 9
    assert source_interface.vrrp6[0].priority == 120

    ipv6_inventory = next(
        item for item in result.inventory_items
        if item.source_path.endswith(" interface ipv6")
    )
    assert ipv6_inventory.status == ExtractionStatus.NORMALIZED
    assert ipv6_inventory.requires_manual_review is False


def test_phase50_firewall_policy_keeps_address_families_independent() -> None:
    text = '''
config firewall policy
    edit 1
        set srcaddr "IPv4-A"
        set dstaddr "IPv4-B"
        set poolname "POOL4"
    next
    edit 2
        set srcaddr6 "IPv6-A"
        set dstaddr6 "IPv6-B"
        set poolname6 "POOL6"
    next
    edit 3
        set srcaddr "IPv4-C"
        set dstaddr "IPv4-D"
        set srcaddr6 "IPv6-C"
        set dstaddr6 "IPv6-D"
        set poolname "POOL4-C"
        set poolname6 "POOL6-C"
        set nat46 enable
        set nat64 enable
        set logtraffic all
    next
end
'''
    fg = parse_fortigate_config(text)
    ipv4, ipv6, dual = fg.policies

    assert ipv4.address_family == "ipv4"
    assert ipv4.srcaddr == ["IPv4-A"]
    assert ipv4.srcaddr6 == []
    assert ipv4.poolname == ["POOL4"]
    assert ipv4.poolname6 == []

    assert ipv6.address_family == "ipv6"
    assert ipv6.srcaddr == []
    assert ipv6.srcaddr6 == ["IPv6-A"]
    assert ipv6.poolname == []
    assert ipv6.poolname6 == ["POOL6"]

    assert dual.address_family == "dual-stack"
    assert dual.srcaddr == ["IPv4-C"]
    assert dual.srcaddr6 == ["IPv6-C"]
    assert dual.dstaddr == ["IPv4-D"]
    assert dual.dstaddr6 == ["IPv6-D"]
    assert dual.poolname == ["POOL4-C"]
    assert dual.poolname6 == ["POOL6-C"]
    assert dual.nat46 == "enable"
    assert dual.nat64 == "enable"
    assert dual.logtraffic == "all"
