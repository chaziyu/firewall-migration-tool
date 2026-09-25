from fwmigrate.vendors.fortigate.extraction.coverage import typed_source_paths
from fwmigrate.vendors.fortigate.section_registry import registered_sections


def test_selected_source_paths_are_registered_and_typed():
    selected_paths = {
        "router static6", "firewall ippool6", "firewall vip6", "firewall vipgrp6",
        "vpn ipsec phase1", "vpn ipsec phase2", "firewall security-policy",
        "firewall profile-protocol-options", "firewall shaper per-ip-shaper",
        "system session-helper", "vpn ssl web realm", "vpn ssl web user-bookmark",
        "vpn ssl web user-group-bookmark", "vpn ssl client", "user nac-policy",
        "firewall address6-template", "ips settings", "vpn kmip-server",
        "user krb-keytab", "router setting", "system sdn-proxy",
        "firewall on-demand-sniffer", "system affinity-interrupt", "system serial-port",
        "firewall region", "firewall vendor-mac",
    }
    registered = set(registered_sections())
    typed = typed_source_paths()

    assert selected_paths <= registered
    assert selected_paths <= typed
