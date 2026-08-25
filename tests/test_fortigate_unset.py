from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


UNSET_CONFIG = '''config system global
    set timezone 28
    unset timezone
end
config system dns
    set primary 8.8.8.8
    set protocol dot
    unset primary
    unset protocol
end
config web-proxy global
    set proxy-fqdn "proxy.example.com"
    set unknown-safe enabled
    unset proxy-fqdn
    unset unknown-safe
end
config system sdwan
    set status enable
    set load-balance-mode source-ip-based
    set duplicate-max-num 3
    unset status
    unset load-balance-mode
    unset duplicate-max-num
end
config vpn ssl settings
    set servercert "VPN_CERT"
    set banned-cipher RSA
    set source-interface "wan1"
    set unknown-safe enabled
    unset servercert
    unset banned-cipher
    unset source-interface
    unset unknown-safe
end
config firewall proxy-address
    edit "nested-unset"
        set host-regex "abc"
        unset host-regex
    next
end
'''


def test_global_and_nested_unset_clear_effective_state_but_preserve_history():
    fg = parse_fortigate_config(UNSET_CONFIG)
    assert fg.system_global.timezone is None
    assert fg.dns.primary is None
    assert "protocol" not in fg.dns.extra_settings
    assert fg.web_proxy_global.proxy_fqdn is None
    assert "unknown_safe" not in fg.web_proxy_global.extra_settings
    assert fg.sdwan.status == "disable"
    assert fg.sdwan.load_balance_mode is None
    assert "duplicate_max_num" not in fg.sdwan.extra_settings
    assert fg.ssl_vpn_settings.servercert is None
    assert fg.ssl_vpn_settings.banned_cipher == []
    assert fg.ssl_vpn_settings.source_interface == []
    assert "unknown_safe" not in fg.ssl_vpn_settings.extra_settings
    assert fg.proxy_addresses[0].host_regex is None

    result = extract_fortigate_config(UNSET_CONFIG)
    unset_paths = {
        item.source_path
        for item in result.inventory_items
        if any(command.operation == "unset" for command in item.commands)
    }
    assert {
        "system global",
        "system dns",
        "web-proxy global",
        "system sdwan",
        "vpn ssl settings",
        "firewall proxy-address",
    } <= unset_paths

    proxy_item = next(
        item for item in result.inventory_items
        if item.source_path == "firewall proxy-address"
    )
    assert [(command.operation, command.key) for command in proxy_item.commands] == [
        ("set", "host-regex"),
        ("unset", "host-regex"),
    ]
