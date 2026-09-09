from fwmigrate.parsers.fortigate.parser import parse_fortigate_config


def test_l2tp_interface_block_is_typed_and_unknown_blocks_remain_raw():
    config = """
config system interface
    edit "port1"
        config l2tp-client-settings
            set user "vpn-user"
            set password "do-not-retain"
            set peer-host "vpn.example.test"
            set mtu 1400
        end
        config future-network-settings
            set keep-source-route enable
        end
    next
end
"""
    interface = parse_fortigate_config(config).interfaces[0]

    assert interface.l2tp_client_settings.user == "vpn-user"
    assert interface.l2tp_client_settings.peer_host == "vpn.example.test"
    assert interface.l2tp_client_settings.mtu == 1400
    assert interface.l2tp_client_settings.has_password is True
    assert "do-not-retain" not in interface.model_dump_json()

    unknown = next(node for node in interface.nested_configs if node.name == "future-network-settings")
    assert unknown.commands[0].key == "keep-source-route"
    assert unknown.commands[0].values == ["enable"]
