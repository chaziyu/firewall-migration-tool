from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer


def test_system_interface_common_fields_are_typed_and_exact():
    config = """
config system interface
    edit "port1"
        set mtu-override enable
        set mtu 1400
        set tcp-mss 1360
        set estimated-upstream-bandwidth 100000
        set estimated-downstream-bandwidth 200000
        set link-up-delay 3
        set link-down-delay 4
        set preserve-session-route enable
        set stp disable
        set stp-ha-secondary enable
        set broadcast-forticlient-discovery disable
        set drop-overlapped-fragment enable
        set drop-fragment disable
        set explicit-web-proxy enable
    next
end
"""
    interface = parse_fortigate_config(config).interfaces[0]

    assert interface.mtu_override == "enable"
    assert interface.mtu == 1400
    assert interface.tcp_mss == 1360
    assert interface.estimated_upstream_bandwidth == 100000
    assert interface.estimated_downstream_bandwidth == 200000
    assert interface.link_up_delay == 3
    assert interface.link_down_delay == 4
    assert interface.preserve_session_route == "enable"
    assert interface.stp == "disable"
    assert interface.stp_ha_secondary == "enable"
    assert interface.broadcast_forticlient_discovery == "disable"
    assert interface.drop_overlapped_fragment == "enable"
    assert interface.drop_fragment == "disable"
    assert interface.explicit_web_proxy == "enable"


def test_system_interface_unset_clears_typed_values():
    config = """
config system interface
    edit "port1"
        set mtu-override enable
        set mtu 1400
        set tcp-mss 1360
        unset mtu
        unset mtu-override
        unset tcp-mss
    next
end
"""
    interface = parse_fortigate_config(config).interfaces[0]

    assert interface.mtu is None
    assert interface.mtu_override is None
    assert interface.tcp_mss is None


def test_missing_mtu_does_not_invent_a_value():
    interface = parse_fortigate_config(
        'config system interface\n    edit "port1"\n    next\nend\n'
    ).interfaces[0]

    assert interface.mtu is None


def test_mtu_maps_to_ir_and_disable_stays_explicit():
    config = """
config system interface
    edit "port1"
        set mtu-override disable
        set mtu 1400
    next
end
"""
    ir_interface = FGToIRTransformer(
        parse_fortigate_config(config)
    ).transform().interfaces[0]

    assert ir_interface.mtu == 1400
    assert ir_interface.source_attributes["mtu_override"] == "disable"
