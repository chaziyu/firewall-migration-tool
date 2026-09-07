from fwmigrate.parsers.fortigate.parser import (
    SECTION_LIST_FIELDS,
    parse_fortigate_config,
)


def _by_name(items):
    return {item.name: item for item in items}


def test_phase26_service_protocols_and_multiple_port_ranges_are_typed():
    config = parse_fortigate_config('''
config firewall service custom
    edit "TCP UDP SCTP"
        set protocol TCP/UDP/SCTP
        set tcp-portrange "443 8443 9000-9002:1024-65535"
        set udp-portrange 53 5353-5355
        set sctp-portrange "3868 3869"
    next
    edit "ICMP Echo"
        set protocol ICMP
        set icmptype 8
        set icmpcode 0
    next
    edit "ICMP6 Echo"
        set protocol ICMP6
        set icmptype 128
        set icmpcode 0
    next
    edit "GRE Numeric"
        set protocol IP
        set protocol-number 47
    next
end
''')

    services = _by_name(config.services)
    transport = services["TCP UDP SCTP"]

    assert [item.original for item in transport.tcp_port_ranges] == [
        "443", "8443", "9000-9002:1024-65535"
    ]
    assert [item.port for item in transport.tcp_port_ranges[:2]] == [443, 8443]
    qualified = transport.tcp_port_ranges[2]
    assert (
        qualified.destination_start,
        qualified.destination_end,
        qualified.source_start,
        qualified.source_end,
    ) == (9000, 9002, 1024, 65535)

    assert [item.original for item in transport.udp_port_ranges] == [
        "53", "5353-5355"
    ]
    assert [item.original for item in transport.sctp_port_ranges] == [
        "3868", "3869"
    ]

    assert services["ICMP Echo"].protocol == "ICMP"
    assert services["ICMP Echo"].icmptype == 8
    assert services["ICMP Echo"].icmpcode == 0
    assert services["ICMP6 Echo"].protocol == "ICMP6"
    assert services["ICMP6 Echo"].icmptype == 128
    assert services["ICMP6 Echo"].icmpcode == 0
    assert services["GRE Numeric"].protocol == "IP"
    assert services["GRE Numeric"].protocol_number == 47


def test_phase26_malformed_numeric_protocol_fields_remain_visible():
    config = parse_fortigate_config('''
config firewall service custom
    edit "future-protocol"
        set protocol IP
        set protocol-number not-a-number
        set icmptype invalid-type
        set icmpcode invalid-code
    next
end
''')

    service = config.services[0]
    assert service.protocol_number is None
    assert service.icmptype is None
    assert service.icmpcode is None
    assert service.extra_settings == {
        "unparsed_protocol_number": "not-a-number",
        "unparsed_icmptype": "invalid-type",
        "unparsed_icmpcode": "invalid-code",
    }


def test_phase27_service_group_set_and_append_preserve_member_order():
    config = parse_fortigate_config('''
config firewall service group
    edit "ordered group"
        set member "HTTPS" "DNS"
        append member "unknown service"
        append member "SSH"
    next
end
''')

    group = config.service_groups[0]
    assert "member" in SECTION_LIST_FIELDS["firewall service group"]
    assert group.member == ["HTTPS", "DNS", "unknown service", "SSH"]
    assert group.comment is None
    assert group.extra_settings == {}


def test_phase27_service_group_unset_clears_then_append_keeps_unresolved_names():
    config = parse_fortigate_config('''
config firewall service group
    edit "mutated group"
        set member "HTTPS" "DNS"
        unset member
        append member "DNS"
        append member "does not exist"
        set comment "ordered references"
        set proxy enable
        set fabric-object disable
        set color 7
    next
end
''')

    group = config.service_groups[0]
    assert group.member == ["DNS", "does not exist"]
    assert group.comment == "ordered references"
    assert group.proxy == "enable"
    assert group.fabric_object == "disable"
    assert group.color == 7
    assert group.extra_settings == {"source_unset_settings": ["member"]}
