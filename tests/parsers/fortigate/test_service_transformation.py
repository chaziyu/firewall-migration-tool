import pytest

from fwmigrate.ir.enums import ServiceProtocol
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.model import FGConfig, FGService, FGServiceGroup
from fwmigrate.parsers.fortigate.parser import FortiGateParser
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.parsers.fortigate.transformer import (
    FGToIRTransformer,
    parse_fortigate_service_port_ranges,
)


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("443", [("443", None)]),
        ("80-90", [("80-90", None)]),
        ("443:1024", [("443", "1024")]),
        ("443:1024-65535", [("443", "1024-65535")]),
        ("80-90:1024-65535", [("80-90", "1024-65535")]),
        (
            "80 443 8000-8080",
            [("80", None), ("443", None), ("8000-8080", None)],
        ),
    ],
)
def test_fortigate_service_port_expressions_are_transformer_owned(
    expression, expected
):
    ports, errors = parse_fortigate_service_port_ranges(
        expression, ServiceProtocol.TCP
    )

    assert not errors
    assert [(port.port, port.source_port) for port in ports] == expected
    assert [port.raw_source_value for port in ports] == expression.split()


@pytest.mark.parametrize(
    "expression", ["70000", "90-80", "abc", "443:", ":1024", "443:90000"]
)
def test_malformed_fortigate_service_ports_fail_closed(expression):
    ir = FGToIRTransformer(
        FGConfig(
            services=[
                FGService(
                    name="bad-service",
                    protocol="TCP",
                    tcp_portrange=expression,
                )
            ]
        )
    ).transform()

    service = ir.services[0]
    assert service.ports[0].raw_source_value == expression
    assert service.requires_manual_review is True
    assert service.migration_status == "PARTIALLY_NORMALIZED"
    assert expression in service.audit_note
    assert any(expression in entry.message for entry in ir.audit_entries)
    assert service.ports[0].port != "any"


def _transform_service(**values):
    return FGToIRTransformer(
        FGConfig(services=[FGService(name="svc", **values)])
    ).transform().services[0]


def test_service_without_protocol_uses_fortios_default_without_changing_source():
    service = _transform_service(tcp_portrange="443")

    assert service.source_protocol_configured is None
    assert service.source_protocol == "TCP/UDP/SCTP"
    assert [(port.protocol, port.port) for port in service.ports] == [
        (ServiceProtocol.TCP, "443")
    ]
    assert service.requires_manual_review is False


@pytest.mark.parametrize(
    ("protocol", "field", "expected"),
    [
        ("TCP", "tcp_portrange", ServiceProtocol.TCP),
        ("UDP", "udp_portrange", ServiceProtocol.UDP),
        ("SCTP", "sctp_portrange", ServiceProtocol.SCTP),
    ],
)
def test_explicit_transport_protocols_are_normalized(protocol, field, expected):
    service = _transform_service(protocol=protocol, **{field: "443"})

    assert service.source_protocol_configured == protocol
    assert service.source_protocol == protocol
    assert service.ports[0].protocol == expected


@pytest.mark.parametrize(
    ("protocol", "expected", "values"),
    [
        ("ICMP", ServiceProtocol.ICMP, {"icmptype": 8, "icmpcode": 0}),
        ("ICMP6", ServiceProtocol.ICMPV6, {"icmptype": 128, "icmpcode": 0}),
        ("IP", ServiceProtocol.IP, {"protocol_number": 47}),
    ],
)
def test_non_transport_protocols_keep_canonical_semantics(protocol, expected, values):
    service = _transform_service(protocol=protocol, **values)

    assert service.source_protocol_configured == protocol
    assert service.source_protocol == protocol
    assert service.ports[0].protocol == expected
    assert service.requires_manual_review is False


@pytest.mark.parametrize(
    "protocol", ["HTTP", "FTP", "CONNECT", "SOCKS-TCP", "SOCKS-UDP", "ALL"]
)
def test_proxy_protocols_are_not_mapped_to_tcp(protocol):
    service = _transform_service(protocol=protocol, tcp_portrange="80")

    assert service.source_protocol == protocol
    assert service.ports == []
    assert service.requires_manual_review is True
    assert service.migration_status == "VENDOR_EXTENSION"
    assert protocol in service.audit_note


def test_unknown_future_protocol_fails_closed_without_crashing():
    service = _transform_service(protocol="QUIC-FUTURE", tcp_portrange="443")

    assert service.source_protocol == "QUIC-FUTURE"
    assert service.ports == []
    assert service.requires_manual_review is True
    assert service.migration_status == "PARTIALLY_NORMALIZED"
    assert "Unknown FortiGate service protocol" in service.audit_note


def test_fortigate_service_transport_fields_are_independent():
    ir = FGToIRTransformer(
        FGConfig(
            services=[
                FGService(
                    name="mixed",
                    protocol="TCP/UDP/SCTP",
                    tcp_portrange="80 443:1024-65535 80",
                    udp_portrange="53, 53",
                    sctp_portrange="5000 5000",
                ),
                FGService(name="udp-only", protocol="UDP", udp_portrange="53"),
                FGService(name="sctp-only", protocol="SCTP", sctp_portrange="5000"),
                FGService(name="empty-tcp", protocol="TCP", tcp_portrange=""),
            ]
        )
    ).transform()

    assert [
        (port.protocol, port.port, port.source_port)
        for port in ir.services[0].ports
    ] == [
        (ServiceProtocol.TCP, "80", None),
        (ServiceProtocol.TCP, "443", "1024-65535"),
        (ServiceProtocol.UDP, "53", None),
        (ServiceProtocol.SCTP, "5000", None),
    ]
    assert [(port.protocol, port.port) for port in ir.services[1].ports] == [
        (ServiceProtocol.UDP, "53")
    ]
    assert [(port.protocol, port.port) for port in ir.services[2].ports] == [
        (ServiceProtocol.SCTP, "5000")
    ]
    assert ir.services[3].ports == []


def test_unmodeled_fortigate_service_semantics_survive_to_canonical_review():
    source = """
config firewall service custom
    edit "classified"
        set tcp-portrange 443
        set helper sip
        set fqdn service.example.test
        set iprange 192.0.2.10 192.0.2.20
        set application 42
        set app-category 7 8
        set app-service-type app-id
        set check-reset-range strict
        set session-ttl 120
        set tcp-halfclose-timer 10
        set tcp-halfopen-timer 20
        set tcp-rst-timer 30
        set tcp-timewait-timer 40
        set udp-idle-timer 50
        set proxy disable
        set fabric-object enable
        set color 3
    next
end
"""

    parsed = FortiGateParser(FortiGateTokenizer(source)).parse().services[0]
    assert parsed.extra_settings["helper"] == "sip"
    assert parsed.extra_settings["app_service_type"] == "app-id"
    assert parsed.tcp_halfclose_timer == 10

    result = extract_fortigate_config(source)
    service = result.canonical_ir.services[0]

    assert {
        "helper", "fqdn", "iprange", "application", "app_category",
        "app_service_type", "check_reset_range", "session_ttl",
        "tcp_halfclose_timer", "tcp_halfopen_timer", "tcp_rst_timer",
        "tcp_timewait_timer", "udp_idle_timer",
    } <= set(service.source_unmodeled_semantic_settings)
    assert service.source_attributes["helper"] == "sip"
    assert service.source_attributes["session_ttl"] == "120"
    assert service.source_attributes["tcp_halfclose_timer"] == 10
    assert service.source_fabric_object == "enable"
    assert service.source_color == 3
    assert service.requires_manual_review is True
    assert result.canonical_ir.requires_manual_review is True
    assert "Unsupported traffic-affecting FortiGate service semantics" in service.audit_note


def test_service_metadata_does_not_become_unmodeled_traffic_semantics():
    service = _transform_service(
        tcp_portrange="443",
        proxy="disable",
        fabric_object="enable",
        color=3,
    )

    assert service.source_unmodeled_semantic_settings == []
    assert service.source_proxy is False
    assert service.source_fabric_object == "enable"
    assert service.source_color == 3
    assert service.requires_manual_review is False


def test_service_group_members_resolve_without_flattening_or_dropping_names():
    ir = FGToIRTransformer(
        FGConfig(
            services=[FGService(name="custom", protocol="TCP", tcp_portrange="443")],
            service_groups=[
                FGServiceGroup(name="nested", member=["custom"]),
                FGServiceGroup(
                    name="outer",
                    member=["custom", "nested", "HTTP", "Web Access", "missing"],
                ),
            ],
        )
    ).transform()

    outer = next(group for group in ir.service_groups if group.name == "outer")
    assert outer.members == ["custom", "nested", "HTTP", "Web Access", "missing"]
    assert outer.unsafe_members == ["missing"]
    assert outer.requires_manual_review is True
    assert outer.migration_status == "PARTIALLY_NORMALIZED"
    assert "missing" in outer.audit_note


def _transform_service_groups(*groups, services=()):
    return FGToIRTransformer(
        FGConfig(services=list(services), service_groups=list(groups))
    ).transform().service_groups


def test_service_group_graph_accepts_simple_service_member():
    group = _transform_service_groups(
        FGServiceGroup(name="web", member=["https"]),
        services=[FGService(name="https", protocol="TCP", tcp_portrange="443")],
    )[0]

    assert group.members == ["https"]
    assert group.unsafe_members == []
    assert group.requires_manual_review is False


def test_service_group_graph_accepts_nested_groups():
    groups = _transform_service_groups(
        FGServiceGroup(name="inner", member=["https"]),
        FGServiceGroup(name="outer", member=["inner"]),
        services=[FGService(name="https", protocol="TCP", tcp_portrange="443")],
    )

    assert [(group.name, group.members, group.unsafe_members) for group in groups] == [
        ("inner", ["https"], []),
        ("outer", ["inner"], []),
    ]


def test_service_group_graph_detects_self_reference():
    group = _transform_service_groups(FGServiceGroup(name="loop", member=["loop"]))[0]

    assert group.members == ["loop"]
    assert group.unsafe_members == ["loop"]
    assert "self-referencing" in group.audit_note


def test_service_group_graph_detects_two_node_cycle():
    groups = _transform_service_groups(
        FGServiceGroup(name="a", member=["b"]),
        FGServiceGroup(name="b", member=["a"]),
    )

    assert all(group.requires_manual_review for group in groups)
    assert all("cyclic service-group" in group.audit_note for group in groups)


def test_service_group_graph_detects_three_node_cycle():
    groups = _transform_service_groups(
        FGServiceGroup(name="a", member=["b"]),
        FGServiceGroup(name="b", member=["c"]),
        FGServiceGroup(name="c", member=["a"]),
    )

    assert [group.unsafe_members for group in groups] == [["b"], ["c"], ["a"]]
    assert all("a -> b -> c -> a" in group.audit_note for group in groups)


def test_service_group_graph_detects_missing_member():
    group = _transform_service_groups(
        FGServiceGroup(name="web", member=["missing"])
    )[0]

    assert group.unsafe_members == ["missing"]
    assert "unresolved service/service-group" in group.audit_note


def test_service_group_graph_preserves_duplicate_member_as_warning():
    group = _transform_service_groups(
        FGServiceGroup(name="web", member=["https", "https"]),
        services=[FGService(name="https", protocol="TCP", tcp_portrange="443")],
    )[0]

    assert group.members == ["https", "https"]
    assert group.unsafe_members == []
    assert group.requires_manual_review is False
    assert "duplicate service-group member(s) preserved" in group.audit_note


def test_service_group_graph_detects_ambiguous_service_and_group_member():
    group = _transform_service_groups(
        FGServiceGroup(name="shared", member=[]),
        FGServiceGroup(name="outer", member=["shared"]),
        services=[FGService(name="shared", protocol="TCP", tcp_portrange="443")],
    )[1]

    assert group.unsafe_members == ["shared"]
    assert "ambiguous service/service-group" in group.audit_note
