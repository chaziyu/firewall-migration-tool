import pytest
from fwmigrate.parsers.checkpoint.models import CheckPointResponse
from fwmigrate.parsers.checkpoint.resolver import CheckPointObjectResolver
from fwmigrate.parsers.checkpoint.services import extract_service_objects, IR_KEYWORD_ANY
from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.ir.enums import ServiceProtocol


def test_extract_tcp_udp_sctp_icmp_services():
    resolver = CheckPointObjectResolver()
    responses = [
        CheckPointResponse(
            command="show-services-tcp",
            data={
                "objects": [
                    {
                        "uid": "uid-s-tcp",
                        "name": "HTTPS_443",
                        "type": "service-tcp",
                        "port": "443",
                        "session-timeout": 3600
                    }
                ]
            }
        ),
        CheckPointResponse(
            command="show-services-udp",
            data={
                "objects": [
                    {
                        "uid": "uid-s-udp",
                        "name": "DNS_53",
                        "type": "service-udp",
                        "port": "53"
                    }
                ]
            }
        ),
        CheckPointResponse(
            command="show-services-icmp",
            data={
                "objects": [
                    {
                        "uid": "uid-s-icmp",
                        "name": "Echo_Request",
                        "type": "service-icmp",
                        "icmp-type": 8,
                        "icmp-code": 0
                    }
                ]
            }
        )
    ]

    svcs, grps, items, unsupp = extract_service_objects(responses, resolver)

    assert len(svcs) == 3
    assert len(grps) == 0
    assert len(unsupp) == 0

    s_tcp = next(s for s in svcs if s.name == "HTTPS_443")
    assert s_tcp.ports[0].protocol == ServiceProtocol.TCP
    assert s_tcp.ports[0].port == "443"

    s_icmp = next(s for s in svcs if s.name == "Echo_Request")
    assert s_icmp.ports[0].protocol == ServiceProtocol.ICMP
    assert s_icmp.ports[0].port == IR_KEYWORD_ANY
    assert s_icmp.ports[0].icmptype == 8


def test_missing_tcp_port_does_not_fallback_to_any():
    resolver = CheckPointObjectResolver()
    responses = [
        CheckPointResponse(
            command="show-services-tcp",
            data={
                "objects": [
                    {
                        "uid": "uid-bad-tcp",
                        "name": "TCP_No_Port",
                        "type": "service-tcp",
                    }
                ]
            }
        )
    ]

    svcs, grps, items, unsupp = extract_service_objects(responses, resolver)

    assert len(svcs) == 0
    assert len(items) == 1
    assert items[0].status == ExtractionStatus.PARTIALLY_NORMALIZED
    assert items[0].requires_manual_review
    res = resolver.resolve("uid-bad-tcp")
    assert not res.usable_in_canonical_reference


def test_specialized_rpc_and_service_groups():
    resolver = CheckPointObjectResolver()
    responses = [
        CheckPointResponse(
            command="show-services-other",
            data={
                "objects": [
                    {
                        "uid": "uid-s-rpc",
                        "name": "Custom_RPC",
                        "type": "service-rpc",
                        "program-number": 100001
                    }
                ]
            }
        ),
        CheckPointResponse(
            command="show-service-groups",
            data={
                "objects": [
                    {
                        "uid": "uid-s-grp",
                        "name": "Grp_Web_Services",
                        "type": "service-group",
                        "members": ["HTTPS_443"]
                    }
                ]
            }
        )
    ]

    svcs, grps, items, unsupp = extract_service_objects(responses, resolver)

    assert len(unsupp) == 1
    assert unsupp[0].source_name == "Custom_RPC"
    assert len(grps) == 1
    assert grps[0].name == "Grp_Web_Services"


@pytest.mark.parametrize("extra,expected_setting", [
    ({"match": "dport=17"}, "match"),
    ({"accept-replies": True}, "accept-replies"),
])
def test_service_other_unmodeled_semantics_taint_dependency(extra, expected_setting):
    obj = {"uid": "other", "name": "Other17", "type": "service-other", "ip-protocol": 17, **extra}
    services, _, items, _ = extract_service_objects([
        CheckPointResponse(command="show-services-other", data={"objects": [obj]})
    ], CheckPointObjectResolver())
    assert services[0].source_protocol_number == 17
    assert services[0].requires_manual_review
    assert f"unmodeled-service-setting:{expected_setting}" in items[0].notes


def test_zero_protocol_and_icmp_values_are_preserved():
    services, _, _, _ = extract_service_objects([
        CheckPointResponse(command="show-services-other", data={"objects": [{
            "uid": "proto-zero", "name": "ProtoZero", "type": "service-other", "ip-protocol": 0,
        }]}),
        CheckPointResponse(command="show-services-icmp", data={"objects": [{
            "uid": "icmp-zero", "name": "ICMPZero", "type": "service-icmp",
            "icmp-type": 0, "icmp-code": 0,
        }]}),
    ], CheckPointObjectResolver())
    assert next(item for item in services if item.name == "ProtoZero").source_protocol_number == 0
    icmp = next(item for item in services if item.name == "ICMPZero")
    assert icmp.ports[0].icmptype == 0
    assert icmp.ports[0].icmpcode == 0


def test_service_fields_are_typed_without_destination_defaults():
    services, _, items, _ = extract_service_objects([CheckPointResponse(
        command="show-services-tcp", data={"objects": [{
            "uid": "typed", "name": "Typed", "type": "service-tcp",
            "port": "443", "source-port": "1024-2048", "match-for-any": False,
            "session-timeout": 60, "aggressive-aging": {"enable": True},
            "sync-connections-on-cluster": True,
            "keep-connections-open-after-policy-installation": False,
            "protocol-signatures": ["https"],
        }]},
    )], CheckPointObjectResolver())
    service = services[0]
    assert service.ports[0].port == "443"
    assert service.ports[0].source_port == "1024-2048"
    assert service.match_for_any is False
    assert service.session_timeout == 60
    assert service.aggressive_aging == {"enable": True}
    assert service.sync_connections_on_cluster is True
    assert service.keep_connections_open_after_policy_installation is False
    assert service.protocol_signatures == ["https"]
    assert items[0].status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_service_other_preserves_matching_and_session_behavior():
    services, _, _, _ = extract_service_objects([CheckPointResponse(
        command="show-services-other", data={"objects": [{
            "uid": "other-6", "name": "Other", "type": "service-other",
            "ip-protocol": 6, "match": "dport=443", "action": "inspect",
            "accept-replies": True, "session-timeout": 30,
        }]},
    )], CheckPointObjectResolver())
    service = services[0]
    assert service.source_protocol_number == 6
    assert service.match == "dport=443"
    assert service.action == "inspect"
    assert service.accept_replies is True
    assert service.session_behavior["session-timeout"] == 30


@pytest.mark.parametrize("command,obj_type", [
    ("show-services-citrix-tcp", "service-citrix-tcp"),
    ("show-services-dce-rpc", "service-dce-rpc"),
    ("show-services-rpc", "service-rpc"),
    ("show-services-gtp", "service-gtp"),
    ("show-services-compound-tcp", "service-compound-tcp"),
])
def test_specialized_services_are_explicit_extract_only(command, obj_type):
    _, _, items, unsupported = extract_service_objects([
        CheckPointResponse(command=command, data={"objects": [{
            "uid": obj_type, "name": obj_type, "type": obj_type,
        }]})
    ], CheckPointObjectResolver())
    assert items[0].status == ExtractionStatus.EXTRACT_ONLY
    assert items[0].requires_manual_review
    assert unsupported
