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
