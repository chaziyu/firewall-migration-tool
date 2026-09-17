from fwmigrate.capabilities.schema import CapabilityStatus
from fwmigrate.generators.service_capabilities import ServiceCapabilities, service_capabilities
from fwmigrate.ir import IRService, IRServiceGroup, IRServicePort
from fwmigrate.ir.enums import ServiceProtocol


def _service(*ports, **kwargs):
    return IRService(name="svc", ports=list(ports), **kwargs)


def test_service_capabilities_classify_protocol_ports_and_nested_groups():
    pan = service_capabilities("palo_alto")

    assert pan.evaluate_service(_service(
        IRServicePort(protocol=ServiceProtocol.TCP, port="80-90"),
    )).status == CapabilityStatus.SUPPORTED
    assert pan.evaluate_service(_service(
        IRServicePort(protocol=ServiceProtocol.SCTP, port="5000"),
    )).status == CapabilityStatus.UNSUPPORTED
    assert pan.evaluate_service(_service(
        IRServicePort(protocol=ServiceProtocol.TCP, port="443", source_port="1024-65535"),
    )).status == CapabilityStatus.UNSUPPORTED
    assert ServiceCapabilities().evaluate_service(_service(
        IRServicePort(protocol=ServiceProtocol.TCP, port="80-90"),
    )).requires_lowering

    group = IRServiceGroup(name="outer", members=["inner"])
    inner = IRServiceGroup(name="inner", members=["svc"])
    assert service_capabilities("cisco_asa").evaluate_group(group, [inner]).requires_lowering
    assert service_capabilities("cisco_asa").evaluate_group(
        IRServiceGroup(name="outer", source_context="other", members=["inner"]),
        [inner],
    ).supported


def test_service_capabilities_preserve_manual_review_state():
    result = service_capabilities("fortigate").evaluate_service(
        _service(migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True)
    )

    assert result.status == CapabilityStatus.MANUAL_REVIEW
    assert result.requires_manual_review

    missing_protocol_number = service_capabilities("fortigate").evaluate_service(
        _service(IRServicePort(protocol=ServiceProtocol.IP, port="47"))
    )
    assert missing_protocol_number.status == CapabilityStatus.MANUAL_REVIEW
