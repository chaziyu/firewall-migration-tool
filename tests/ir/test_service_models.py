from fwmigrate.ir.enums import ServiceProtocol
from fwmigrate.ir.service import IRService, IRServicePort


def test_service_models_live_in_the_service_domain():
    service = IRService(
        name="https",
        ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="443")],
    )

    assert service.ports[0].port == "443"
    assert IRService.__module__ == "fwmigrate.ir.service"

