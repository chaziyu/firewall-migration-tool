from fwmigrate.ir import (
    IRAddress,
    IRAddressGroup,
    IRConfig,
    IRMetadata,
    IRPolicy,
    IRService,
    IRServiceGroup,
)
from fwmigrate.ir.enums import AddressType, PolicyAction, ServiceProtocol
from fwmigrate.ir.service import IRServicePort


def build_ir(scale: int = 100) -> IRConfig:
    """Create a deterministic dependency-heavy IR without customer data."""
    addresses = [
        IRAddress(
            name=f"address-{i}",
            type=AddressType.HOST,
            subnet=f"198.18.{i // 254}.{i % 254 + 1}/32",
        )
        for i in range(scale)
    ]
    address_groups = [
        IRAddressGroup(name=f"address-group-{i}", members=[f"address-{i}"])
        for i in range(scale // 4)
    ]
    services = [
        IRService(
            name=f"service-{i}",
            ports=[IRServicePort(protocol=ServiceProtocol.TCP, port=str(1024 + i))],
        )
        for i in range(max(1, scale // 4))
    ]
    service_groups = [
        IRServiceGroup(name=f"service-group-{i}", members=[f"service-{i}"])
        for i in range(max(1, scale // 8))
    ]
    policies = [
        IRPolicy(
            name=f"policy-{i}",
            source=[f"address-group-{i % max(1, scale // 4)}"],
            destination=[f"address-{(i + 1) % scale}"],
            service=[f"service-group-{i % max(1, scale // 8)}"],
            action=PolicyAction.ALLOW,
        )
        for i in range(max(1, scale // 2))
    ]
    return IRConfig(
        metadata=IRMetadata(hostname=f"benchmark-{scale}"),
        addresses=addresses,
        address_groups=address_groups,
        services=services,
        service_groups=service_groups,
        policies=policies,
    )
