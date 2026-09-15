from fwmigrate.core.normalizer import IRNormalizer
from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.ir import IRAddress, IRAddressGroup, IRConfig, IRMetadata, IRPolicy, IRService, IRServiceGroup
from fwmigrate.ir.enums import AddressType, PolicyAction, ServiceProtocol
from fwmigrate.ir.service import IRServicePort


def test_optimizer_does_not_perform_mandatory_normalization():
    ir = IRConfig(
        metadata=IRMetadata(hostname="optimizer-test", source_vendor="fortigate"),
        policies=[
            IRPolicy(
                name="unsafe-anomaly",
                source=["client"],
                destination=["botnet", "d1", "d2", "d3", "d4"],
                service=["any"],
                action=PolicyAction.DENY,
                migration_status="NORMALIZED",
            )
        ],
    )

    RuleOptimizer(ir).find_unused_objects()

    assert ir.policies[0].source == ["client"]
    assert not ir.audit_entries
    assert IRNormalizer().normalize(ir).changes


def test_pruning_replaces_only_pruned_collections():
    kept_address = IRAddress(name="kept-address", type=AddressType.HOST, value="192.0.2.1/32")
    kept_service = IRService(
        name="kept-service",
        ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="443")],
    )
    ir = IRConfig(
        metadata=IRMetadata(),
        addresses=[kept_address, IRAddress(name="unused-address", type=AddressType.HOST, value="192.0.2.2/32")],
        address_groups=[
            IRAddressGroup(name="kept-address-group", members=[kept_address.name]),
            IRAddressGroup(name="unused-address-group", members=["unused-address"]),
        ],
        services=[kept_service, IRService(name="unused-service")],
        service_groups=[
            IRServiceGroup(name="kept-service-group", members=[kept_service.name]),
            IRServiceGroup(name="unused-service-group", members=["unused-service"]),
        ],
        policies=[IRPolicy(
            name="keep-objects",
            source=["kept-address-group"],
            destination=[kept_address.name],
            service=["kept-service-group"],
            action=PolicyAction.ALLOW,
        )],
    )

    pruned = RuleOptimizer(ir).prune_unused_objects()

    assert pruned is not ir
    assert [item.name for item in ir.addresses] == ["kept-address", "unused-address"]
    assert [item.name for item in pruned.addresses] == ["kept-address"]
    assert [item.name for item in ir.services] == ["kept-service", "unused-service"]
    assert [item.name for item in pruned.services] == ["kept-service"]
    assert [item.name for item in ir.address_groups] == ["kept-address-group", "unused-address-group"]
    assert [item.name for item in pruned.address_groups] == ["kept-address-group"]
    assert [item.name for item in ir.service_groups] == ["kept-service-group", "unused-service-group"]
    assert [item.name for item in pruned.service_groups] == ["kept-service-group"]
    assert pruned.addresses[0] is kept_address
    assert pruned.services[0] is kept_service
