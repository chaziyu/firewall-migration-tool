from fwmigrate.extraction.models import DependencyRecord, ExtractionResult, UnsupportedItem
from fwmigrate.ir.core import (
    IRAddress,
    IRConfig,
    IRMetadata,
    IRNATRule,
    IRPolicy,
    IRRoute,
    IRSecurityProfileGroup,
    IRService,
    IRVPNTunnel,
    IRZone,
)
from fwmigrate.ir.enums import AddressType, NATType, PolicyAction
from fwmigrate.ir.io import dump_ir_json, load_ir_json


def test_canonical_ir_round_trip_preserves_representative_configuration():
    config = IRConfig(
        metadata=IRMetadata(source_vendor="test", source_context="root"),
        generation_safe=False,
        generation_blocking_reasons=["unsupported source evidence"],
        requires_manual_review=True,
        zones=[IRZone(name="inside")],
        addresses=[IRAddress(name="web", type=AddressType.HOST, subnet="10.0.0.10/32")],
        services=[IRService(name="https")],
        policies=[IRPolicy(
            name="allow-web",
            from_zone=["inside"],
            to_zone=["any"],
            source=["web"],
            destination=["any"],
            service=["https"],
            action=PolicyAction.ALLOW,
        )],
        nat_rules=[IRNATRule(
            name="web-dnat",
            type=NATType.DESTINATION,
            source=["any"],
            destination=["web"],
            services=["https"],
            translated_destinations=["web"],
        )],
        routes=[IRRoute(name="default", destination="0.0.0.0/0", next_hops=["10.0.0.1"])],
        vpn_tunnels=[IRVPNTunnel(name="site-a", local_interface="inside")],
        security_profile_groups=[IRSecurityProfileGroup(name="default")],
    )
    extraction = ExtractionResult(
        canonical_ir=config,
        unsupported_items=[UnsupportedItem(source_path="system/feature", reason="not portable")],
        dependencies=[DependencyRecord(
            source_path="policy/allow-web",
            source_object="allow-web",
            source_field="source",
            reference="web",
            expected_type="address",
            result="RESOLVED",
        )],
        requires_manual_review=True,
        generation_safe=False,
        blocking_reasons=["unsupported source evidence"],
    )

    restored = load_ir_json(dump_ir_json(config))
    restored_extraction = ExtractionResult.model_validate_json(extraction.model_dump_json())

    assert restored == config
    assert restored_extraction.canonical_ir == config
    assert restored_extraction.unsupported_items[0].reason == "not portable"
    assert restored_extraction.dependencies[0].reference == "web"
    assert restored.generation_blocking_reasons == ["unsupported source evidence"]
