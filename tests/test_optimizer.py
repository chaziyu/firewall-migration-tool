from fwmigrate.core.optimizer import RuleOptimizer
from fwmigrate.ir.core import (
    IRConfig, IRMetadata, IRAddress, IRAddressGroup, IRService, IRServicePort, IRPolicy
)
from fwmigrate.ir.enums import AddressType, ServiceProtocol, PolicyAction

def test_rule_optimizer():
    ir = IRConfig(
        metadata=IRMetadata(hostname="opt-test", source_vendor="fortigate"),
        addresses=[
            IRAddress(name="used_web", type=AddressType.HOST, value="10.0.0.1/32"),
            IRAddress(name="unused_db", type=AddressType.HOST, value="10.0.0.2/32"),
            IRAddress(name="dup_web_1", type=AddressType.HOST, value="10.0.0.1/32"),
        ],
        services=[
            IRService(name="used_http", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="80")]),
            IRService(name="unused_ssh", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="22")]),
            IRService(name="dup_http_1", ports=[IRServicePort(protocol=ServiceProtocol.TCP, port="80")]),
        ],
        policies=[
            IRPolicy(
                name="Allow_All_Preceding",
                from_zone=["any"],
                to_zone=["any"],
                source=["any"],
                destination=["any"],
                service=["any"],
                action=PolicyAction.ALLOW
            ),
            IRPolicy(
                name="Allow_Specific_Used",
                from_zone=["trust"],
                to_zone=["untrust"],
                source=["used_web"],
                destination=["all"],
                service=["used_http"],
                action=PolicyAction.ALLOW
            )
        ]
    )

    optimizer = RuleOptimizer(ir)

    # 1. Unused objects
    unused = optimizer.find_unused_objects()
    assert "unused_db" in unused["unused_addresses"]
    assert "used_web" not in unused["unused_addresses"]
    assert "unused_ssh" in unused["unused_services"]
    assert "used_http" not in unused["unused_services"]

    # 2. Duplicate objects
    dups = optimizer.find_duplicate_objects()
    assert len(dups["duplicate_addresses"]) >= 1
    assert len(dups["duplicate_services"]) >= 1

    # 3. Shadowed rules
    shadowed = optimizer.find_shadowed_rules()
    assert len(shadowed) == 1
    assert shadowed[0]["rule"] == "Allow_Specific_Used"
    assert shadowed[0]["shadowed_by"] == "Allow_All_Preceding"

    # 4. Pruning
    pruned_ir = optimizer.prune_unused_objects()
    pruned_addr_names = [a.name for a in pruned_ir.addresses]
    assert "unused_db" not in pruned_addr_names
    assert "used_web" in pruned_addr_names


def test_optimizer_does_not_mutate_or_shadow_from_unsafe_policies():
    unsafe = IRPolicy(
        name="Unsafe_Preceding", from_zone=["any"], to_zone=["any"],
        source=["suspicious-source"],
        destination=["bad-1", "bad-2", "bad-3", "bad-4", "bad-5"],
        service=["any"], action=PolicyAction.DENY,
        migration_status="PARTIALLY_NORMALIZED", requires_manual_review=True,
        review_reasons=["source-uncertain"],
    )
    safe = IRPolicy(
        name="Safe_Current", from_zone=["trust"], to_zone=["untrust"],
        source=["host-a"], destination=["host-b"], service=["https"],
        action=PolicyAction.DENY,
    )
    ir = IRConfig(
        metadata=IRMetadata(hostname="safety", source_vendor="checkpoint"),
        policies=[unsafe, safe],
    )
    optimizer = RuleOptimizer(ir)
    optimizer.fix_outbound_threat_source_anomalies()
    assert unsafe.source == ["suspicious-source"]
    assert ir.audit_entries == []
    assert optimizer.find_shadowed_rules() == []
