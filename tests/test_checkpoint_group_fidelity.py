from fwmigrate.extraction.models import (
    ExtractionResult,
    ExtractionStatus,
    SourceInventoryItem,
    UnsupportedItem,
)
from fwmigrate.ir.core import AddressType, IRAddress, IRAddressGroup, IRConfig, IRMetadata
from fwmigrate.parsers.checkpoint.group_fidelity import apply_checkpoint_group_fidelity


def _result(addresses, groups, inventory, unsupported=None):
    return ExtractionResult(
        canonical_ir=IRConfig(
            metadata=IRMetadata(source_vendor="checkpoint"),
            addresses=addresses,
            address_groups=groups,
        ),
        inventory_items=inventory,
        unsupported_items=unsupported or [],
    )


def test_exclusion_group_resolves_include_and_exclude_by_uid_without_flattening():
    addresses = [
        IRAddress(name="Net_All", type=AddressType.NETWORK, subnet="10.0.0.0/8", source_uuid="uid-all"),
        IRAddress(name="Net_DMZ", type=AddressType.NETWORK, subnet="10.10.0.0/16", source_uuid="uid-dmz"),
    ]
    group = IRAddressGroup(
        name="Grp_Exclude_DMZ",
        source_uuid="uid-ex",
        members=["uid-all"],
        exclusion_enabled=True,
        exclude_members=["uid-dmz"],
        migration_status="PARTIALLY_NORMALIZED",
        requires_manual_review=True,
        source_attributes={"include": "uid-all", "except": "uid-dmz"},
    )
    inventory = [
        SourceInventoryItem(
            domain="Domain-A", source_path="checkpoint/show-networks", name="Net_All",
            source_id="uid-all", source_type="network", status=ExtractionStatus.NORMALIZED,
        ),
        SourceInventoryItem(
            domain="Domain-A", source_path="checkpoint/show-networks", name="Net_DMZ",
            source_id="uid-dmz", source_type="network", status=ExtractionStatus.NORMALIZED,
        ),
        SourceInventoryItem(
            domain="Domain-A", source_path="checkpoint/show-groups-with-exclusion",
            name="Grp_Exclude_DMZ", source_id="uid-ex", source_type="group-with-exclusion",
            source_attributes={"include": "uid-all", "except": "uid-dmz"},
            status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True,
            notes=["Exclusion groups (include/except) cannot be expressed directly in canonical IR"],
        ),
    ]
    result = _result(
        addresses, [group], inventory,
        [UnsupportedItem(
            source_path="checkpoint/show-groups-with-exclusion",
            source_name="Grp_Exclude_DMZ",
            reason="Check Point group-with-exclusion requires policy rule expansion",
        )],
    )

    apply_checkpoint_group_fidelity(result)

    assert group.members == ["Net_All"]
    assert group.exclude_members == ["Net_DMZ"]
    assert group.exclusion_enabled is True
    assert group.source_attributes["checkpoint-unresolved-include-references"] == []
    assert group.source_attributes["checkpoint-unresolved-exclude-references"] == []
    exclusion_item = inventory[-1]
    assert "group-with-exclusion-semantics-preserved-in-ir" in exclusion_item.notes
    assert all("cannot be expressed directly" not in note for note in exclusion_item.notes)
    assert "target portability requires review" in result.unsupported_items[0].reason


def test_exclusion_group_drops_unresolved_uid_from_canonical_members_but_preserves_evidence():
    group = IRAddressGroup(
        name="BrokenExclude",
        source_uuid="uid-ex",
        members=["uid-missing-include"],
        exclusion_enabled=True,
        exclude_members=["uid-missing-exclude"],
        migration_status="PARTIALLY_NORMALIZED",
        requires_manual_review=True,
        source_attributes={"include": "uid-missing-include", "except": "uid-missing-exclude"},
    )
    inventory = [SourceInventoryItem(
        domain="Domain-A", source_path="checkpoint/show-groups-with-exclusion",
        name="BrokenExclude", source_id="uid-ex", source_type="group-with-exclusion",
        source_attributes={"include": "uid-missing-include", "except": "uid-missing-exclude"},
        status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True,
    )]
    result = _result([], [group], inventory)

    apply_checkpoint_group_fidelity(result)

    assert group.members == []
    assert group.exclude_members == []
    assert group.source_attributes["checkpoint-unresolved-include-references"] == ["uid-missing-include"]
    assert group.source_attributes["checkpoint-unresolved-exclude-references"] == ["uid-missing-exclude"]
    assert "unresolved-group-with-exclusion-include:uid-missing-include" in inventory[0].notes
    assert "unresolved-group-with-exclusion-exclude:uid-missing-exclude" in inventory[0].notes
    assert result.generation_safe is False
    assert "checkpoint-group-with-exclusion-unresolved-reference" in result.blocking_reasons


def test_exclusion_group_preserves_dual_stack_canonical_expansion():
    addresses = [
        IRAddress(name="Dual__ipv4", type=AddressType.HOST, subnet="10.0.0.1/32", source_uuid="uid-dual"),
        IRAddress(name="Dual__ipv6", type=AddressType.HOST, subnet="2001:db8::1/128", source_uuid="uid-dual"),
    ]
    group = IRAddressGroup(
        name="DualInclude",
        source_uuid="uid-ex",
        members=["uid-dual"],
        exclusion_enabled=True,
        exclude_members=[],
        migration_status="PARTIALLY_NORMALIZED",
        requires_manual_review=True,
        source_attributes={"include": "uid-dual", "except": []},
    )
    inventory = [
        SourceInventoryItem(
            domain="Domain-A", source_path="checkpoint/show-hosts", name="Dual",
            source_id="uid-dual", source_type="host", status=ExtractionStatus.NORMALIZED,
        ),
        SourceInventoryItem(
            domain="Domain-A", source_path="checkpoint/show-groups-with-exclusion",
            name="DualInclude", source_id="uid-ex", source_type="group-with-exclusion",
            source_attributes={"include": "uid-dual", "except": []},
            status=ExtractionStatus.PARTIALLY_NORMALIZED, requires_manual_review=True,
        ),
    ]
    result = _result(addresses, [group], inventory)

    apply_checkpoint_group_fidelity(result)

    assert group.members == ["Dual__ipv4", "Dual__ipv6"]
    assert group.exclude_members == []
