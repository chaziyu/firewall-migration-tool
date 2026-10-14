from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, apply_explicit_options
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.vendors.fortigate.model.interface import FGInterface
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.zone import FGZone


@pytest.mark.parametrize("options", [
    {"vdoms": {"ghost": {"vsys": "vsys1"}}},
    {"interfaces": {"root": {"ghost": {"target_zone": "trust"}}}},
    {"interfaces": {"blue": {"wan": {"target_interface": "ethernet1/1"}}}},
    {"zones": {"root": {"ghost": {"target_zone": "trust"}}}},
    {"interfaces": {"root": {"dmz": {"target_interface": "ethernet1/1"}}}},
])
def test_explicit_mapping_rejects_nonexistent_or_cross_scope_sources(options):
    source = FGConfig(interfaces=[FGInterface(name="wan")], zones=[FGZone(name="dmz")])
    with pytest.raises(ValueError, match="source"):
        apply_explicit_options(source, PANMigrationDecisionSet(), options)


def test_valid_optional_and_legacy_zone_mappings_remain_compatible():
    source = FGConfig(interfaces=[FGInterface(name="wan")], zones=[FGZone(name="dmz")])
    decisions = apply_explicit_options(source, PANMigrationDecisionSet(), PANMigrationOptions(
        vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
            "wan": {"target_interface": "ethernet1/1"}, "dmz": {"target_zone": "dmz"},
        }},
    ))
    assert decisions.to_options().zones["root"]["dmz"].target_zone == "dmz"
    assert all(item.review_state is PANDecisionReviewState.CONFIRMED for item in decisions.decisions)


def test_changed_mapping_clears_previous_operation_approval():
    source = FGConfig(interfaces=[FGInterface(name="wan")])
    old = PANMigrationDecision("root", "interface", "wan", "target_interface",
        value="ethernet1/1", review_state=PANDecisionReviewState.CONFIRMED,
        approved_operation="CONFIGURE", approval_context={"candidate": "old"})
    options = {"interfaces": {"root": {"wan": {"target_interface": "ethernet1/2"}}}}
    changed = apply_explicit_options(source, PANMigrationDecisionSet((old,)), options).decisions[0]
    assert changed.approved_operation is None
    assert changed.approval_context is None
    assert changed.evidence_source == "ENGINEER"
    unchanged = apply_explicit_options(source, PANMigrationDecisionSet((replace(old, value="ethernet1/2"),)), options).decisions[0]
    assert unchanged.approved_operation == "CONFIGURE"
