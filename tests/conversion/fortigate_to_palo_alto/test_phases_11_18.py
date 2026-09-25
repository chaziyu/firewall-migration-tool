from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan,
    PANMigrationStatus,
    PlannedAddress,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.transform.nat import NormalizedSourceNAT


def test_validation_reports_item_warnings_without_mutating_plan():
    item = PlannedAddress(source_name="bad", status=PANMigrationStatus.MANUAL_REVIEW, warnings=("needs mapping",))
    plan = PANMigrationPlan(addresses=(item,))

    result = validate_plan(plan)

    assert result.plan is plan
    assert result.issues[0].message == "needs mapping"
    assert plan.addresses[0] is item


def test_renderer_emits_only_supported_commands_and_complete_report():
    plan = PANMigrationPlan(addresses=(
        PlannedAddress(source_name="net", target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="10.0.0.0/24"),
        PlannedAddress(source_name="review", status=PANMigrationStatus.MANUAL_REVIEW),
    ))

    rendered = PANSetRenderer().render(plan)

    assert rendered.commands == ("set system setting target-vsys vsys1", "set address net ip-netmask 10.0.0.0/24")
    assert rendered.report["counts"]["SUPPORTED"] == 1
    assert rendered.report["counts"]["MANUAL_REVIEW"] == 1


def test_source_nat_item_with_transform_issue_is_not_renderable():
    source = FGConfig(policies=[FGPolicy(policy_id=1, name="nat", nat="enable", dstintf=["wan"])])
    derived = SimpleNamespace(nat=(NormalizedSourceNAT(
        vdom="root", policy_id=1, policy_name="nat", translation_type="ip_pool",
        pool_names=("missing",), translated_addresses=(), egress_interfaces=("wan",),
        issues=("IP pool 'missing' was not found.",),
    ),))
    options = PANMigrationOptions(interfaces={"root": {"wan": {"target_zone": "untrust"}}})

    from fwmigrate.conversion.fortigate_to_palo_alto.nat import plan_nat
    item = plan_nat(source, derived, options)[0]

    assert item.status is PANMigrationStatus.MANUAL_REVIEW
    assert item.source_translation is None


def test_source_nat_to_interface_uses_confirmed_target_interface_mapping():
    source = FGConfig(policies=[FGPolicy(policy_id=1, name="nat", nat="enable", dstintf=["wan"])])
    derived = SimpleNamespace(nat=(NormalizedSourceNAT(
        vdom="root", policy_id=1, policy_name="nat", translation_type="interface",
        pool_names=(), translated_addresses=(), egress_interfaces=("wan",), issues=(),
    ),))
    options = PANMigrationOptions(interfaces={"root": {"wan": {
        "target_interface": "ethernet1/2", "target_zone": "untrust",
    }}})

    from fwmigrate.conversion.fortigate_to_palo_alto.nat import plan_nat
    item = plan_nat(source, derived, options)[0]
    unmapped = plan_nat(source, derived, PANMigrationOptions())[0]

    assert item.to_interface == "ethernet1/2"
    assert unmapped.to_interface is None
