from dataclasses import replace
from pathlib import Path

import pytest

from fwmigrate.conversion.fortigate_to_juniper_srx.design.deterministic import (
    approve_design,
    build_deterministic_draft,
    validate_approval,
)
from fwmigrate.conversion.fortigate_to_juniper_srx.application.workflow import run_migration_pipeline
from fwmigrate.conversion.fortigate_to_juniper_srx.models import SRXMigrationPlan, SRXPlanItem
from fwmigrate.conversion.fortigate_to_juniper_srx.options import SRXMigrationOptions
from fwmigrate.conversion.fortigate_to_juniper_srx.plan_dependencies import assess_render_disposition
from fwmigrate.conversion.fortigate_to_juniper_srx.rendering.renderer import JunosSetRenderer
from fwmigrate.conversion.fortigate_to_juniper_srx.target.comparison import compare_target_plan
from fwmigrate.conversion.fortigate_to_juniper_srx.target.evidence import build_target_evidence
from fwmigrate.vendors.juniper_srx.source_analysis import extract_juniper_source
from fwmigrate.source_reporting import source_reporters
from fwmigrate.source_reporting.builtin import register_builtin_source_reporters


COMPLETE = ["addresses", "applications", "interfaces", "zones", "static_routes", "schedules", "policies", "nat"]
OPTIONS = SRXMigrationOptions(
    source_vdom="root", target_context="root", target_version="25.2R1",
    target_mode="standalone", routing_table="inet.0",
)


def address_plan():
    return SRXMigrationPlan(
        source_vdom="root", target_context="root", target_version="25.2R1",
        target_mode="standalone", routing_table="inet.0",
        items=(SRXPlanItem(
            key="address:office", family="address", source_vdom="root",
            source_name="office", target_name="FGT-office",
            settings=(("address_type", "prefix"), ("value", "10.20.0.0/16")),
        ),), decisions=(), findings=(),
    )


def policy_plan():
    return SRXMigrationPlan(
        source_vdom="root", target_context="root", target_version="25.2R1",
        target_mode="standalone", routing_table="inet.0",
        items=(SRXPlanItem(
            key="policy:allow", family="policy", source_vdom="root",
            source_name="allow", target_name="FGT-allow",
            settings=(("from_zone", "trust"), ("to_zone", "untrust"),
                      ("source_addresses", ("any-ipv4",)), ("destination_addresses", ("any-ipv4",)),
                      ("applications", ("any",)), ("action", "permit"), ("schedule", None),
                      ("disabled", False), ("logging", "disable")),
        ),), decisions=(), findings=(),
    )


def policy_zones():
    return (
        "set security zones security-zone trust\n"
        "set security zones security-zone untrust\n"
    )


def evidence(text, *, families=None, metadata=None, options=OPTIONS):
    target = extract_juniper_source(text)
    metadata = metadata or {
        "context": "root", "version": "25.2R1", "mode": "standalone",
        "complete_families": COMPLETE if families is None else families,
    }
    return build_target_evidence(target, text, metadata, options)


def test_complete_empty_target_proves_absence_for_objects():
    plan = compare_target_plan(address_plan(), evidence(""))

    assert assess_render_disposition(plan)["address:office"] == "CREATE"
    assert JunosSetRenderer().render(plan).commands == (
        "set security address-book global address FGT-office 10.20.0.0/16",
    )


def test_exact_local_and_inherited_configuration_is_reused_without_commands():
    line = "set security address-book global address FGT-office 10.20.0.0/16\n"
    local = compare_target_plan(address_plan(), evidence(line))
    inherited_text = (
        "set groups common security address-book global address FGT-office 10.20.0.0/16\n"
        "set apply-groups common\n"
    )
    inherited = compare_target_plan(address_plan(), evidence(inherited_text))

    assert assess_render_disposition(local)["address:office"] == "REUSE"
    assert assess_render_disposition(inherited)["address:office"] == "REUSE"
    assert JunosSetRenderer().render(local).commands == ()
    assert JunosSetRenderer().render(inherited).commands == ()


def test_conflicting_or_inactive_object_never_becomes_create():
    conflict = "set security address-book global address FGT-office 10.21.0.0/16\n"
    inactive = (
        "set security address-book global address FGT-office 10.20.0.0/16\n"
        "deactivate security address-book global address FGT-office\n"
    )

    for text in (conflict, inactive):
        plan = compare_target_plan(address_plan(), evidence(text))
        assert assess_render_disposition(plan)["address:office"] == "BLOCK"
        assert JunosSetRenderer().render(plan).commands == ()


def test_unconfirmed_family_and_target_profile_mismatch_fail_closed():
    incomplete = compare_target_plan(address_plan(), evidence("", families=COMPLETE[1:]))
    mismatch = evidence("", metadata={
        "context": "root", "version": "25.2R1", "mode": "cluster", "complete_families": COMPLETE,
    })

    assert "TARGET_FAMILY_COMPLETENESS_UNCONFIRMED" in incomplete.items[0].blockers
    assert "TARGET_MODE_MISMATCH_OR_UNSUPPORTED" in mismatch.global_blockers
    assert assess_render_disposition(compare_target_plan(address_plan(), mismatch))["address:office"] == "BLOCK"


def test_inherited_conflict_and_unresolved_group_block_comparison():
    conflict = (
        "set groups common security address-book global address FGT-office 10.21.0.0/16\n"
        "set apply-groups common\n"
    )
    unresolved = "set apply-groups missing-group\n"

    inherited_conflict = compare_target_plan(address_plan(), evidence(conflict))
    unresolved_group = compare_target_plan(address_plan(), evidence(unresolved))

    assert "TARGET_CONFIGURATION_CONFLICT" in inherited_conflict.items[0].blockers
    assert "TARGET_GROUP_RESOLUTION_UNVERIFIED" in unresolved_group.findings[0].code
    assert assess_render_disposition(unresolved_group)["address:office"] == "BLOCK"


def test_policy_creation_requires_an_insertion_anchor_and_exact_policy_reuse_is_noop():
    plan = policy_plan()
    blocked = compare_target_plan(plan, evidence(""))
    commands = JunosSetRenderer().render(plan).commands
    exact = compare_target_plan(plan, evidence(policy_zones() + "\n".join(commands) + "\n"))

    assert assess_render_disposition(blocked)["policy:allow"] == "BLOCK"
    assert "TARGET_POLICY_INSERTION_ANCHOR_UNVERIFIED" in blocked.items[0].blockers
    assert assess_render_disposition(exact)["policy:allow"] == "REUSE"
    assert JunosSetRenderer().render(exact).commands == ()


def test_policy_creation_on_verified_empty_destination_needs_no_anchor():
    compared = compare_target_plan(policy_plan(), evidence(policy_zones()))
    assert assess_render_disposition(compared)["policy:allow"] == "CREATE"
    assert JunosSetRenderer().render(compared).commands


@pytest.mark.parametrize("extra", [
    "set security policies global policy g then permit\n",
    "set security policies from-zone trust to-zone untrust policy existing then deny\n",
    "set groups common security policies from-zone trust to-zone untrust policy inherited then deny\nset apply-groups common\n",
    "set security policies default-policy permit-all\n",
    "set security nat source rule-set rs rule r then source-nat interface\n",
    "set routing-instances ri interface ge-0/0/0.0\n",
    "deactivate security policies\n",
])
def test_empty_destination_creation_blocks_ambiguous_or_populated_state(extra):
    compared = compare_target_plan(policy_plan(), evidence(policy_zones() + extra))
    assert assess_render_disposition(compared)["policy:allow"] == "BLOCK"


@pytest.mark.parametrize("missing", COMPLETE)
def test_empty_destination_creation_requires_complete_evidence(missing):
    compared = compare_target_plan(policy_plan(), evidence(policy_zones(), families=[f for f in COMPLETE if f != missing]))
    assert assess_render_disposition(compared)["policy:allow"] == "BLOCK"


def test_policy_order_conflict_and_destination_nat_block_reuse():
    commands = JunosSetRenderer().render(policy_plan()).commands
    extra = "set security policies from-zone trust to-zone untrust policy other then deny\n"
    order_conflict = compare_target_plan(
        policy_plan(), evidence(policy_zones() + extra + "\n".join(commands) + "\n"),
    )
    nat_conflict = compare_target_plan(
        policy_plan(), evidence(policy_zones() + "set security nat source rule-set rs rule r then source-nat interface\n"
                                + "\n".join(commands) + "\n"),
    )

    assert "TARGET_POLICY_ORDER_UNVERIFIED" in order_conflict.items[0].blockers
    assert "TARGET_NAT_POLICY_INTERACTION_UNVERIFIED" in nat_conflict.items[0].blockers


def test_target_fingerprint_is_part_of_signed_approval_context():
    plan = address_plan()
    first = evidence("")
    second = evidence("set system host-name changed\n")
    draft = build_deterministic_draft(plan, "source-digest", OPTIONS, first)
    approval = approve_design(plan, draft, ["address:office"], first)
    changed_draft = build_deterministic_draft(plan, "source-digest", OPTIONS, second)

    assert draft["target_digest"] != changed_draft["target_digest"]
    with pytest.raises(ValueError, match="different pair, source or design"):
        validate_approval(plan, changed_draft, approval)


def test_native_fortigate_plan_reuses_exact_commands_from_junos_parse_back(complete_options):
    register_builtin_source_reporters()
    fixture = Path(__file__).parents[2] / "fixtures" / "fortigate" / "multi_vendor_explicit.conf"
    source_text = fixture.read_text(encoding="utf-8").replace(
        'set interface "lan" "app-vlan"', 'set interface "lan"', 1,
    )
    source = source_reporters.get("fortigate").analyze_source(source_text)
    original, rendered, _ = run_migration_pipeline(source, complete_options)
    target = evidence(rendered.command_text)
    compared = compare_target_plan(original, target)
    original_dispositions = assess_render_disposition(original)
    compared_dispositions = assess_render_disposition(compared)

    assert [item.key for item in original.items if original_dispositions[item.key] == "CREATE"]
    assert all(compared_dispositions[item.key] == "REUSE"
               for item in original.items if original_dispositions[item.key] == "CREATE")
    assert JunosSetRenderer().render(compared).commands == ()
