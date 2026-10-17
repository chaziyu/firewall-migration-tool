from dataclasses import replace

from fwmigrate.conversion.fortigate_to_juniper_srx import FortiGateToJuniperSRXPlanner
from fwmigrate.conversion.fortigate_to_juniper_srx.planning.policies import plan_policies
from fwmigrate.conversion.fortigate_to_juniper_srx.planning.schedules import plan_schedules
from fwmigrate.conversion.fortigate_to_juniper_srx.planning.topology import plan_topology
from fwmigrate.vendors.fortigate.derived import build_derived_views


def _plan(analysis, options):
    return FortiGateToJuniperSRXPlanner().plan(
        analysis.extracted.config,
        analysis.derived,
        options,
        source_inventory=analysis.extracted.source_objects,
    )


def test_policies_require_complete_source_inventory(policy_analysis, complete_options):
    plan = FortiGateToJuniperSRXPlanner().plan(
        policy_analysis.extracted.config, policy_analysis.derived, complete_options,
    )
    policies = [item for item in plan.items if item.family == "policy"]
    assert policies
    assert all("SOURCE_INVENTORY_NOT_PROVIDED" in item.blockers for item in policies)


def test_central_snat_policy_routing_and_unsupported_sections_block_rules(blocker_analysis, complete_options):
    from fwmigrate.vendors.fortigate.extraction.source_inventory import SourceObjectRecord

    unsupported = SourceObjectRecord(
        vdom="root", source_path="firewall policy6", object_name="1",
        parent_objects=(), values={}, explicit_fields=(), unset_fields=(), commands=(),
        start_line_number=None, end_line_number=None,
    )
    plan = FortiGateToJuniperSRXPlanner().plan(
        blocker_analysis.extracted.config,
        blocker_analysis.derived,
        complete_options,
        source_inventory=(*blocker_analysis.extracted.source_objects, unsupported),
    )
    policies = [item for item in plan.items if item.family == "policy"]
    assert policies
    assert all("CENTRAL_SNAT_EVIDENCE_UNTRANSLATED" in item.blockers for item in policies)
    assert all("POLICY_ROUTING_EVIDENCE_UNTRANSLATED" in item.blockers for item in policies)
    assert all("UNSUPPORTED_POLICY_SECTION_PRESENT" in item.blockers for item in policies)


def test_empty_policy_sections_are_not_mistaken_for_untranslated_rules(policy_analysis, complete_options):
    from fwmigrate.vendors.fortigate.extraction.source_inventory import SourceObjectRecord

    empty_section = SourceObjectRecord(
        vdom="root", source_path="firewall central-snat-map", object_name=None,
        parent_objects=(), values={}, explicit_fields=(), unset_fields=(), commands=(),
        start_line_number=None, end_line_number=None,
    )
    inventory = (*policy_analysis.extracted.source_objects, empty_section)
    plan = FortiGateToJuniperSRXPlanner().plan(
        policy_analysis.extracted.config, policy_analysis.derived, complete_options,
        source_inventory=inventory,
    )
    policies = [item for item in plan.items if item.family == "policy"]
    assert all(not item.blockers for item in policies)


def test_duplicate_source_policy_ids_block_both_rules(policy_analysis, complete_options):
    source = policy_analysis.extracted.config.model_copy(deep=True)
    source.policies.append(source.policies[0].model_copy(update={"name": "duplicate-id"}))
    derived = build_derived_views(source)
    plan = FortiGateToJuniperSRXPlanner().plan(
        source, derived, complete_options, source_inventory=policy_analysis.extracted.source_objects,
    )
    duplicates = [item for item in plan.items if item.family == "policy" and item.source_name != "deny-other"]
    assert len(duplicates) == 2
    assert all("DUPLICATE_SOURCE_POLICY_ID" in item.blockers for item in duplicates)


def test_explicit_policy_actions_matches_logging_and_order_are_preserved(policy_analysis, complete_options):
    plan = _plan(policy_analysis, complete_options)
    policies = [item for item in plan.items if item.family == "policy"]
    assert [item.source_name for item in policies] == ["allow-app", "deny-other"]
    assert all(not item.blockers for item in policies)
    allow, deny = policies
    assert dict(allow.settings)["action"] == "permit"
    assert dict(allow.settings)["logging"] == "all"
    assert allow.key in deny.dependencies
    assert dict(deny.settings)["source_addresses"] == ("any-ipv4",)
    assert dict(deny.settings)["applications"] == ("any",)


def test_unsupported_earlier_nat_policy_blocks_later_rule(policy_analysis, complete_options):
    source = policy_analysis.extracted.config.model_copy(deep=True)
    source.policies[0] = source.policies[0].model_copy(update={"nat": "enable"})
    source.policies[1] = source.policies[1].model_copy(update={"action": "accept"})
    derived = build_derived_views(source)
    plan = FortiGateToJuniperSRXPlanner().plan(
        source, derived, complete_options, source_inventory=policy_analysis.extracted.source_objects,
    )
    policies = [item for item in plan.items if item.family == "policy"]
    assert "POLICY_NAT_REQUIRES_SEPARATE_SUPPORT" in policies[0].blockers
    assert policies[0].key in policies[1].dependencies


def test_one_source_rule_expands_to_every_mapped_zone_pair(policy_analysis, complete_options):
    source = policy_analysis.extracted.config.model_copy(deep=True)
    source.policies[0] = source.policies[0].model_copy(update={
        "srcintf": ["inside", "outside"],
        "dstintf": ["inside", "outside"],
    })
    derived = build_derived_views(source)
    items = [*plan_topology(source, derived, complete_options, "root"),
             *plan_schedules(source, complete_options, "root")]
    policies, _ = plan_policies(
        source, derived, complete_options, "root", items,
        plan_schedules(source, complete_options, "root"),
        policy_analysis.extracted.source_objects,
    )
    expanded = [item for item in policies if item.source_name == "allow-app"]
    assert {(dict(item.settings)["from_zone"], dict(item.settings)["to_zone"])
            for item in expanded} == {
                ("inside-zone", "inside-zone"), ("inside-zone", "outside-zone"),
                ("outside-zone", "inside-zone"), ("outside-zone", "outside-zone"),
            }


def test_invalid_target_zone_tokens_are_blocked(policy_analysis, complete_options):
    options = replace(complete_options, zones={"root": {"inside": "inside;commit", "outside": "outside-zone"}})
    plan = _plan(policy_analysis, options)
    inside = next(item for item in plan.items if item.family == "zone" and item.source_name == "inside")
    assert "ZONE_TARGET_NAME_INVALID" in inside.blockers
    policies = [item for item in plan.items if item.family == "policy"]
    assert all("POLICY_TARGET_ZONE_BLOCKED" in item.blockers for item in policies)


def test_timezone_blocks_unverified_dst_and_accepts_fixed_offset_weekly_scope(explicit_analysis, complete_options):
    dst_options = replace(complete_options, timezone="America/New_York")
    source = explicit_analysis.extracted.config.model_copy(deep=True)
    source.one_time_schedules[0] = source.one_time_schedules[0].model_copy(update={
        "start": "2026/03/07 01:00", "end": "2026/03/09 03:00",
    })
    schedules = plan_schedules(source, dst_options, "root")
    recurring = next(item for item in schedules if item.source_name == "weekday-hours")
    one_time = next(item for item in schedules if item.source_name == "change-window")
    assert "RECURRING_SCHEDULE_DST_NOT_VERIFIED" in recurring.blockers
    assert "ONE_TIME_SCHEDULE_DST_NOT_VERIFIED" in one_time.blockers

    fixed_zone = plan_schedules(source, complete_options, "root")
    assert all(not item.blockers for item in fixed_zone)


def test_unavailable_timezone_does_not_activate_schedules(explicit_analysis, complete_options):
    options = replace(complete_options, timezone="Not/A_Real_Zone")
    schedules = plan_schedules(explicit_analysis.extracted.config, options, "root")
    assert all("SCHEDULE_TIMEZONE_RULES_UNAVAILABLE" in item.blockers for item in schedules)


def test_overnight_recurring_schedule_is_blocked(explicit_analysis, complete_options):
    source = explicit_analysis.extracted.config.model_copy(deep=True)
    source.recurring_schedules[0] = source.recurring_schedules[0].model_copy(update={
        "start": "21:00", "end": "06:00",
    })
    schedule = next(item for item in plan_schedules(source, complete_options, "root")
                    if item.source_name == "weekday-hours")
    assert "RECURRING_SCHEDULE_INTERVAL_INVALID_OR_OVERNIGHT" in schedule.blockers
