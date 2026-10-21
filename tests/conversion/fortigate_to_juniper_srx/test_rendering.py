import hashlib
from dataclasses import replace
from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_juniper_srx import FortiGateToJuniperSRXPlanner
from fwmigrate.conversion.fortigate_to_juniper_srx.rendering.renderer import JunosSetRenderer
from fwmigrate.vendors.juniper_srx.source_report import JuniperSRXSourceReporter


def test_large_plan_order_matches_existing_priority_and_dependency_order():
    from fwmigrate.conversion.fortigate_to_juniper_srx.models import SRXPlanItem
    from fwmigrate.conversion.fortigate_to_juniper_srx.rendering.renderer import (
        _FAMILY_ORDER,
        _topological_order,
    )

    items = [SRXPlanItem(
        key=f"item-{index}", family="service_group" if index % 3 else "service",
        source_vdom="root", source_name=str(index), target_name=f"target-{index}",
        source_order=index % 17,
        dependencies=(f"item-{index - 1}",) if index % 5 else ("reused",),
    ) for index in range(3000)]
    ordered = _topological_order(list(reversed(items)), {"reused"})
    assert len(ordered) == len(items)
    emitted = {"reused"}
    for item in ordered:
        ready = [row for row in items if row.key not in emitted and set(row.dependencies) <= emitted]
        assert item == min(ready, key=lambda row: (_FAMILY_ORDER[row.family], row.source_order, row.key))
        emitted.add(item.key)


def test_ordering_does_not_satisfy_missing_or_cyclic_dependencies():
    from fwmigrate.conversion.fortigate_to_juniper_srx.models import SRXPlanItem
    from fwmigrate.conversion.fortigate_to_juniper_srx.rendering.renderer import _topological_order

    def item(key, dependencies=()):
        return SRXPlanItem(key, "service", "root", key, key, dependencies=dependencies)

    ready = item("ready")
    assert _topological_order([
        item("missing", ("absent",)), item("a", ("b",)), item("b", ("a",)), ready,
    ]) == [ready]


def _render(analysis, options):
    plan = FortiGateToJuniperSRXPlanner().plan(
        analysis.extracted.config,
        analysis.derived,
        options,
        source_inventory=analysis.extracted.source_objects,
    )
    return JunosSetRenderer().render(plan)


def test_reviewable_set_output_is_deterministic_and_native_parser_round_trips(policy_analysis, complete_options):
    rendered = _render(policy_analysis, complete_options)
    repeated = _render(policy_analysis, complete_options)
    assert rendered == repeated
    assert rendered.command_count == len(rendered.commands)
    assert rendered.command_sha256 == hashlib.sha256(rendered.command_text.encode("utf-8")).hexdigest()
    assert rendered.commands
    assert all(command.startswith(("set ", "deactivate ")) for command in rendered.commands)
    assert not any("commit" in command or "delete" in command or "replace" in command
                   for command in rendered.commands)

    policy_lines = [line for line in rendered.commands if "security policies" in line]
    policy_items = _policy_items(policy_analysis, complete_options)
    assert next(i for i, line in enumerate(policy_lines) if policy_items[0].target_name in line) < \
        next(i for i, line in enumerate(policy_lines) if policy_items[1].target_name in line)
    assert "any-ipv4" in "\n".join(rendered.commands)
    assert "application any" in "\n".join(rendered.commands)
    assert any("session-init" in line for line in rendered.commands)
    assert any("session-close" in line for line in rendered.commands)
    change_window = next(item for item in _schedule_items(policy_analysis, complete_options)
                         if item.source_name == "change-window")
    assert f"set schedulers scheduler {change_window.target_name} start-date 2026-12-24.09.00" in rendered.commands
    assert f"set schedulers scheduler {change_window.target_name} stop-date 2026-12-24.11.00" in rendered.commands

    parsed = JuniperSRXSourceReporter().analyze_source(rendered.command_text)
    assert not parsed.config.unsupported_commands
    policy_view = parsed.derived.policy_relationships[0]["zone_policy_sets"]
    policies = [policy for row in policy_view for policy in row["policies"]]
    assert [policy["name"] for policy in policies][-2:] == [item.target_name for item in policy_items]
    assert all(edge["resolved"] for edge in parsed.derived.policy_relationships[0]["edges"])


def test_inactive_policy_is_emitted_as_deactivated(policy_analysis, complete_options):
    source = policy_analysis.extracted.config.model_copy(deep=True)
    source.policies[0] = source.policies[0].model_copy(update={"status": "disable"})
    from fwmigrate.vendors.fortigate.derived import build_derived_views
    analysis = SimpleNamespace(
        extracted=SimpleNamespace(config=source, source_objects=policy_analysis.extracted.source_objects),
        derived=build_derived_views(source),
    )
    rendered = _render(analysis, complete_options)
    policy_name = _policy_items(analysis, complete_options)[0].target_name
    assert any(line.startswith("deactivate security policies") and policy_name in line
               for line in rendered.commands)


def test_blocked_nat_and_dependency_chain_emit_no_policy_lines(policy_analysis, complete_options):
    source = policy_analysis.extracted.config.model_copy(deep=True)
    source.policies[0] = source.policies[0].model_copy(update={"nat": "enable"})
    source.policies[1] = source.policies[1].model_copy(update={"action": "accept"})
    from fwmigrate.vendors.fortigate.derived import build_derived_views
    plan = FortiGateToJuniperSRXPlanner().plan(
        source,
        build_derived_views(source),
        complete_options,
        source_inventory=policy_analysis.extracted.source_objects,
    )
    rendered = JunosSetRenderer().render(plan)
    assert not any("security policies" in line for line in rendered.commands)


def test_unapproved_predecessor_blocks_later_policy_lines(policy_analysis, complete_options):
    plan = FortiGateToJuniperSRXPlanner().plan(
        policy_analysis.extracted.config,
        policy_analysis.derived,
        complete_options,
        source_inventory=policy_analysis.extracted.source_objects,
    )
    first = next(item for item in plan.items if item.family == "policy")
    plan = replace(plan, items=tuple(
        replace(item, blockers=(*item.blockers, "DECISION_NOT_CONFIRMED")) if item.key == first.key else item
        for item in plan.items
    ))
    rendered = JunosSetRenderer().render(plan)
    assert not any("security policies" in line for line in rendered.commands)


def _policy_items(analysis, options):
    plan = FortiGateToJuniperSRXPlanner().plan(
        analysis.extracted.config,
        analysis.derived,
        options,
        source_inventory=analysis.extracted.source_objects,
    )
    return [item for item in plan.items if item.family == "policy"]


def _schedule_items(analysis, options):
    from fwmigrate.conversion.fortigate_to_juniper_srx.planning.schedules import plan_schedules

    return plan_schedules(analysis.extracted.config, options, "root")
