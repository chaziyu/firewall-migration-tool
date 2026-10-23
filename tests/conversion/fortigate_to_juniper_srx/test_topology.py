from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_juniper_srx import (
    FortiGateToJuniperSRXPlanner,
    SRXInterfaceMapping,
)
from fwmigrate.vendors.fortigate.derived import build_derived_views


def _settings(item):
    return dict(item.settings)


def test_explicit_interfaces_vlan_parent_zones_and_static_routes_are_mapped(explicit_analysis, complete_options):
    source = explicit_analysis.extracted.config.model_copy(deep=True)
    source.static_routes[0].status = "enable"
    source.static_routes[0].explicit_fields.add("status")
    plan = FortiGateToJuniperSRXPlanner().plan(
        source, build_derived_views(source), complete_options
    )
    items = {item.family + ":" + item.source_name: item for item in plan.items}
    vlan = items["interface:app-vlan"]
    lan = items["interface:lan"]
    assert vlan.disposition == "BLOCK"
    assert "VLAN_PLATFORM_COMPATIBILITY_UNVERIFIED" in vlan.blockers
    assert vlan.target_name == "ge-0/0/0.120"
    assert lan.key in vlan.dependencies

    inside = items["zone:inside"]
    assert _settings(inside)["interfaces"] == (lan.target_name, vlan.target_name)
    assert inside.dependencies == (lan.key, vlan.key)
    assert inside.disposition == "BLOCK"
    assert "ZONE_INTERFACE_MEMBER_BLOCKED" in inside.blockers

    route = items["static_route:1"]
    assert route.disposition == "CREATE"
    assert _settings(route)["destination"] == "0.0.0.0/0"
    assert _settings(route)["next_hop"] == "203.0.113.1"
    assert route.dependencies == (items["interface:wan"].key,)


@pytest.mark.parametrize("status", [None, "disable", "unknown", "enable"])
def test_route_requires_explicit_enabled_state(explicit_analysis, complete_options, status):
    from fwmigrate.conversion.fortigate_to_juniper_srx.application.workflow import (
        approve_design, build_review,
    )
    from fwmigrate.conversion.fortigate_to_juniper_srx.rendering.renderer import JunosSetRenderer

    source = explicit_analysis.extracted.config
    source.static_routes[0].status = status
    if status is not None:
        source.static_routes[0].explicit_fields.add("status")
    review = build_review(explicit_analysis, complete_options, "source")
    route = next(item for item in review["plan"].items if item.family == "static_route" and item.source_name == "1")
    rendered = JunosSetRenderer().render(review["plan"])
    if status == "enable":
        assert not route.blockers
        assert any("static route 0.0.0.0/0 " in line for line in rendered.commands)
    else:
        assert "STATIC_ROUTE_STATUS_NOT_EXPLICITLY_ENABLED" in route.blockers
        assert not any("static route 0.0.0.0/0 " in line for line in rendered.commands)
        with pytest.raises(ValueError, match="blocked|Blocked"):
            approve_design(review, review["draft"], [route.key])


def test_route_with_unknown_source_settings_cannot_render(explicit_analysis, complete_options):
    from fwmigrate.conversion.fortigate_to_juniper_srx.rendering.renderer import JunosSetRenderer

    source = explicit_analysis.extracted.config
    source.static_routes[0].status = "enable"
    source.static_routes[0].explicit_fields.add("status")
    source.static_routes[0].raw_extra["future-route-setting"] = "preserved"
    plan = FortiGateToJuniperSRXPlanner().plan(source, explicit_analysis.derived, complete_options)
    route = next(item for item in plan.items if item.family == "static_route" and item.source_name == "1")
    assert "STATIC_ROUTE_HAS_UNSUPPORTED_SOURCE_SETTINGS" in route.blockers
    assert not any("static route 0.0.0.0/0 " in line for line in JunosSetRenderer().render(plan).commands)


def test_missing_scope_target_choices_and_interface_mapping_fail_closed(explicit_analysis):
    plan = FortiGateToJuniperSRXPlanner().plan(
        explicit_analysis.extracted.config, explicit_analysis.derived
    )

    codes = {finding.code for finding in plan.findings}
    assert {"SOURCE_VDOM_REQUIRED", "TARGET_CONTEXT_REQUIRED", "TARGET_VERSION_REQUIRED",
            "TARGET_MODE_REQUIRED", "ROUTING_TABLE_REQUIRED"} <= codes
    assert plan.items == ()


def test_incompatible_zone_merge_and_wrong_vlan_parent_block_topology(explicit_analysis, complete_options):
    options = replace(
        complete_options,
        zones={"root": {"inside": "shared-zone", "outside": "shared-zone"}},
        interfaces={"root": {
            "lan": SRXInterfaceMapping("ge-0/0/0", 0),
            "wan": SRXInterfaceMapping("ge-0/0/1", 0),
            "app-vlan": SRXInterfaceMapping("ge-0/0/2", 120),
        }},
    )
    plan = FortiGateToJuniperSRXPlanner().plan(
        explicit_analysis.extracted.config, explicit_analysis.derived, options
    )
    items = {item.family + ":" + item.source_name: item for item in plan.items}

    assert "VLAN_TARGET_INTERFACE_DIFFERS_FROM_MAPPED_PARENT" in items["interface:app-vlan"].blockers
    assert "TARGET_ZONE_MERGES_SOURCE_ZONES" in items["zone:inside"].blockers
    assert "TARGET_ZONE_MERGES_SOURCE_ZONES" in items["zone:outside"].blockers


def test_duplicate_target_physical_ownership_and_source_interface_names_block(explicit_analysis, complete_options):
    options = replace(
        complete_options,
        interfaces={"root": {
            "lan": SRXInterfaceMapping("ge-0/0/0", 0),
            "wan": SRXInterfaceMapping("ge-0/0/0", 0),
            "app-vlan": SRXInterfaceMapping("ge-0/0/0", 120),
        }},
    )
    plan = FortiGateToJuniperSRXPlanner().plan(
        explicit_analysis.extracted.config, explicit_analysis.derived, options
    )
    items = {item.family + ":" + item.source_name: item for item in plan.items}
    assert "DUPLICATE_TARGET_PHYSICAL_INTERFACE" in items["interface:lan"].blockers
    assert "DUPLICATE_TARGET_PHYSICAL_INTERFACE" in items["interface:wan"].blockers

    source = explicit_analysis.extracted.config.model_copy(deep=True)
    source.interfaces.append(source.interfaces[0].model_copy(deep=True))
    derived = build_derived_views(source)
    duplicate_plan = FortiGateToJuniperSRXPlanner().plan(source, derived, complete_options)
    duplicate_lan = [item for item in duplicate_plan.items
                     if item.family == "interface" and item.source_name == "lan"]
    assert len(duplicate_lan) == 1
    assert "DUPLICATE_SOURCE_INTERFACE" in duplicate_lan[0].blockers


def test_route_missing_gateway_distance_and_invalid_unit_are_rejected(blocker_analysis, complete_options):
    plan = FortiGateToJuniperSRXPlanner().plan(
        blocker_analysis.extracted.config, blocker_analysis.derived, complete_options
    )
    route = next(item for item in plan.items if item.family == "static_route")
    assert "STATIC_ROUTE_GATEWAY_NOT_EXPLICIT_IPV4" in route.blockers
    assert "STATIC_ROUTE_DISTANCE_NOT_EXPLICIT" in route.blockers
    with pytest.raises(ValueError):
        SRXInterfaceMapping("ge-0/0/0", 16386)


def test_route_preference_outside_junos_range_is_blocked(explicit_analysis, complete_options):
    source = explicit_analysis.extracted.config.model_copy(deep=True)
    source.static_routes[0] = source.static_routes[0].model_copy(update={"distance": -1})
    derived = build_derived_views(source)
    plan = FortiGateToJuniperSRXPlanner().plan(source, derived, complete_options)
    route = next(item for item in plan.items if item.family == "static_route" and item.source_name == "1")
    assert "STATIC_ROUTE_DISTANCE_INVALID_FOR_TARGET" in route.blockers


def test_one_vdom_can_be_planned_while_other_vdom_remains_visible_manual(blocker_analysis, complete_options):
    plan = FortiGateToJuniperSRXPlanner().plan(
        blocker_analysis.extracted.config, blocker_analysis.derived, complete_options
    )
    manual = [finding for finding in plan.findings if finding.code == "OTHER_VDOM_REMAINS_MANUAL"]
    assert manual and all(not finding.blocking for finding in manual)
