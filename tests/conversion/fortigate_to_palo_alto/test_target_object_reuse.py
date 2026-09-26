from types import SimpleNamespace

from fwmigrate.conversion.fortigate_to_palo_alto.decisions import (
    PANDecisionReviewState, PANMigrationDecision, PANMigrationDecisionSet,
)
from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedAddressGroup, PlannedServiceGroup,
    PlannedNATRule, PlannedStaticRoute, PlannedSchedule,
    PlannedZone, PlannedSecurityRule, PlannedService,
)
from fwmigrate.conversion.fortigate_to_palo_alto.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.conversion.fortigate_to_palo_alto.target_object_reuse import (
    classify_target_object_reuse, _address, _members, _schedule, _service,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target_plan_validation import (
    PANRenderDisposition, assess_target_plan, validate_target_plan,
)
from fwmigrate.conversion.fortigate_to_palo_alto.target_validation import PANTargetFinding
from fwmigrate.vendors.palo_alto.model.address import PANAddress, PANAddressGroup
from fwmigrate.vendors.palo_alto.model.schedule import PANSchedule, PANScheduleRecurring
from fwmigrate.vendors.palo_alto.model.service import PANService, PANServiceProtocol, PANServiceOverride
from fwmigrate.vendors.palo_alto.source_model import PANScope
from fwmigrate.vendors.palo_alto.model.routing import PANStaticRoute, PANVirtualRouter
from fwmigrate.vendors.palo_alto.model.nat import PANNATRule


def _target(address):
    return SimpleNamespace(config=SimpleNamespace(
        addresses=[address], address_groups=[], services=[], service_groups=[], schedules=[],
        scopes=[address.scope]), derived=SimpleNamespace(reference_index=None, scope_hierarchy=None))


def test_same_name_address_reuse_requires_exact_explicit_semantics():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_kind="address",
        source_object_type="address", source_name="lan-net", target_vsys="vsys1", target_name="lan-net",
        status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="192.0.2.0/24"),))
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    target_address = PANAddress(name="lan-net", source_path="/config/devices/entry/vsys/entry/address/entry",
        scope=scope, ip_netmask="192.0.2.0/24", explicit_fields={"ip_netmask"})
    reuse = classify_target_object_reuse(plan, _target(target_address), "dev")
    assert reuse[0]["status"] == "EXACT_MATCH"

    target_address.ip_netmask = "198.51.100.0/24"
    conflict = classify_target_object_reuse(plan, _target(target_address), "dev")
    assert conflict[0]["status"] == "NAME_CONFLICT"


def test_missing_target_explicit_field_is_not_treated_as_exact():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_kind="address",
        source_object_type="address", source_name="lan-net", target_vsys="vsys1", target_name="lan-net",
        status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="192.0.2.0/24"),))
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    target_address = PANAddress(name="lan-net", source_path="/config/devices/entry/vsys/entry/address/entry",
        scope=scope, ip_netmask="192.0.2.0/24", explicit_fields=set())
    result = classify_target_object_reuse(plan, _target(target_address), "dev")
    assert result[0]["status"] != "EXACT_MATCH"


def test_address_reuse_rejects_alternate_form_and_unknown_semantics():
    source = PlannedAddress(address_type="ip-netmask", value="192.0.2.1/32")
    alternate = PANAddress(source_path="/address", ip_netmask="192.0.2.1/32", ip_range="192.0.2.1-192.0.2.1",
                           explicit_fields={"ip_netmask", "ip_range"})
    assert _address(source, alternate)[2]
    unknown = PANAddress(source_path="/address", ip_netmask="192.0.2.1/32",
                         explicit_fields={"ip_netmask"}, raw_extra={"future": "value"})
    assert _address(source, unknown)[1]


def test_address_group_reuse_rejects_dynamic_or_unknown_semantics():
    source = PlannedAddressGroup(source_object_type="address_group", members=("a",))
    dynamic = PANAddressGroup(source_path="/group", static_members=["a"], dynamic_filter="tag eq x",
                              explicit_fields={"static_members", "dynamic_filter"})
    assert _members(source, dynamic)[1]
    unknown = PANAddressGroup(source_path="/group", static_members=["a"],
                              explicit_fields={"static_members"}, raw_extra={"future": "value"})
    assert _members(source, unknown)[1]


def test_shared_object_is_visible_to_the_selected_vsys_for_exact_reuse():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_object_type="address",
        source_name="lan-net", target_vsys="vsys1", target_name="lan-net",
        status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="192.0.2.0/24"),))
    shared = PANAddress(name="lan-net", source_path="/config/shared/address/entry",
        scope=PANScope(kind="shared", name="shared"), ip_netmask="192.0.2.0/24",
        explicit_fields={"ip_netmask"})
    target = SimpleNamespace(config=SimpleNamespace(addresses=[shared], scopes=[
        PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")]),
        derived=SimpleNamespace(reference_index=None, scope_hierarchy=None))
    assert classify_target_object_reuse(plan, target, "dev")[0]["status"] == "EXACT_MATCH"


def test_same_name_semantic_conflict_is_not_rendered():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_object_type="address", source_name="lan-net",
        target_vsys="vsys1", target_name="lan-net", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.0/24"),))
    reuse = ({"family": "address", "source_vdom": "root", "source_kind": None, "target_vsys": "vsys1",
        "source_name": "lan-net", "target_name": "lan-net", "status": "NAME_CONFLICT"},)
    decisions = PANMigrationDecisionSet()
    dispositions, blockers = assess_target_plan(plan, reuse, (), decisions, build_plan_dependency_index(plan, decisions))
    assert plan.addresses[0].status == PANMigrationStatus.SUPPORTED
    rendered = PANSetRenderer().render(plan, dispositions=dispositions, render_blockers=blockers)
    assert rendered.commands == ()
    assert rendered.report["items"][0]["render_disposition"] == "BLOCK"


def test_target_validation_error_blocks_rendering_only_in_affected_vdom():
    plan = PANMigrationPlan(addresses=(
        PlannedAddress(source_vdom="root", source_name="root-net", target_vsys="vsys1",
            target_name="root-net", status=PANMigrationStatus.SUPPORTED,
            address_type="ip-netmask", value="192.0.2.0/24"),
        PlannedAddress(source_vdom="blue", source_name="blue-net", target_vsys="vsys2",
            target_name="blue-net", status=PANMigrationStatus.SUPPORTED,
            address_type="ip-netmask", value="198.51.100.0/24"),
    ))
    decision = PANMigrationDecision("root", "vdom", "root", "vsys", value="vsys1",
                                    review_state=PANDecisionReviewState.CONFIRMED)
    finding = PANTargetFinding(decision.key, "TARGET_VSYS_CONFLICT", "error", "missing")
    decisions = PANMigrationDecisionSet((decision,))
    dependencies = build_plan_dependency_index(plan, decisions)
    dispositions, _ = assess_target_plan(plan, (), (finding,), decisions, dependencies)
    assert dispositions[item_key(plan.addresses[0])] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(plan.addresses[1])] is PANRenderDisposition.CREATE
    assert plan.addresses[0].status is plan.addresses[1].status is PANMigrationStatus.SUPPORTED


def test_interface_conflict_blocks_its_zone_dependents_only():
    plan = PANMigrationPlan(
        addresses=(PlannedAddress(source_vdom="root", source_object_type="address", source_name="web-net",
            target_vsys="vsys1", target_name="web-net", status=PANMigrationStatus.SUPPORTED,
            address_type="ip-netmask", value="192.0.2.0/24"),),
        services=(PlannedService(source_vdom="root", source_object_type="service", source_name="https",
            target_vsys="vsys1", target_name="https", status=PANMigrationStatus.SUPPORTED,
            protocol="tcp", destination_port="443"),),
        zones=(PlannedZone(source_vdom="root", source_kind="interface", source_name="lan",
            source_object_type="zone", target_vsys="vsys1", target_name="trust",
            status=PANMigrationStatus.SUPPORTED, interfaces=("ethernet1/1",)),),
        security_rules=(PlannedSecurityRule(source_vdom="root", source_kind="policy", source_name="allow-web",
            source_object_type="security_rule", target_vsys="vsys1", target_name="allow-web",
            status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("trust",),
            sources=("web-net",), destinations=("web-net",), services=("https",), action="allow"),),
    )
    decision = PANMigrationDecision("root", "interface", "lan", "target_interface", value="ethernet1/1",
                                    review_state=PANDecisionReviewState.CONFIRMED)
    finding = PANTargetFinding(decision.key, "TARGET_INTERFACE_FAMILY_MISMATCH", "error", "incompatible")
    decisions = PANMigrationDecisionSet((decision,))
    dependencies = build_plan_dependency_index(plan, decisions)
    dispositions, _ = assess_target_plan(plan, (), (finding,), decisions, dependencies)
    assert dispositions[item_key(plan.zones[0])] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(plan.security_rules[0])] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(plan.addresses[0])] is PANRenderDisposition.CREATE
    assert dispositions[item_key(plan.services[0])] is PANRenderDisposition.CREATE
    finding_result = validate_target_plan(plan, (), (finding,), decisions, dependencies)[0]
    assert finding_result.code == "TARGET_MAPPING_CONFLICT"
    assert finding_result.message == "incompatible"
    assert item_key(plan.security_rules[0]) in finding_result.affected_item_keys


def test_existing_route_destination_requires_exact_route_semantics_for_reuse():
    plan = PANMigrationPlan(static_routes=(PlannedStaticRoute(source_vdom="root", source_kind="static_route",
        source_object_type="static_route", source_name="10", target_name="10", status=PANMigrationStatus.SUPPORTED,
        destination="192.0.2.0/24", nexthop_type="ip-address", nexthop="192.0.2.1", admin_distance=10,
        virtual_router="vr-main"),))
    scope = PANScope(kind="device", name="dev", device_name="dev")
    existing = PANStaticRoute(name="10", source_path="/router/vr/static-route/entry", scope=scope,
        destination="192.0.2.0/24", nexthop_type="ip-address", nexthop_ip_address="192.0.2.1",
        admin_distance="10", explicit_fields={"destination", "nexthop_type", "nexthop_ip_address", "admin_distance"})
    target = SimpleNamespace(config=SimpleNamespace(virtual_routers=[PANVirtualRouter(name="vr-main",
        source_path="/router", scope=scope, static_routes=[existing])], interfaces=[], interface_units=[],
        zones=[], addresses=[], address_groups=[], services=[], service_groups=[], schedules=[]),
        derived=SimpleNamespace(reference_index=None, scope_hierarchy=None))
    collision = classify_target_object_reuse(plan, target, "dev")
    route = next(item for item in collision if item["family"] == "static_route")
    assert route["status"] == "AMBIGUOUS"
    existing.nexthop_ip_address = "198.51.100.1"
    collision = classify_target_object_reuse(plan, target, "dev")
    route = next(item for item in collision if item["family"] == "static_route")
    assert route["status"] == "NAME_CONFLICT"


def test_nat_overlap_is_reported_and_not_auto_reused():
    scope = PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev")
    planned = PlannedNATRule(source_vdom="root", source_name="nat1", target_name="nat1",
        target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED, from_zones=("TRUST",),
        to_zones=("UNTRUST",), source_addresses=("lan-net",), destination_addresses=("web-net",), service="https")
    target_rule = PANNATRule(name="existing-nat", source_path="/nat/rule", scope=scope,
        from_zones=["TRUST"], to_zones=["UNTRUST"], source=["lan-net"], destination=["web-net"],
        service="https", explicit_fields={"from_zones", "to_zones", "source", "destination", "service"})
    target = SimpleNamespace(config=SimpleNamespace(nat_rules=[target_rule]))
    collision = classify_target_object_reuse(PANMigrationPlan(nat_rules=(planned,)), target, "dev")
    assert collision[0]["status"] == "AMBIGUOUS"


def test_daily_schedule_reuse_compares_daily_fields_and_requires_explicit_target():
    planned = PlannedSchedule(schedule_type="recurring", daily=(("08:00", "17:00"),))
    target = PANSchedule(name="business-hours", source_path="/schedule", recurring=PANScheduleRecurring(
        daily=["08:00-17:00"], explicit_fields={"daily"}), explicit_fields={"recurring"})
    assert _schedule(planned, target)[0]
    target.recurring.explicit_fields.clear()
    assert not _schedule(planned, target)[0]


def test_weekly_and_non_recurring_schedule_comparisons_use_their_own_fields():
    weekly = PlannedSchedule(schedule_type="recurring", weekly=(("monday", "09:00", "17:00"),))
    target_weekly = PANSchedule(name="weekly", source_path="/schedule", recurring=PANScheduleRecurring(
        weekly={"monday": ["09:00-17:00"]}, explicit_fields={"weekly"}), explicit_fields={"recurring"})
    assert _schedule(weekly, target_weekly)[0]
    one_time = PlannedSchedule(schedule_type="one-time", non_recurring=(("2026/09/30@08:00", "2026/09/30@17:00"),))
    target_one_time = PANSchedule(name="one-time", source_path="/schedule",
        non_recurring=["2026/09/30@08:00-2026/09/30@17:00"], explicit_fields={"non_recurring"})
    assert _schedule(one_time, target_one_time)[0]


def test_schedule_reuse_rejects_additional_or_unknown_semantics():
    weekly = PlannedSchedule(schedule_type="recurring", weekly=(("monday", "09:00", "17:00"),))
    target = PANSchedule(source_path="/schedule", recurring=PANScheduleRecurring(
        daily=["09:00-17:00"], weekly={"monday": ["09:00-17:00"]}, explicit_fields={"daily", "weekly"}),
        explicit_fields={"recurring"})
    assert _schedule(weekly, target)[1]
    one_time = PlannedSchedule(schedule_type="one-time", non_recurring=(("start", "end"),))
    target_one_time = PANSchedule(source_path="/schedule", non_recurring=["start-end"],
        recurring=PANScheduleRecurring(daily=["08:00-09:00"], explicit_fields={"daily"}),
        explicit_fields={"non_recurring", "recurring"})
    assert _schedule(one_time, target_one_time)[1]


def test_service_reuse_rejects_overrides_and_unknown_protocol_semantics():
    source = PlannedService(protocol="tcp", destination_port="443")
    override = PANService(source_path="/service", tcp=PANServiceProtocol(port="443", source_port="",
        override=PANServiceOverride(timeout="3600"), explicit_fields={"port", "source_port", "override"}),
        explicit_fields={"tcp"})
    assert _service(source, override)[1]
    unknown = PANService(source_path="/service", tcp=PANServiceProtocol(port="443", source_port="",
        raw_extra={"future": "value"}, explicit_fields={"port", "source_port"}), explicit_fields={"tcp"})
    assert _service(source, unknown)[1]


def test_exact_object_reuse_skips_creation_command_and_keeps_plan_unchanged():
    plan = PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_kind="address",
        source_object_type="address", source_name="lan-net", target_vsys="vsys1", target_name="lan-net",
        status=PANMigrationStatus.SUPPORTED, address_type="ip-netmask", value="192.0.2.0/24"),))
    target_address = PANAddress(name="lan-net", source_path="/config/devices/entry/vsys/entry/address/entry",
        scope=PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev"),
        ip_netmask="192.0.2.0/24", explicit_fields={"ip_netmask"})
    reuse = classify_target_object_reuse(plan, _target(target_address), "dev")
    decisions = PANMigrationDecisionSet()
    dispositions, _ = assess_target_plan(plan, reuse, (), decisions, build_plan_dependency_index(plan, decisions))
    rendered = PANSetRenderer().render(plan, dispositions=dispositions)
    assert plan.addresses[0].status is PANMigrationStatus.SUPPORTED
    assert rendered.commands == ()
    assert rendered.report["items"][0]["render_disposition"] == "REUSE"


def test_reused_address_remains_available_to_a_rendered_policy():
    address = PlannedAddress(source_vdom="root", source_object_type="address", source_name="lan-net",
        target_vsys="vsys1", target_name="lan-net", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.0/24")
    service = PlannedService(source_vdom="root", source_object_type="service", source_name="https",
        target_vsys="vsys1", target_name="https", status=PANMigrationStatus.SUPPORTED,
        protocol="tcp", destination_port="443")
    zones = tuple(PlannedZone(source_vdom="root", source_object_type="zone", source_name=name,
        target_vsys="vsys1", target_name=name, status=PANMigrationStatus.SUPPORTED,
        interfaces=(f"ethernet1/{index}",)) for index, name in enumerate(("trust", "untrust"), 1))
    rule = PlannedSecurityRule(source_vdom="root", source_object_type="security_rule", source_name="allow-web",
        target_vsys="vsys1", target_name="allow-web", status=PANMigrationStatus.SUPPORTED,
        from_zones=("trust",), to_zones=("untrust",), sources=("lan-net",), destinations=("any",),
        services=("https",), action="allow")
    plan = PANMigrationPlan(addresses=(address,), services=(service,), zones=zones, security_rules=(rule,))
    target_address = PANAddress(name="lan-net", source_path="/config/devices/entry/vsys/entry/address/entry",
        scope=PANScope(kind="vsys", name="vsys1", vsys="vsys1", device_name="dev"),
        ip_netmask="192.0.2.0/24", explicit_fields={"ip_netmask"})
    reuse = classify_target_object_reuse(plan, _target(target_address), "dev")
    decisions = PANMigrationDecisionSet()
    dispositions, _ = assess_target_plan(plan, reuse, (), decisions, build_plan_dependency_index(plan, decisions))
    rendered = PANSetRenderer().render(plan, dispositions=dispositions)
    assert not any("address lan-net" in command for command in rendered.commands)
    assert any("allow-web" in command for command in rendered.commands), rendered.commands
    assert any("lan-net" in command and "source" in command for command in rendered.commands), rendered.commands


def test_dependency_index_scopes_same_names_by_object_family():
    address = PlannedAddress(source_vdom="root", source_kind="address", source_object_type="address",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.1/32")
    group = PlannedAddressGroup(source_vdom="root", source_kind="address_group", source_object_type="address_group",
        source_name="group", target_vsys="vsys1", target_name="group", status=PANMigrationStatus.SUPPORTED,
        members=("web",))
    service = PlannedService(source_vdom="root", source_kind="service", source_object_type="service",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        protocol="tcp", destination_port="443")
    rule = PlannedSecurityRule(source_vdom="root", source_kind="policy", source_object_type="security_rule",
        source_name="allow-web", target_vsys="vsys1", target_name="allow-web", status=PANMigrationStatus.SUPPORTED,
        sources=("web",), services=("web",), action="allow")
    plan = PANMigrationPlan(addresses=(address,), address_groups=(group,), services=(service,), security_rules=(rule,))
    index = build_plan_dependency_index(plan, PANMigrationDecisionSet())
    assert item_key(group) in index.dependents_by_item[item_key(address)]
    assert item_key(rule) in index.dependents_by_item[item_key(address)]
    assert item_key(rule) in index.dependents_by_item[item_key(service)]
    assert item_key(service) not in index.dependents_by_item[item_key(address)]


def test_expanded_dependency_blocks_address_consumers_but_not_same_name_service():
    address = PlannedAddress(source_vdom="root", source_kind="address", source_object_type="address",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.1/32")
    group = PlannedAddressGroup(source_vdom="root", source_kind="address_group", source_object_type="address_group",
        source_name="group", target_vsys="vsys1", target_name="group", status=PANMigrationStatus.SUPPORTED,
        members=("web",))
    service = PlannedService(source_vdom="root", source_kind="service", source_object_type="service",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        protocol="tcp", destination_port="443")
    rule = PlannedSecurityRule(source_vdom="root", source_kind="policy", source_object_type="security_rule",
        source_name="allow-web", target_vsys="vsys1", target_name="allow-web", status=PANMigrationStatus.SUPPORTED,
        sources=("web",), services=("web",), action="allow")
    plan = PANMigrationPlan(addresses=(address,), address_groups=(group,), services=(service,), security_rules=(rule,))
    reuse = ({"status": "NAME_CONFLICT", "family": "address", "source_vdom": "root",
              "source_kind": "address", "target_vsys": "vsys1",
              "source_name": "web", "target_name": "web"},)
    dependencies = build_plan_dependency_index(plan, PANMigrationDecisionSet())
    dispositions, _ = assess_target_plan(plan, reuse, (), PANMigrationDecisionSet(), dependencies)
    assert dispositions[item_key(address)] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(group)] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(rule)] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(service)] is PANRenderDisposition.CREATE


def test_target_conflicts_do_not_cross_associate_same_name_different_source_kinds():
    first = PlannedAddress(source_vdom="root", source_kind="address", source_object_type="address",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.1/32")
    second = PlannedAddress(source_vdom="root", source_kind="vip", source_object_type="address",
        source_name="web", target_vsys="vsys1", target_name="web", status=PANMigrationStatus.SUPPORTED,
        address_type="ip-netmask", value="192.0.2.2/32")
    plan = PANMigrationPlan(addresses=(first, second))
    decisions = PANMigrationDecisionSet()
    dependencies = build_plan_dependency_index(plan, decisions)
    conflict = ({"status": "NAME_CONFLICT", "family": "address", "source_vdom": "root",
                 "source_kind": "address", "target_vsys": "vsys1", "source_name": "web", "target_name": "web"},)
    dispositions, _ = assess_target_plan(plan, conflict, (), decisions, dependencies)
    finding = validate_target_plan(plan, conflict, (), decisions, dependencies)[0]
    assert dispositions[item_key(first)] is PANRenderDisposition.BLOCK
    assert dispositions[item_key(second)] is PANRenderDisposition.CREATE
    assert finding.affected_item_keys == (item_key(first),)
