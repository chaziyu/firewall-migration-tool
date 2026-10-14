from types import SimpleNamespace
import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.models import (
    PANMigrationPlan, PANMigrationStatus, PlannedAddress, PlannedAddressGroup,
    PlannedNATRule, PlannedSchedule, PlannedSecurityRule, PlannedService,
    PlannedServiceGroup, PlannedZone,
)
from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import plan_nat
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.planning.routing import plan_routes
from fwmigrate.conversion.fortigate_to_palo_alto.validation import validate_plan
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.address import FGAddress, FGAddressGroup
from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute
from fwmigrate.vendors.fortigate.model.source import FGConfig


@pytest.mark.parametrize('src4,dst4,src6,dst6,supported', [
    (['all'], ['all'], None, None, True),
    (None, None, ['v6-source'], ['v6-destination'], False),
    (['all'], ['all'], ['v6-source'], ['v6-destination'], False),
    (['all'], ['all'], [], [], False),
    ([], [], ['v6-source'], ['v6-destination'], False),
    (None, None, None, None, False),
    ([], [], None, None, False),
])
def test_policy_address_families_never_fall_back_or_drop_ipv6(src4, dst4, src6, dst6, supported):
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import plan_policies
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    policy = FGPolicy(vdom='root', policy_id=42, name='family-policy',
        srcintf=['lan'], dstintf=['wan'], srcaddr=src4, dstaddr=dst4, srcaddr6=src6, dstaddr6=dst6,
        service=['ALL'], schedule='always', action='accept')
    config = FGConfig(policies=[policy])
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}, interfaces={'root': {
        'lan': {'target_zone': 'trust'}, 'wan': {'target_zone': 'untrust'}}})
    rules = plan_policies(config, options)
    plan = PANMigrationPlan(security_rules=rules, zones=(
        PlannedZone(source_vdom='root', source_kind='zone', source_name='trust',
            target_name='trust', target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED),
        PlannedZone(source_vdom='root', source_kind='zone', source_name='untrust',
            target_name='untrust', target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED)))
    validation = validate_plan(plan)
    artifact = PANSetRenderer().render(plan, validation)
    assert any('set vsys vsys1 rulebase security' in command for command in artifact.commands) == supported
    assert config.policies[0].srcaddr6 == src6
    rule = artifact.report['items'][-1]
    assert rule['source_policy_id'] == 42
    if src6 is not None or dst6 is not None:
        assert rules[0].status is PANMigrationStatus.UNSUPPORTED
        assert rules[0].sources == tuple('0.0.0.0/0' if name == 'all' else name for name in (src4 or ()))
        assert f'explicit source srcaddr6 = {src6!r}' in rule['warnings']
        assert f'explicit source dstaddr6 = {dst6!r}' in rule['warnings']
        assert rule['render_disposition'] == 'BLOCK'


def _objects(*, address_status=PANMigrationStatus.SUPPORTED, service_status=PANMigrationStatus.SUPPORTED,
             schedule_status=PANMigrationStatus.SUPPORTED, group_member="host", service_member="https"):
    return dict(
        addresses=(PlannedAddress(source_object_type="address", source_name="host", target_vsys="vsys1",
                                  status=address_status, address_type="ip-netmask", value="192.0.2.5/32"),),
        address_groups=(PlannedAddressGroup(source_object_type="address_group", source_name="hosts", target_vsys="vsys1",
                                            status=PANMigrationStatus.SUPPORTED, members=(group_member,)),),
        services=(PlannedService(source_object_type="service", source_name="https", target_vsys="vsys1",
                                 status=service_status, protocol="tcp", destination_port="443"),),
        service_groups=(PlannedServiceGroup(source_object_type="service_group", source_name="web", target_vsys="vsys1",
                                            status=PANMigrationStatus.SUPPORTED, members=(service_member,)),),
        schedules=(PlannedSchedule(source_object_type="schedule", source_name="work-hours", target_vsys="vsys1",
                                   status=schedule_status, schedule_type="weekly", weekly=(("monday", "08:00", "17:00"),)),),
        zones=(PlannedZone(source_object_type="zone", source_name="trust", target_vsys="vsys1",
                           status=PANMigrationStatus.SUPPORTED),),
    )


def _rule(**updates):
    values = dict(source_object_type="security_rule", source_name="allow", target_vsys="vsys1",
                  status=PANMigrationStatus.SUPPORTED, from_zones=("trust",), to_zones=("trust",),
                  sources=("hosts",), destinations=("any",), services=("web",), action="allow")
    values.update(updates)
    return PlannedSecurityRule(**values)


def test_unsupported_address_blocks_group_and_security_rule_transitively():
    plan = PANMigrationPlan(**_objects(address_status=PANMigrationStatus.UNSUPPORTED), security_rules=(_rule(),))
    result = validate_plan(plan)
    assert not any(key[0] in {"address_group", "security_rule"} for key in result.renderable_item_keys)
    assert {issue.code for issue in result.issues} >= {"dependency_not_renderable"}


def test_unsupported_service_blocks_service_group_and_security_rule_transitively():
    plan = PANMigrationPlan(**_objects(service_status=PANMigrationStatus.UNSUPPORTED), security_rules=(_rule(),))
    result = validate_plan(plan)
    assert not any(key[0] in {"service_group", "security_rule"} for key in result.renderable_item_keys)
    assert sum(issue.code == "dependency_not_renderable" for issue in result.issues) >= 2


def test_manual_or_missing_schedule_blocks_security_rule():
    objects = _objects(schedule_status=PANMigrationStatus.MANUAL_REVIEW)
    plan = PANMigrationPlan(**objects, security_rules=(_rule(schedule="work-hours"),))
    result = validate_plan(plan)
    assert not any(key[0] == "security_rule" for key in result.renderable_item_keys)
    assert any(issue.code == "dependency_not_renderable" for issue in result.issues)

    missing = PANMigrationPlan(**_objects(), security_rules=(_rule(schedule="missing"),))
    missing_result = validate_plan(missing)
    assert not any(key[0] == "security_rule" for key in missing_result.renderable_item_keys)
    assert any(issue.code == "missing_schedule" for issue in missing_result.issues)


def test_renderable_address_and_service_groups_are_valid_rule_references():
    plan = PANMigrationPlan(**_objects(), security_rules=(_rule(),))
    result = validate_plan(plan)
    assert ("security_rule", "vsys1", "allow") in result.renderable_item_keys


def test_missing_group_member_blocks_group_and_dependent_rule():
    plan = PANMigrationPlan(**_objects(group_member="absent"), security_rules=(_rule(),))
    result = validate_plan(plan)
    assert not any(key[0] in {"address_group", "security_rule"} for key in result.renderable_item_keys)
    assert any(issue.code == "missing_group_member" for issue in result.issues)


def test_nat_planner_does_not_truncate_multiple_policy_services():
    policy = SimpleNamespace(vdom="root", policy_id=10, name="outbound", srcintf=["lan"],
                             srcaddr=["clients"], dstaddr=["any"], service=["http", "https"])
    nat = SimpleNamespace(vdom="root", policy_id=10, policy_name="outbound", egress_interfaces=["wan"],
                          translated_addresses=["203.0.113.8"], translation_type="ip_pool", pool_types=("overload",), issues=())
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"}, "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"}}})
    planned = plan_nat(SimpleNamespace(policies=(policy,), vips=()), SimpleNamespace(nat=(nat,)), options)[0]
    assert planned.service is None
    assert planned.status is PANMigrationStatus.MANUAL_REVIEW
    assert any("multiple services" in warning for warning in planned.warnings)


def test_nat_planner_marks_missing_zone_mapping_for_review():
    policy = SimpleNamespace(vdom="root", policy_id=10, name="outbound", srcintf=["unmapped"],
                             srcaddr=["clients"], dstaddr=["any"], service=["https"])
    nat = SimpleNamespace(vdom="root", policy_id=10, policy_name="outbound", egress_interfaces=["wan"],
                          translated_addresses=["203.0.113.8"], translation_type="ip_pool", pool_types=("overload",), issues=())
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"}}})
    planned = plan_nat(SimpleNamespace(policies=(policy,), vips=()), SimpleNamespace(nat=(nat,)), options)[0]
    assert planned.from_zones == ()
    assert planned.status is PANMigrationStatus.MANUAL_REVIEW
    assert any("zone mapping is incomplete" in warning for warning in planned.warnings)


def test_nat_validation_blocks_incomplete_source_nat_fields():
    nat = PlannedNATRule(source_object_type="nat_rule", source_kind="source_nat", source_name="outbound",
                         target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
                         source_translation_type="dynamic-ip-and-port", translated_addresses=("203.0.113.8",))
    result = validate_plan(PANMigrationPlan(nat_rules=(nat,)))
    assert not result.renderable_item_keys
    assert {issue.code for issue in result.issues} >= {"missing_nat_zone", "missing_nat_address", "missing_nat_service", "missing_nat_interface"}


def test_nat_validation_blocks_vip_without_required_zone_mappings():
    vip = PlannedNATRule(source_object_type="nat_rule", source_kind="vip", source_name="web-vip",
                         target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
                         destination_addresses=("198.51.100.10",), destination_translated_address="10.0.0.10")
    result = validate_plan(PANMigrationPlan(nat_rules=(vip,)))
    assert not result.renderable_item_keys
    assert any(issue.code == "missing_nat_zone" for issue in result.issues)


def test_route_dstaddr_resolves_only_direct_subnet_address():
    config = FGConfig(
        # A bare address does not carry an explicit mask and cannot define a route prefix.
        addresses=[FGAddress(name="servers", subnet="10.0.0.0 255.255.255.0"),
                   FGAddress(name="host-only", subnet="192.0.2.7")],
        address_groups=[FGAddressGroup(name="server-group", members=["servers"])],
        static_routes=[FGStaticRoute(seq_num=1, dstaddr="servers", gateway="192.0.2.1"),
                       FGStaticRoute(seq_num=2, dstaddr="server-group", gateway="192.0.2.1"),
                       FGStaticRoute(seq_num=3, dstaddr="missing", gateway="192.0.2.1"),
                       FGStaticRoute(seq_num=4, dstaddr="host-only", gateway="192.0.2.1")],
    )
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}})
    routes = plan_routes(config, options, build_derived_views(config))
    assert routes[0].destination == "10.0.0.0/24"
    assert routes[0].status is PANMigrationStatus.SUPPORTED
    assert routes[1].destination is None and routes[1].status is PANMigrationStatus.MANUAL_REVIEW
    assert routes[2].destination is None and routes[2].status is PANMigrationStatus.MANUAL_REVIEW
    assert routes[3].destination is None and routes[3].status is PANMigrationStatus.MANUAL_REVIEW


def test_static_route_disabled_and_any_explicit_priority_require_review():
    from fwmigrate.conversion.fortigate_to_palo_alto.options import VDOMMapping
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
    from fwmigrate.vendors.fortigate.model.route_static import FGStaticRoute

    options = PANMigrationOptions(vdoms={"root": VDOMMapping(virtual_router="vr1")})
    routes = plan_routes(FGConfig(static_routes=[
        FGStaticRoute(seq_num=1, dst="192.0.2.0/24", status="disable"),
        FGStaticRoute(seq_num=2, dst="198.51.100.0/24", priority=0, explicit_fields={"priority"}),
        FGStaticRoute(seq_num=3, dst="203.0.113.0/24", priority=10, explicit_fields={"priority"}),
        FGStaticRoute(seq_num=4, dst="10.0.0.0/24"),
    ]), options)
    assert [route.status for route in routes] == [PANMigrationStatus.MANUAL_REVIEW] * 3 + [PANMigrationStatus.SUPPORTED]
    assert routes[1].priority == 0
    assert any("priority" in warning for warning in routes[1].warnings)


def test_address_group_exclusion_uses_explicit_fortigate_values():
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.addresses import _plan_group
    from fwmigrate.conversion.fortigate_to_palo_alto.options import VDOMMapping
    from fwmigrate.vendors.fortigate.model.address import FGAddressGroup

    options = PANMigrationOptions(vdoms={"root": VDOMMapping(vsys="vsys1")})
    disabled, _ = _plan_group(FGAddressGroup(name="g", members=["a"], exclude="disable"), options)
    enabled, _ = _plan_group(FGAddressGroup(name="g", members=["a"], exclude="enable"), options)
    missing, _ = _plan_group(FGAddressGroup(name="g", members=["a"], exclude_members=["b"]), options)
    assert disabled.status is PANMigrationStatus.SUPPORTED
    assert enabled.status is PANMigrationStatus.MANUAL_REVIEW
    assert missing.status is PANMigrationStatus.MANUAL_REVIEW


def test_fortigate_source_nat_transform_to_renderer_is_fail_closed():
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    from fwmigrate.vendors.fortigate.model.interface import FGInterface
    from fwmigrate.vendors.fortigate.model.ippool import FGIPPool
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.fortigate.transform.nat import transform_nat

    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"},
        "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"},
    }})
    base_policy = dict(policy_id=90, name="outbound", nat="enable", srcintf=["lan"], dstintf=["wan"],
                       srcaddr=["any"], dstaddr=["any"], service=["any"], status="enable", action="accept", schedule="always")
    interface_source = FGConfig(interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")],
        policies=[FGPolicy(**base_policy)])
    interface_derived = SimpleNamespace(nat=tuple(transform_nat(interface_source)))
    interface_rule = plan_nat(interface_source, interface_derived, options)[0]
    zones = tuple(PlannedZone(source_object_type="zone", source_name=name, target_name=target,
                              target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED)
                  for name, target in (("lan", "trust"), ("wan", "untrust")))
    rendered = PANSetRenderer().render(PANMigrationPlan(zones=zones, nat_rules=(interface_rule,)))
    assert interface_rule.status is PANMigrationStatus.SUPPORTED
    assert "set vsys vsys1 rulebase nat rules outbound source-translation dynamic-ip-and-port interface-address interface ethernet1/1" in rendered.commands

    pool_source = FGConfig(interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")],
        ip_pools=[FGIPPool(name="PAT", type="overload", startip="203.0.113.8", endip="203.0.113.8",
                           explicit_fields={"type"})],
        policies=[FGPolicy(**{**base_policy, "ippool": "enable", "poolname": ["PAT"]})])
    pool_derived = SimpleNamespace(nat=tuple(transform_nat(pool_source)))
    pool_rule = plan_nat(pool_source, pool_derived, options)[0]
    pool_rendered = PANSetRenderer().render(PANMigrationPlan(zones=zones, nat_rules=(pool_rule,)))
    assert pool_rule.status is PANMigrationStatus.SUPPORTED
    assert any("translated-address [ 203.0.113.8 ]" in command for command in pool_rendered.commands)

    unsupported_source = FGConfig(interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")],
        ip_pools=[FGIPPool(name="ONE-TO-ONE", type="one-to-one", startip="203.0.113.8",
                           endip="203.0.113.8", explicit_fields={"type"})],
        policies=[FGPolicy(**{**base_policy, "ippool": "enable", "poolname": ["ONE-TO-ONE"]})])
    unsupported_rule = plan_nat(unsupported_source,
        SimpleNamespace(nat=tuple(transform_nat(unsupported_source))), options)[0]
    unsupported_rendered = PANSetRenderer().render(PANMigrationPlan(zones=zones, nat_rules=(unsupported_rule,)))
    assert unsupported_rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert unsupported_rule.translated_addresses == ("203.0.113.8",)
    assert not unsupported_rendered.commands

    disabled_source = FGConfig(interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")],
        policies=[FGPolicy(**{**base_policy, "status": "disable"})])
    disabled_rule = plan_nat(disabled_source, SimpleNamespace(nat=tuple(transform_nat(disabled_source))), options)[0]
    disabled_rendered = PANSetRenderer().render(PANMigrationPlan(zones=zones, nat_rules=(disabled_rule,)))
    assert disabled_rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert not disabled_rendered.commands


def test_parsed_fortigate_cli_pool_nat_reaches_palo_alto_renderer():
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter

    analysis = FortiGateSourceReporter().analyze_source('''config system interface
    edit "lan"
        set ip 10.0.0.1 255.255.255.0
    next
    edit "wan"
        set ip 203.0.113.1 255.255.255.0
    next
end
config firewall ippool
    edit "PAT"
        set type overload
        set startip 203.0.113.8
        set endip 203.0.113.8
    next
end
config firewall policy
    edit 90
        set name "outbound"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "any"
        set dstaddr "any"
        set service "any"
        set nat enable
        set action accept
        set schedule always
        set ippool enable
        set poolname "PAT"
    next
end
''')
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"},
        "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"},
    }})
    rule = plan_nat(analysis.extracted.config, analysis.derived, options)[0]
    zones = tuple(PlannedZone(source_object_type="zone", source_name=name, target_name=target,
                              target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED)
                  for name, target in (("lan", "trust"), ("wan", "untrust")))
    rendered = PANSetRenderer().render(PANMigrationPlan(zones=zones, nat_rules=(rule,)))
    assert rule.status is PANMigrationStatus.SUPPORTED
    assert any("source-translation dynamic-ip-and-port translated-address [ 203.0.113.8 ]" in command
               for command in rendered.commands)


@pytest.mark.parametrize("updates", [
    {"srcaddr_negate": "enable"}, {"dstaddr_negate": "enable"}, {"service_negate": "enable"},
    {"internet_service": "enable"}, {"internet_service_src_name": ["example"]},
    {"users": ["alice"]}, {"groups": ["staff"]}, {"schedule": "work-hours"}, {"schedule": None},
    {"action": "deny"}, {"action": None}, {"raw_extra": {"match-vip": "enable"}},
])
def test_snat_unrepresented_policy_conditions_emit_no_commands(updates):
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.fortigate.model.interface import FGInterface
    from fwmigrate.vendors.fortigate.transform.nat import transform_nat
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer

    values = dict(policy_id=1, name="unsafe", nat="enable", action="accept", schedule="always",
                  srcintf=["lan"], dstintf=["wan"], srcaddr=["all"], dstaddr=["all"], service=["ALL"])
    config = FGConfig(policies=[FGPolicy(**{**values, **updates})],
                      interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")])
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"}, "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"}}})
    rules = plan_nat(config, SimpleNamespace(nat=tuple(transform_nat(config))), options)
    assert rules[0].status is PANMigrationStatus.MANUAL_REVIEW
    rendered = PANSetRenderer().render(PANMigrationPlan(nat_rules=rules))
    assert rendered.commands == ()
    assert rendered.report["items"][0]["warnings"]
    for field, value in updates.items():
        assert getattr(config.policies[0], field) == value


@pytest.mark.parametrize("distance,supported", [(9, False), (10, True), (240, True), (241, False), (None, True)])
def test_route_distance_source_and_direct_plan_validation(distance, supported):
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedStaticRoute
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer

    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1", "virtual_router": "default"}})
    source = FGConfig(static_routes=[FGStaticRoute(seq_num=1, dst="192.0.2.0/24", gateway="198.51.100.1", distance=distance)])
    route = plan_routes(source, options)[0]
    assert (route.status is PANMigrationStatus.SUPPORTED) == supported
    direct = PlannedStaticRoute(source_object_type="static_route", source_name="direct", status=PANMigrationStatus.SUPPORTED,
        destination="192.0.2.0/24", virtual_router="default", nexthop_type="ip-address", nexthop="198.51.100.1", admin_distance=distance)
    for item in (route, direct):
        rendered = PANSetRenderer().render(PANMigrationPlan(static_routes=(item,)))
        assert bool(rendered.commands) == supported
        if distance is None:
            assert not any("admin-dist" in command for command in rendered.commands)


@pytest.mark.parametrize("updates", [{"preferred_source": "192.0.2.1"}, {"raw_extra": {"link-monitor-exempt": "enable"}}])
def test_unrepresented_route_forwarding_settings_block_rendering(updates):
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    route = FGStaticRoute(seq_num=1, dst="192.0.2.0/24", gateway="198.51.100.1", **updates)
    options = PANMigrationOptions(vdoms={"root": {"virtual_router": "default"}})
    planned = plan_routes(FGConfig(static_routes=[route]), options)
    assert planned[0].warnings
    assert PANSetRenderer().render(PANMigrationPlan(static_routes=planned)).commands == ()


def test_builtin_all_and_named_all_preserve_ipv4_match_identity():
    from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"}, "wan": {"target_zone": "untrust"}}})
    policy = FGPolicy(policy_id=1, srcintf=["lan"], dstintf=["wan"], srcaddr=["all"], dstaddr=["all"],
                      service=["ALL"], action="accept", schedule="always")
    for addresses, expected in (([], "0.0.0.0/0"), ([FGAddress(name="all", subnet="192.0.2.0/24")], "all")):
        source = FGConfig(addresses=addresses, policies=[policy])
        plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), options)
        assert plan.security_rules[0].sources == (expected,)
        assert plan.security_rules[0].destinations == (expected,)
        assert source.policies[0].srcaddr == ["all"]


@pytest.mark.parametrize("family", ["addresses", "address_groups", "vips", "vip_groups"])
def test_address_references_preserve_explicit_all_in_each_scoped_family(family):
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.addresses import address_references
    source = SimpleNamespace(**{family: [SimpleNamespace(name="all", vdom="branch")]})
    assert address_references(source, "branch", ["host", "all", "all"]) == ("host", "all", "all")
    assert address_references(source, "root", ["host", "all"]) == ("host", "0.0.0.0/0")
    assert address_references(source, None, ["all"]) == ("0.0.0.0/0",)


def test_address_references_skip_inventory_without_all_and_stop_at_explicit_all():
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.addresses import address_references

    class UnreadableInventory:
        def __iter__(self):
            pytest.fail("Unneeded address inventory scan")

    source = SimpleNamespace(addresses=UnreadableInventory())
    assert address_references(source, "root", iter(["host", "host"])) == ("host", "host")
    assert address_references(source, "root", []) == ()
    source.addresses = [SimpleNamespace(name="all", vdom=None)]
    source.address_groups = UnreadableInventory()
    assert address_references(source, "root", ["all"]) == ("all",)


def test_literal_ipv4_selectors_are_only_exempt_for_addresses_and_keep_named_dependencies():
    from dataclasses import replace
    address = PlannedAddress(source_object_type="address", source_name="192.0.2.1", target_vsys="vsys1",
                             status=PANMigrationStatus.UNSUPPORTED)
    rule = _rule(sources=("192.0.2.1",), destinations=("0.0.0.0/0",), services=("any",))
    objects = _objects()
    objects["addresses"] = (address,)
    assert ("security_rule", "vsys1", "allow") not in validate_plan(PANMigrationPlan(**objects, security_rules=(rule,))).renderable_item_keys
    objects["addresses"] = ()
    assert ("security_rule", "vsys1", "allow") in validate_plan(PANMigrationPlan(**objects, security_rules=(rule,))).renderable_item_keys
    invalid_zone = replace(rule, to_zones=("0.0.0.0/0",))
    assert ("security_rule", "vsys1", "allow") not in validate_plan(PANMigrationPlan(**objects, security_rules=(invalid_zone,))).renderable_item_keys


@pytest.mark.parametrize("named_all", [False, True])
def test_snat_builtin_all_and_named_all_share_policy_address_mapping(named_all):
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.fortigate.model.interface import FGInterface
    from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
    source = FGConfig(interfaces=[FGInterface(name="wan", ip="203.0.113.1/24")],
        addresses=[FGAddress(name="all", subnet="192.0.2.0/24")] if named_all else [],
        policies=[FGPolicy(policy_id=1, nat="enable", action="accept", schedule="always", srcintf=["lan"],
                          dstintf=["wan"], srcaddr=["all"], dstaddr=["all"], service=["ALL"])])
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "lan": {"target_zone": "trust"}, "wan": {"target_zone": "untrust", "target_interface": "ethernet1/1"}}})
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), options)
    expected = ("all",) if named_all else ("0.0.0.0/0",)
    assert plan.nat_rules[0].source_addresses == plan.security_rules[0].sources == expected
    assert plan.nat_rules[0].destination_addresses == plan.security_rules[0].destinations == expected
    assert plan.nat_rules[0].status is PANMigrationStatus.SUPPORTED


def test_negated_ipv4_source_and_destination_do_not_expand_into_ipv6():
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import plan_policies
    source = FGConfig(policies=[FGPolicy(policy_id=1, action="accept", schedule="always", srcintf=["any"],
        dstintf=["any"], srcaddr=["all"], dstaddr=["all"], service=["ALL"], srcaddr_negate="enable", dstaddr_negate="enable")])
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}})
    rule = plan_policies(source, options)[0]
    assert rule.status is not PANMigrationStatus.SUPPORTED
    assert any("IPv6 matching" in warning for warning in rule.warnings)
