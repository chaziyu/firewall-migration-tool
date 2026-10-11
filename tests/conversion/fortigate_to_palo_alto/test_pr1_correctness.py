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
    assert any('set rulebase security' in command for command in artifact.commands) == supported
    assert config.policies[0].srcaddr6 == src6
    rule = artifact.report['items'][-1]
    assert rule['source_policy_id'] == 42
    if src6 is not None or dst6 is not None:
        assert rules[0].status is PANMigrationStatus.UNSUPPORTED
        assert rules[0].sources == tuple('any' if name == 'all' else name for name in (src4 or ()))
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
                          translated_addresses=["203.0.113.8"], translation_type="ip_pool", issues=())
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
                          translated_addresses=["203.0.113.8"], translation_type="ip_pool", issues=())
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
