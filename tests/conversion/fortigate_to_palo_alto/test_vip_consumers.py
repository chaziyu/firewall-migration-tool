from types import SimpleNamespace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, apply_explicit_options, run_migration_pipeline
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import build_decision_set
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus, PlannedZone
from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import plan_nat
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vip import FGVIP, FGVIPGroup


def _source(destination="web-group"):
    return FGConfig(
        vips=[FGVIP(name="web", type="static-nat", extip="198.51.100.10",
                    mappedip=["10.0.0.10"], extintf="wan")],
        vip_groups=[FGVIPGroup(name="web-group", members=["web"])],
        policies=[FGPolicy(policy_id=1, srcintf=["outside"], dstintf=["inside"],
                           srcaddr=["all"], dstaddr=[destination], service=["ALL"],
                           action="accept", schedule="always")],
    )


def _options():
    return PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "outside": {"target_zone": "outside"}, "inside": {"target_zone": "inside"},
        "wan": {"target_zone": "untrust"},
    }})


@pytest.mark.parametrize('external_interface', ['any', None, 'wan'])
def test_reviewed_vip_external_zone_is_scoped_and_never_uses_post_nat_zone(external_interface):
    from dataclasses import replace
    source = _source('web')
    source.vips[0].extintf = external_interface
    options = _options()
    if external_interface != 'wan':
        missing = plan_nat(source, build_derived_views(source), options)[0]
        assert missing.status is PANMigrationStatus.MANUAL_REVIEW
        assert not missing.to_zones
    settings = {'vip_external_zones': {'root': {'web': 'untrust'}}}
    rule = plan_nat(source, build_derived_views(source), replace(options, conversion_settings=settings))[0]
    assert rule.status is PANMigrationStatus.SUPPORTED
    assert rule.to_zones == ('untrust',)
    assert rule.to_zones != ('inside',)
    with pytest.raises(ValueError, match='current source VIP'):
        plan_nat(source, build_derived_views(source), replace(options, conversion_settings={
            'vip_external_zones': {'blue': {'web': 'untrust'}}}))


@pytest.mark.parametrize('zone', ['any', '', 'bad/zone', 'x' * 32, 'bad\rzone'])
def test_vip_zone_settings_reject_invalid_choices(zone):
    with pytest.raises(ValueError, match='destination zone'):
        PANMigrationOptions(conversion_settings={'vip_external_zones': {'root': {'web': zone}}})


def test_repeated_vip_names_use_independent_vdom_choices():
    from dataclasses import replace
    source = _source('web')
    source.vips[0].extintf = 'any'
    source.vips.append(source.vips[0].model_copy(update={'vdom': 'blue', 'extip': '203.0.113.11'}))
    source.policies.append(source.policies[0].model_copy(update={'vdom': 'blue'}))
    original = _options()
    options = replace(original, vdoms={'root': {'vsys': 'vsys1'}, 'blue': {'vsys': 'vsys2'}},
        interfaces={**original.interfaces, 'blue': original.interfaces['root']},
        conversion_settings={'vip_external_zones': {'root': {'web': 'root-outside'}, 'blue': {'web': 'blue-outside'}}})
    rules = plan_nat(source, build_derived_views(source), options)
    assert {rule.source_vdom: rule.to_zones for rule in rules} == {'root': ('root-outside',), 'blue': ('blue-outside',)}
    assert all(rule.status is PANMigrationStatus.SUPPORTED for rule in rules)


def test_vip_zone_availability_uses_selected_vsys_and_device():
    from dataclasses import replace
    from fwmigrate.conversion.fortigate_to_palo_alto.target.profile import bind_vip_external_zones
    from fwmigrate.vendors.palo_alto.source_model import PANScope
    from fwmigrate.vendors.palo_alto.model.zone import PANZone
    source = _source('web')
    source.vips[0].extintf = 'any'
    settings = {'vip_external_zones': {'root': {'web': 'untrust'}}}
    options = replace(_options(), conversion_settings=settings)
    plan = PANMigrationPlan(nat_rules=plan_nat(source, build_derived_views(source), options))
    zone = PANZone(name='untrust', network_type='layer3',
        scope=PANScope(kind='vsys', name='vsys1', vsys='vsys1', device_name='fw'))
    target = SimpleNamespace(config=SimpleNamespace(zones=[zone]))
    bound = bind_vip_external_zones(plan, settings, target, 'fw')
    assert bound.target_zone_references == (('vsys1', 'untrust'),)
    assert not any(' zone untrust ' in command for command in PANSetRenderer().render(bound).commands)
    for device, vsys in [('other', 'vsys1'), ('fw', 'vsys2')]:
        zone.scope.vsys = vsys
        with pytest.raises(ValueError, match='unavailable'):
            bind_vip_external_zones(plan, settings, target, device)


@pytest.mark.parametrize("destination", ["web", "web-group"])
def test_vip_consumers_reach_requirements_and_dnat_renderer(destination):
    source = _source(destination)
    before = source.model_dump()
    derived = build_derived_views(source)
    requirements = build_mapping_requirements(source, derived)
    assert any(item["source_name"] == "wan" and "vip" in item["reasons"]
               for item in requirements["interfaces"])
    decisions = build_decision_set(source, derived, requirements)
    options = apply_explicit_options(source, decisions, _options()).to_options()
    rules = plan_nat(source, derived, options)
    assert rules[0].status is PANMigrationStatus.SUPPORTED
    zones = tuple(PlannedZone(source_object_type="zone", source_name=name, target_name=name,
                             target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED)
                  for name in ("outside", "untrust"))
    rendered = PANSetRenderer().render(PANMigrationPlan(nat_rules=rules, zones=zones))
    assert any("destination-translation translated-address 10.0.0.10" in command
               for command in rendered.commands)
    assert source.model_dump() == before


def test_flat_vip_group_expands_security_and_coverage_requires_every_rendered_dependency():
    from dataclasses import replace
    from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage, represented_vip_groups
    from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
    source = _source()
    plan = FortiGateToPaloAltoPlanner().plan(source, build_derived_views(source), _options())
    assert plan.security_rules[0].destinations == ('web',)
    zones = tuple(PlannedZone(source_vdom='root', source_object_type='zone', source_name=name, target_name=name,
        target_vsys='vsys1', status=PANMigrationStatus.SUPPORTED) for name in ('outside', 'inside', 'untrust'))
    rendered = PANSetRenderer().render(replace(plan, zones=zones))
    assert any('rulebase security' in command and 'destination [ web ]' in command for command in rendered.commands)
    satisfied = {row['item_key'] for row in rendered.report['items'] if row['satisfied']}
    represented = represented_vip_groups(source, plan, satisfied)
    assert represented == {('root', 'web-group')}
    assert not build_migration_coverage(source, planned_vip_groups=represented)['unplanned']
    nat_key = next(row['item_key'] for row in rendered.report['items'] if row['source_object_type'] == 'nat_rule')
    assert not represented_vip_groups(source, plan, satisfied - {nat_key})
    source.vip_groups[0].raw_extra['future-setting'] = 'enable'
    assert not represented_vip_groups(source, plan, satisfied)


def test_vip_group_security_coverage_stays_visible_as_manual_work():
    source = _source()
    result = run_migration_pipeline(source, build_derived_views(source), options=_options())
    assert result.plan.nat_rules[0].status is PANMigrationStatus.SUPPORTED
    assert result.artifact_status == "PARTIAL"
    assert any(row["source_kind"] == "vip_group" for row in result.coverage["unplanned"])
    assert not any("rulebase security" in command for command in result.rendered.commands)


@pytest.mark.parametrize("members,extra_groups,warning", [
    (["web", "missing"], [], "unresolved"),
    (["web", "web-group"], [], "circular"),
    (["child"], [FGVIPGroup(name="child", members=["web"])], "nested"),
])
def test_invalid_vip_group_blocks_known_member_translation(members, extra_groups, warning):
    source = _source()
    source.vip_groups[0].members = members
    source.vip_groups.extend(extra_groups)
    rule = plan_nat(source, build_derived_views(source), _options())[0]
    assert rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert any(warning in text for text in rule.warnings)
    assert not rule.destination_translated_address


def test_vip_group_never_resolves_member_from_another_vdom():
    source = _source()
    source.vips[0].vdom = "blue"
    rule = plan_nat(source, build_derived_views(source), _options())[0]
    assert rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert "no referencing" in " ".join(rule.warnings)


def test_vip_multiple_policy_consumers_expand_distinct_ingress_matches():
    source = _source()
    source.policies.append(source.policies[0].model_copy(update={"policy_id": 2}))
    assert plan_nat(source, build_derived_views(source), _options())[0].status is PANMigrationStatus.SUPPORTED
    source.policies[1].srcintf = ["inside"]
    rules = plan_nat(source, build_derived_views(source), _options())
    assert len(rules) == 2
    assert all(rule.status is PANMigrationStatus.SUPPORTED for rule in rules)
    assert len({rule.from_zones for rule in rules}) == 2
    assert [rule.target_name for rule in rules] == ['web-match-1', 'web-match-2']


def test_group_interface_and_unknown_semantics_require_manual_review():
    source = _source()
    source.vip_groups[0].interface = "other"
    source.vip_groups[0].raw_extra = {"future-match": "enable"}
    rule = plan_nat(source, build_derived_views(source), _options())[0]
    assert rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert any("interface" in warning for warning in rule.warnings)
    assert any("future-match" in warning for warning in rule.warnings)


def test_vip_discovery_supports_existing_minimal_derived_callers():
    source = _source("web")
    assert plan_nat(source, SimpleNamespace(), _options())[0].status is PANMigrationStatus.SUPPORTED


def test_vip_address_namespace_collision_requires_manual_review():
    from fwmigrate.vendors.fortigate.model.address import FGAddress

    source = _source("web")
    source.addresses = [FGAddress(name="web", subnet="192.0.2.1/32")]
    rule = plan_nat(source, build_derived_views(source), _options())[0]
    assert rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert any("ambiguous" in text for text in rule.warnings)


def test_independent_group_interfaces_are_checked_only_for_their_members():
    source = _source()
    source.vip_groups[0].interface = "wan"
    source.vip_groups.append(FGVIPGroup(name="other-group", interface="wan2", members=["other"]))
    source.vips.append(source.vips[0].model_copy(update={"name": "other", "extintf": "wan2", "extip": "198.51.100.11"}))
    source.policies[0].dstaddr.append("other-group")
    options = _options()
    options.interfaces["root"]["wan2"] = options.interfaces["root"]["wan"]
    assert all(rule.status is PANMigrationStatus.SUPPORTED
               for rule in plan_nat(source, build_derived_views(source), options))


@pytest.mark.parametrize("updates,warning", [
    ({"status": "unknown"}, "state"),
    ({"ippool": "disable"}, "IP-pool"),
])
def test_source_nat_uncertain_policy_controls_block_conversion(updates, warning):
    from fwmigrate.vendors.fortigate.model.interface import FGInterface
    from fwmigrate.vendors.fortigate.model.ippool import FGIPPool

    source = _source("web")
    source.vips = []
    source.vip_groups = []
    source.interfaces = [FGInterface(name="inside", ip="10.0.0.1/24")]
    source.ip_pools = [FGIPPool(name="pool", type="overload", startip="203.0.113.1",
                              endip="203.0.113.1", explicit_fields={"type", "startip", "endip"})]
    source.policies[0] = source.policies[0].model_copy(update={
        "nat": "enable", "ippool": "enable", "poolname": ["pool"], "dstaddr": ["all"],
    })
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "outside": {"target_zone": "outside"},
        "inside": {"target_zone": "inside", "target_interface": "ethernet1/1"},
    }})
    assert plan_nat(source, build_derived_views(source), options)[0].status is PANMigrationStatus.SUPPORTED
    source.policies[0] = source.policies[0].model_copy(update=updates)
    rule = plan_nat(source, build_derived_views(source), options)[0]
    assert rule.status is PANMigrationStatus.MANUAL_REVIEW
    assert any(warning in text for text in rule.warnings)


@pytest.mark.parametrize("value", ["invalid", "203.0.113.10-203.0.113.1", "2001:db8::1"])
def test_invalid_snat_translated_address_is_not_rendered(value):
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedNATRule

    rule = PlannedNATRule(source_object_type="nat_rule", source_kind="source_nat", source_name="snat",
                          target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED,
                          from_zones=("any",), to_zones=("any",), source_addresses=("any",),
                          destination_addresses=("any",), service="any", to_interface="ethernet1/1",
                          source_translation_type="dynamic-ip-and-port", translated_addresses=(value,))
    assert PANSetRenderer().render(PANMigrationPlan(nat_rules=(rule,))).commands == ()
