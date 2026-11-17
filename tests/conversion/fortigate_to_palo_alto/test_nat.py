import pytest
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import assess_target_plan
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from dataclasses import replace
from fwmigrate.conversion.fortigate_to_palo_alto.models import PlannedNATRule
from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import _packet_disjoint_test
from copy import deepcopy
from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import inspection_design_groups, snat_precedence_warnings
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.cli_paths import security_rule
from types import SimpleNamespace
from fwmigrate.conversion.fortigate_to_palo_alto import apply_explicit_options, run_migration_pipeline
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import build_decision_set
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PlannedZone
from fwmigrate.conversion.fortigate_to_palo_alto.planning.nat import plan_nat
from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.model.vip import FGVIP, FGVIPGroup
import hashlib
import io
import json
import zipfile
from fwmigrate.collection.snapshot import sanitize_source
from fwmigrate.main import cli
from fwmigrate.vendors.palo_alto.source_report import PaloAltoSourceReporter
from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage
from fwmigrate.vendors.fortigate.model.ippool import FGIPPool

# --- test_combined_nat.py ---
_COMBINED_NAT_SOURCE = '''config system interface
edit outside
set type physical
set ip 192.0.2.1 255.255.255.0
next
edit inside
set type physical
set ip 10.0.0.1 255.255.255.0
next
end
config firewall address
edit clients
set subnet 198.51.100.0 255.255.255.0
next
end
config firewall ippool
edit pool
set type overload
set startip 10.0.0.100
set endip 10.0.0.100
next
end
config firewall vip
edit published
set type static-nat
set extintf outside
set extip 192.0.2.10
set mappedip 10.0.0.10
next
end
config firewall policy
edit 1
set name clients-in
set srcintf outside
set dstintf inside
set srcaddr clients
set dstaddr published
set service ALL
set action accept
set schedule always
set nat enable
set ippool enable
set poolname pool
next
end
'''


def plan_source(source):
    analysis = FortiGateSourceReporter().analyze_source(source)
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}}, interfaces={'root': {
        'outside': {'target_interface': 'ethernet1/1', 'target_zone': 'outside'},
        'inside': {'target_interface': 'ethernet1/2', 'target_zone': 'inside'}}})
    return FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options, include_configuration=True)


def test_isolated_pool_snat_and_static_vip_become_one_original_packet_rule():
    plan = plan_source(_COMBINED_NAT_SOURCE)
    rule, = plan.nat_rules
    assert rule.status is PANMigrationStatus.SUPPORTED
    # Client -> public VIP becomes translated source -> mapped server in one rule.
    assert rule.source_addresses == ('clients',)
    assert rule.destination_addresses == ('192.0.2.10',)
    assert rule.translated_addresses == ('10.0.0.100',)
    assert rule.destination_translated_address == '10.0.0.10'
    assert rule.from_zones == rule.to_zones == ('outside',)
    assert rule.to_interface is None and rule.translation_interface == 'ethernet1/2'
    commands = PANSetRenderer().render(plan).commands
    base = 'set vsys vsys1 rulebase nat rules published-snat-1'
    assert base + ' source-translation dynamic-ip-and-port translated-address [ 10.0.0.100 ]' in commands
    assert base + ' destination-translation translated-address 10.0.0.10' in commands
    assert not any(command.startswith(base + ' to-interface') for command in commands)


@pytest.mark.parametrize('source', [
    _COMBINED_NAT_SOURCE.replace('198.51.100.0 255.255.255.0', '10.0.0.0 255.255.255.0'),
    _COMBINED_NAT_SOURCE.replace('set srcaddr clients', 'set srcaddr all'),
    _COMBINED_NAT_SOURCE.replace('set type overload', 'set type one-to-one'),
    _COMBINED_NAT_SOURCE + 'config firewall policy\nedit 2\nset action deny\nnext\nend\n',
    _COMBINED_NAT_SOURCE.replace('set service ALL', 'set service HTTPS'),
])
def test_uncertain_combined_matches_keep_both_rules_blocked(source):
    plan = plan_source(source)
    assert all(rule.status is not PANMigrationStatus.SUPPORTED for rule in plan.nat_rules)
    assert not any(' rulebase nat ' in command for command in PANSetRenderer().render(plan).commands)


def test_combined_translation_requires_approved_egress_and_blocks_consuming_policy():
    plan = plan_source(_COMBINED_NAT_SOURCE)
    egress = next(item for item in plan.interfaces if item.source_name == 'inside')
    decisions = PANMigrationDecisionSet()
    index = build_plan_dependency_index(plan, decisions)
    classification = {'family': 'interface', 'status': 'AMBIGUOUS', 'source_vdom': egress.source_vdom,
        'source_kind': egress.source_kind, 'source_name': egress.source_name,
        'target_vsys': egress.target_vsys, 'target_name': egress.target_name}
    dispositions, blockers = assess_target_plan(plan, [classification], (), decisions, index)
    assert dispositions[item_key(plan.nat_rules[0])].value == 'BLOCK'
    assert dispositions[item_key(plan.security_rules[0])].value == 'BLOCK'
    commands = PANSetRenderer().render(plan, dispositions=dispositions, render_blockers=blockers).commands
    assert not any(' rulebase nat ' in command or ' rulebase security ' in command for command in commands)


def test_multiple_isolated_policy_partitions_each_get_one_combined_nat_rule():
    second = '''config firewall vip
edit second
set type static-nat
set extintf outside
set extip 192.0.2.20
set mappedip 10.0.0.20
next
end
config firewall policy
edit 2
set name second-in
set srcintf outside
set dstintf inside
set srcaddr clients
set dstaddr second
set service ALL
set action accept
set schedule always
set nat enable
set ippool enable
set poolname pool
next
end
'''
    plan = plan_source(_COMBINED_NAT_SOURCE + second)
    assert len(plan.nat_rules) == 2
    assert all(rule.status is PANMigrationStatus.SUPPORTED for rule in plan.nat_rules)
    assert [rule.source_policy_id for rule in plan.nat_rules] == [1, 2]
    assert all(rule.translated_addresses == ('10.0.0.100',) for rule in plan.nat_rules)
    # Sharing the public address or mapped server no longer proves separate partitions.
    for changed in (second.replace('192.0.2.20', '192.0.2.10'), second.replace('10.0.0.20', '10.0.0.10')):
        blocked = plan_source(_COMBINED_NAT_SOURCE + changed)
        assert not any(rule.source_translation_type and rule.destination_translated_address
                       and rule.status is PANMigrationStatus.SUPPORTED for rule in blocked.nat_rules)

# --- test_nat_flow_independence.py ---
def test_independence_requires_a_proof_including_the_translated_destination():
    analysis = FortiGateSourceReporter().analyze_source('''config system interface
edit inside
set type physical
next
edit outside
set type physical
next
end
config firewall vip
edit published
set type static-nat
set extintf outside
set extip 192.0.2.1
set mappedip 198.51.100.1
next
end
config firewall policy
edit 1
set srcintf inside
next
end
config firewall address
edit clients
set subnet 10.0.0.0 255.255.255.0
next
edit others
set subnet 10.0.1.0 255.255.255.0
next
edit translated
set subnet 198.51.100.1 255.255.255.255
next
end
config firewall addrgrp
edit nested
set member clients
next
end
''')
    independent = _packet_disjoint_test(analysis.extracted.config)
    snat = PlannedNATRule(source_vdom='root', source_kind='source_nat', source_policy_id=1,
        from_zones=('inside',), source_addresses=('nested',), destination_addresses=('any',))
    dnat = PlannedNATRule(source_vdom='root', source_kind='vip', source_name='published', from_zones=('outside',), source_addresses=('any',),
        destination_addresses=('192.0.2.1',), destination_translated_address='198.51.100.1')
    assert not independent(snat, dnat), 'VIP extintf does not bind DNAT to that ingress'
    analysis.extracted.config.policies[0].srcintf = ['outside']
    independent = _packet_disjoint_test(analysis.extracted.config)
    assert not independent(snat, dnat)
    assert not independent(snat, replace(dnat, source_addresses=('others',)))
    assert not independent(snat, replace(dnat, source_addresses=('missing',)))
    assert not independent(replace(snat, destination_addresses=('translated',)), dnat)
    assert independent(replace(snat, destination_addresses=('203.0.113.0/24',)), dnat)
    assert not independent(replace(snat, source_addresses=('any',), destination_addresses=('203.0.113.0/24',)), dnat), 'Mapped servers can use VIP reverse-SNAT'
    assert not independent(replace(snat, source_addresses=('unknown.example',)), dnat)


def test_cycles_duplicates_and_unknown_scopes_cannot_prove_separation():
    analysis = FortiGateSourceReporter().analyze_source('''config firewall addrgrp
edit cycle
set member cycle
next
end
''')
    independent = _packet_disjoint_test(analysis.extracted.config)
    first = PlannedNATRule(source_vdom='root', from_zones=('any',), source_addresses=('cycle',))
    second = replace(first, source_addresses=('192.0.2.1',))
    assert not independent(first, second)
    assert not independent(replace(first, source_addresses=('missing',)), second)
    assert not independent(replace(first, from_zones=()), second)

# --- test_policy_nat_automation.py ---
SOURCE = '''config system interface
 edit inside
  set type physical
  set ip 10.0.0.1 255.255.255.0
 next
 edit outside
  set type physical
  set ip 203.0.113.1 255.255.255.0
 next
end
config firewall service custom
 edit web
  set tcp-portrange 8443
 next
 edit dns
  set udp-portrange 5353
 next
end
config firewall service group
 edit clients
  set member web dns
 next
end
config firewall policy
 edit 1
  set name outbound
  set srcintf inside
  set dstintf outside
  set srcaddr all
  set dstaddr all
  set action accept
  set schedule always
  set service clients
  set nat enable
  set utm-status enable
  set ips-sensor strict
 next
end
'''


def inputs():
    analysis = FortiGateSourceReporter().analyze_source(SOURCE)
    options = PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}}, interfaces={'root': {
        'inside': {'target_zone': 'trust', 'target_interface': 'ethernet1/2'}, 'outside': {'target_zone': 'untrust', 'target_interface': 'ethernet1/1'}}})
    return analysis, options


@pytest.mark.parametrize('updates,first,blocked', [
    ({}, True, True),
    ({'nat': None}, True, True),
    ({'status': 'disable'}, True, False),
    ({'action': 'deny'}, True, False),
    ({'vdom': 'branch'}, True, False),
    ({'srcintf': ['other']}, True, False),
    ({'srcintf': ['same-zone']}, True, True),
    ({'srcintf': ['any']}, True, True),
    ({'srcintf': ['other', 'missing']}, True, True),
    ({}, False, False),
])
def test_no_nat_precedence_preserves_source_order_scope_and_unknown_matches(updates, first, blocked):
    from fwmigrate.vendors.fortigate.model.policy import FGPolicy
    from fwmigrate.vendors.fortigate.model.source import FGConfig

    prior = FGPolicy(policy_id=20, name='exception', srcintf=['inside'], dstintf=['outside'],
        action='accept', nat='disable').model_copy(update=updates)
    later = FGPolicy(policy_id=1, name='snat', srcintf=['inside'], dstintf=['outside'], action='accept', nat='enable')
    source = FGConfig(policies=[prior, later] if first else [later, prior])
    _, options = inputs()
    options = replace(options, interfaces={'root': {**options.interfaces['root'],
        'other': {'target_zone': 'other-zone'}, 'same-zone': {'target_zone': 'trust'}}})
    original = source.model_dump()
    findings = snat_precedence_warnings(source, options)
    assert bool(findings.get(('root', 1))) == blocked
    assert source.model_dump() == original


def test_shared_profile_mapping_requires_review_and_does_not_bypass_decryption():
    analysis, options = inputs()
    source = analysis.extracted.config
    original = deepcopy(source)
    group, = inspection_design_groups(source)
    assert group['member_keys'] == ['1']
    assert FortiGateToPaloAltoPlanner().plan(source, analysis.derived, options).security_rules[0].status is not PANMigrationStatus.SUPPORTED
    reviewed = replace(options, conversion_settings={'security_profiles': {group['identity']: 'target-protection'}})
    rule = FortiGateToPaloAltoPlanner().plan(source, analysis.derived, reviewed).security_rules[0]
    assert rule.status is PANMigrationStatus.SUPPORTED
    assert any(path[-4:] == ('group', '[', 'target-protection', ']') for path in security_rule(rule))
    assert source == original
    source.policies[0].ssl_ssh_profile = 'deep-inspection'
    new_group, = inspection_design_groups(source)
    reviewed = replace(options, conversion_settings={'security_profiles': {new_group['identity']: 'target-protection'}})
    assert FortiGateToPaloAltoPlanner().plan(source, analysis.derived, reviewed).security_rules[0].status is not PANMigrationStatus.SUPPORTED


def test_no_inspection_does_not_request_an_unrelated_security_profile_group():
    _, options = inputs()
    config = SOURCE.replace('set utm-status enable', 'set utm-status disable').replace('set ips-sensor strict', 'set ssl-ssh-profile no-inspection')
    analysis = FortiGateSourceReporter().analyze_source(config)
    assert inspection_design_groups(analysis.extracted.config) == []
    rule = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options).security_rules[0]
    assert rule.status is PANMigrationStatus.SUPPORTED
    analysis = FortiGateSourceReporter().analyze_source(config.replace('no-inspection', 'certificate-inspection'))
    rule = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options).security_rules[0]
    assert inspection_design_groups(analysis.extracted.config) == []
    assert any('decryption design' in warning for warning in rule.warnings)
    assert rule.status is not PANMigrationStatus.SUPPORTED


def test_snat_service_union_splits_adjacent_rules_without_losing_other_blockers():
    analysis, options = inputs()
    source = analysis.extracted.config
    plan = FortiGateToPaloAltoPlanner().plan(source, analysis.derived, options)
    assert [rule.service for rule in plan.nat_rules] == ['web', 'dns']
    assert [rule.target_name for rule in plan.nat_rules] == ['outbound-svc-1', 'outbound-svc-2']
    assert all(rule.status is PANMigrationStatus.SUPPORTED for rule in plan.nat_rules)
    source.policies[0].users = ['restricted-user']
    blocked = FortiGateToPaloAltoPlanner().plan(source, analysis.derived, options)
    assert all(rule.status is not PANMigrationStatus.SUPPORTED for rule in blocked.nat_rules)
    assert all(any('user/group' in warning for warning in rule.warnings) for rule in blocked.nat_rules)


def test_disjoint_destinations_snat_and_dnat_render_but_overlapping_flows_stay_blocked():
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    extra = '''config firewall address
edit route-scope
set subnet 203.0.113.0 255.255.255.0
next
edit clients-only
set subnet 10.0.1.0 255.255.255.0
next
end
config firewall vip
edit published
set type static-nat
set extintf outside
set extip 192.0.2.10
set mappedip 10.0.0.10
next
end
config firewall policy
edit 2
set srcintf outside
set dstintf inside
set srcaddr all
set dstaddr published
set action accept
set schedule always
set service web
next
end
'''
    _, options = inputs()
    analysis = FortiGateSourceReporter().analyze_source(SOURCE.replace('set dstaddr all', 'set dstaddr route-scope').replace('set srcaddr all', 'set srcaddr clients-only') + extra)
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options, include_configuration=True)
    assert len(plan.nat_rules) == 3
    assert all(rule.status is PANMigrationStatus.SUPPORTED for rule in plan.nat_rules)
    commands = PANSetRenderer().render(plan).commands
    assert any('source-translation' in command for command in commands)
    assert any('destination-translation' in command for command in commands)
    analysis = FortiGateSourceReporter().analyze_source(SOURCE + extra)
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options, include_configuration=True)
    assert all(rule.status is not PANMigrationStatus.SUPPORTED for rule in plan.nat_rules)
    assert not any(' rulebase nat ' in command for command in PANSetRenderer().render(plan).commands)


def test_simple_vip_port_translation_generates_an_original_port_service():
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    extra = '''config firewall vip
edit published
set type static-nat
set extintf outside
set extip 192.0.2.10
set mappedip 10.0.0.10
set portforward enable
set protocol tcp
set extport 8080
set mappedport 80
next
end
config firewall policy
edit 2
set srcintf outside
set dstintf inside
set srcaddr all
set dstaddr published
set action accept
set schedule always
set service ALL
next
end
'''
    _, options = inputs()
    source = SOURCE.replace('set nat enable', 'set nat disable') + extra
    analysis = FortiGateSourceReporter().analyze_source(source)
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options, include_configuration=True)
    nat, = plan.nat_rules
    assert nat.status is PANMigrationStatus.SUPPORTED
    assert nat.destination_translated_port == '80'
    assert nat.service == 'FG-VIP-published-tcp-8080'
    commands = PANSetRenderer().render(plan).commands
    assert 'set vsys vsys1 service FG-VIP-published-tcp-8080 protocol tcp port 8080' in commands
    assert 'set vsys vsys1 rulebase nat rules published destination-translation translated-port 80' in commands
    collision = source + '''config firewall service custom
edit FG-VIP-published-tcp-8080
set udp-portrange 53
next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(collision)
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options, include_configuration=True)
    assert next(item for item in plan.services if item.source_kind == 'vip_service').status is PANMigrationStatus.MANUAL_REVIEW
    assert not any(' rulebase nat ' in command for command in PANSetRenderer().render(plan).commands)
    analysis = FortiGateSourceReporter().analyze_source(source.replace('set service ALL', 'set service web'))
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options, include_configuration=True)
    assert plan.nat_rules[0].status is not PANMigrationStatus.SUPPORTED
    assert not any(' rulebase nat ' in command for command in PANSetRenderer().render(plan).commands)


@pytest.mark.parametrize(('protocol', 'port', 'supported'), [
    ('tcp', '8081', True), ('udp', '8080', True), ('tcp', '8080', False),
    ('tcp', '8080-8081', False), ('tcp', '0', False),
])
def test_shared_vip_external_address_requires_distinct_original_protocol_ports(protocol, port, supported):
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
    source = SOURCE.replace('set nat enable', 'set nat disable')
    for number, (transport, original_port) in enumerate((('tcp', '8080'), (protocol, port)), 2):
        source += f'''config firewall vip
edit published{number}
set type static-nat
set extintf outside
set extip 192.0.2.10
set mappedip 10.0.0.{number}
set portforward enable
set protocol {transport}
set extport {original_port}
set mappedport 80
next
end
config firewall policy
edit {number}
set srcintf outside
set dstintf inside
set srcaddr all
set dstaddr published{number}
set action accept
set schedule always
set service ALL
next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(source)
    _, options = inputs()
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options, include_configuration=True)
    assert len(plan.nat_rules) == 2
    assert all((rule.status is PANMigrationStatus.SUPPORTED) == supported for rule in plan.nat_rules)
    commands = PANSetRenderer().render(plan).commands
    assert any(' rulebase nat ' in command for command in commands) == supported


def test_split_nat_conflict_is_bound_to_the_exact_generated_rule():
    from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet
    from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
    from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import assess_target_plan, validate_target_plan
    analysis, options = inputs()
    plan = FortiGateToPaloAltoPlanner().plan(analysis.extracted.config, analysis.derived, options)
    first, second = plan.nat_rules
    decisions = PANMigrationDecisionSet()
    dependencies = build_plan_dependency_index(plan, decisions)
    classification = {'family': 'nat_rule', 'status': 'NAME_CONFLICT', 'source_vdom': 'root', 'source_kind': first.source_kind,
        'source_name': first.source_name, 'target_vsys': first.target_vsys, 'target_name': first.target_name}
    dispositions, _ = assess_target_plan(plan, [classification], (), decisions, dependencies)
    assert dispositions[item_key(first)].value == 'BLOCK'
    assert dispositions[item_key(second)].value == 'CREATE'
    findings = validate_target_plan(plan, [classification], (), decisions, dependencies)
    assert item_key(first) in findings[0].affected_item_keys
    assert item_key(second) not in findings[0].affected_item_keys

# --- test_vip_consumers.py ---
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

# --- test_vip_descriptions.py ---
def source_text(comment="VIP owner", extra=""):
    setting = "" if comment is None else f'set comment "{comment}"'
    return f"""config firewall vip
edit published
set type static-nat
set extip 198.51.100.10
set mappedip 10.0.0.10
set extintf any
{setting}
{extra}
next
end
"""


def migrate(text, options=None, **kwargs):
    analysis = FortiGateSourceReporter().analyze_source(sanitize_source("fortigate", text))
    before = deepcopy(analysis.extracted)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
        options=options or PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}),
        source_inventory=analysis.extracted.source_objects, **kwargs)
    assert analysis.extracted == before
    return result


@pytest.mark.parametrize("comment", [None, "", "VIP owner"])
def test_vip_comments_reach_address_description_without_filling_absent_values(comment):
    result = migrate(source_text(comment))
    item, = result.plan.addresses
    assert item.description == comment
    descriptions = [command for command in result.rendered.commands if " description " in command]
    assert descriptions == ([] if comment is None else [f'set vsys vsys1 address published description "{comment}"'])


def test_unset_vip_comment_stays_absent():
    result = migrate(source_text(extra="unset comment"))
    assert result.plan.addresses[0].description is None
    assert not any(" description " in command for command in result.rendered.commands)


def test_same_named_vips_keep_their_own_vdom_metadata():
    text = "config vdom\n" + "".join(
        f"edit {vdom}\n{source_text(comment)}next\n" for vdom, comment in (("root", "Root owner"), ("blue", "Blue owner"))
    ) + "end\n"
    result = migrate(text, PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}, "blue": {"vsys": "vsys2"}}))
    assert {row.source_vdom: row.description for row in result.plan.addresses} == {"root": "Root owner", "blue": "Blue owner"}
    assert 'set vsys vsys1 address published description "Root owner"' in result.rendered.commands
    assert 'set vsys vsys2 address published description "Blue owner"' in result.rendered.commands


@pytest.mark.parametrize("source_comment,target_comment,expected", [
    ("VIP owner", "VIP owner", "EXACT_MATCH"),
    ("VIP owner", "Destination owner", "NAME_CONFLICT"),
    ("VIP owner", None, "AMBIGUOUS"),
    ("", "", "EXACT_MATCH"),
    ("", None, "AMBIGUOUS"),
    (None, "Destination owner", "EXACT_MATCH"),
])
def test_vip_address_reuse_requires_matching_explicit_description(source_comment, target_comment, expected):
    description = "" if target_comment is None else f"<description>{target_comment}</description>"
    target = PaloAltoSourceReporter().analyze_source(f"""<config><devices><entry name="fw"><vsys><entry name="vsys1">
<address><entry name="published"><ip-netmask>198.51.100.10/32</ip-netmask>{description}</entry></address>
</entry></vsys></entry></devices></config>""")
    before = deepcopy(target.config)
    result = migrate(source_text(source_comment), target=target, target_device="fw")
    row, = [row for row in result.target_object_reuse if row["family"] == "address"]
    assert row["status"] == expected
    assert target.config == before
    assert not result.rendered.commands


@pytest.mark.parametrize("comment", ["VIP owner", "unsafe\x01value", "unsafe\tvalue", "x" * 1024],
                         ids=["valid", "control", "tab", "over-limit"])
def test_invalid_vip_metadata_is_retained_and_blocks_consuming_security_rule(comment):
    from dataclasses import replace
    from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedZone
    from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer

    policy = """config firewall policy
edit 1
set srcintf outside
set dstintf inside
set srcaddr all
set dstaddr published
set service ALL
set action accept
set schedule always
next
end
"""
    options = PANMigrationOptions(vdoms={"root": {"vsys": "vsys1"}}, interfaces={"root": {
        "outside": {"target_zone": "outside"}, "inside": {"target_zone": "inside"}}})
    result = migrate(source_text(comment, extra="set extintf outside") + policy, options)
    item, = result.plan.addresses
    assert item.description == comment
    invalid = comment != "VIP owner"
    assert any("target description" in warning for warning in item.warnings) == invalid
    assert any(issue.code == "invalid_target_description" for issue in result.validation.issues) == invalid
    zones = tuple(PlannedZone(source_vdom="root", source_object_type="zone", source_name=name,
        target_name=name, target_vsys="vsys1", status=PANMigrationStatus.SUPPORTED) for name in ("outside", "inside"))
    rendered = PANSetRenderer().render(replace(result.plan, zones=zones))
    assert any("address published " in command for command in rendered.commands) != invalid
    assert any("rulebase security" in command for command in rendered.commands) != invalid


def test_vip_metadata_uses_sanitized_source_evidence():
    text = source_text(extra='set password "SYNTHETIC-CREDENTIAL"')
    sanitized = sanitize_source("fortigate", text)
    assert "SYNTHETIC-CREDENTIAL" not in sanitized
    assert "[REDACTED]" in sanitized
    result = migrate(sanitized)
    assert "SYNTHETIC-CREDENTIAL" not in repr(result.plan) + repr(result.rendered.report)
    assert result.plan.addresses[0].description == "VIP owner"


def test_unreferenced_vip_addresses_require_only_their_explicit_vsys_placement():
    from fwmigrate.conversion.fortigate_to_palo_alto.requirements import build_mapping_requirements

    text = "config vdom\n" + "".join(
        f"edit {vdom}\n{source_text()}next\n" for vdom in ("root", "blue")
    ) + "end\n"
    analysis = FortiGateSourceReporter().analyze_source(text)
    requirements = build_mapping_requirements(analysis.extracted.config, analysis.derived)
    assert requirements["vdoms"] == [
        {"source_vdom": "blue", "requires": ["vsys"]},
        {"source_vdom": "root", "requires": ["vsys"]},
    ]
    assert not requirements["interfaces"]


def test_cli_preserves_vip_description_and_report_digest(tmp_path):
    from click.testing import CliRunner

    source = tmp_path / "source.conf"
    source.write_text(source_text())
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text("vdoms:\n  root:\n    vsys: vsys1\n")
    output = tmp_path / "output"
    response = CliRunner().invoke(cli, ["migrate", "-i", str(source), "-o", str(output),
        "--zone-map", str(mapping), "--automation-mode", "REVIEW_ONLY"])
    assert response.exit_code == 0, response.output
    commands = (output / "palo_alto_config.set").read_bytes()
    assert b'address published description "VIP owner"' in commands
    report = json.loads((output / "migration_report.json").read_text())
    assert report["command_sha256"] == hashlib.sha256(commands).hexdigest()


def test_signed_web_preview_download_and_bundle_keep_vip_description():
    from fwmigrate.web import create_app
    from tests.approved_design import approved_migrate

    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={"file": (io.BytesIO(source_text().encode()), "source.conf")})
    assert preview.status_code == 200
    response = approved_migrate(client, json={"source": preview.get_json()["source_evidence"],
        "workflow_mode": "OFFLINE_EXPORT", "mapping": {"vdoms": {"root": {"vsys": "vsys1"}}}})
    assert response.status_code == 200
    artifact = response.get_json()["artifact"]
    assert 'set vsys vsys1 address published description "VIP owner"' in artifact["commands"]
    body = {"artifact": artifact, "source": preview.get_json()["source_evidence"]}
    command_preview = client.post("/api/migration/command-preview", json=body)
    download = client.post("/api/migration/download", json=body)
    bundle = client.post("/api/migration/bundle", json=body)
    assert command_preview.status_code == download.status_code == bundle.status_code == 200
    assert command_preview.get_json()["commands"] == artifact["commands"]
    assert hashlib.sha256(download.data).hexdigest() == artifact["command_sha256"]
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        assert archive.read("palo_alto_config.set") == download.data


def test_invalid_vip_description_is_manual_before_target_placement():
    from fwmigrate.web import create_app

    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={"file": (io.BytesIO(source_text("unsafe\x01value").encode()), "source.conf")})
    assert preview.status_code == 200
    prepared = client.post("/api/migration/design/prepare", json={"source": preview.get_json()["source_evidence"],
        "workflow_mode": "OFFLINE_EXPORT"})
    assert prepared.status_code == 200
    draft = prepared.get_json()["draft"]
    row, = [row for row in draft["configuration"] if row["source_kind"] == "vip" and row["family"] == "address"]
    assert row["status"] == "UNSUPPORTED"
    assert any("unsafe CLI controls" in reason for reason in row["blocking_reasons"])

# --- test_vip_group_metadata_coverage.py ---
_VIP_GROUP_SOURCE = """config system interface
edit outside
set type physical
set ip 192.0.2.1 255.255.255.0
next
edit inside
set type physical
set ip 10.0.0.1 255.255.255.0
next
end
config firewall vip
edit published
set type static-nat
set extip 192.0.2.10
set mappedip 10.0.0.10
set extintf outside
next
end
config firewall vipgrp
edit published-group
set member published
next
end
config firewall policy
edit 1
set name inbound
set srcintf outside
set dstintf inside
set srcaddr all
set dstaddr published-group
set service ALL
set action accept
set schedule always
next
end
"""


def _vip_group_source_text(comment=None, extra=""):
    setting = "" if comment is None else f'set comments "{comment}"'
    return _VIP_GROUP_SOURCE.replace("set member published", f"set member published\n{setting}\n{extra}")


def options():
    return PANMigrationOptions(vdoms={"root": {"vsys": "vsys1", "virtual_router": "VR"}}, interfaces={"root": {
        "outside": {"target_interface": "ethernet1/1", "target_zone": "outside"},
        "inside": {"target_interface": "ethernet1/2", "target_zone": "inside"}}})


def _vip_group_migrate(text):
    analysis = FortiGateSourceReporter().analyze_source(text)
    before = deepcopy(analysis.extracted)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived, options=options(),
        include_interface_zones=True, source_inventory=analysis.extracted.source_objects)
    assert analysis.extracted == before
    return result


@pytest.mark.parametrize("comment", [None, "", "Group owner"])
def test_group_metadata_remains_manual_without_blocking_verified_traffic(comment):
    baseline = _vip_group_migrate(_vip_group_source_text())
    assert baseline.artifact_status == "READY"
    result = _vip_group_migrate(_vip_group_source_text(comment))
    assert result.rendered.commands == baseline.rendered.commands
    assert any("rulebase security" in command for command in result.rendered.commands)
    assert any("rulebase nat" in command for command in result.rendered.commands)
    if comment is None:
        assert result.coverage["complete"]
        assert result.artifact_status == "READY"
    else:
        assert result.artifact_status == "PARTIAL"
        assert not result.coverage["complete"]
        gap, = result.coverage["unplanned"]
        assert (gap["source_vdom"], gap["source_kind"], gap["source_name"]) == ("root", "vip_group", "published-group")
        assert "VIP-group comment requires manual metadata review" in gap["reason"]
        assert "membership and consumer coverage" not in gap["reason"]
        assert "Group owner" not in gap["reason"]


def test_unset_comment_does_not_create_metadata_work():
    result = _vip_group_migrate(_vip_group_source_text("Old owner", extra="unset comments"))
    assert result.artifact_status == "READY"
    assert result.coverage["complete"]


def test_same_named_source_groups_keep_scoped_residual_metadata_records():
    text = "config vdom\n" + "".join(f'''edit {vdom}
config firewall vipgrp
edit published-group
set member published
set comments "Scoped owner"
next
end
next
''' for vdom in ("root", "blue")) + "end\n"
    analysis = FortiGateSourceReporter().analyze_source(text)
    covered_membership = {("root", "published-group"), ("blue", "published-group")}
    coverage = build_migration_coverage(analysis.extracted.config, planned_vip_groups=covered_membership)
    assert coverage["unplanned_count"] == 2
    assert {row["source_vdom"] for row in coverage["unplanned"]} == {"root", "blue"}


def test_unrepresented_group_keeps_both_metadata_and_membership_limitations():
    analysis = FortiGateSourceReporter().analyze_source(_vip_group_source_text("Group owner"))
    coverage = build_migration_coverage(analysis.extracted.config)
    gap, = [row for row in coverage["unplanned"] if row["source_kind"] == "vip_group"]
    assert "VIP-group comment requires manual metadata review" in gap["reason"]
    assert "membership and consumer coverage" in gap["reason"]


def test_web_review_exposes_group_metadata_without_echoing_source_comment():
    from fwmigrate.web import create_app

    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={"file": (io.BytesIO(_vip_group_source_text("Group owner").encode()), "source.conf")})
    assert preview.status_code == 200
    prepared = client.post("/api/migration/design/prepare", json={"source": preview.get_json()["source_evidence"],
        "workflow_mode": "OFFLINE_EXPORT"})
    assert prepared.status_code == 200
    issues = prepared.get_json()["draft"]["issues"]
    assert any(row["category"] == "MANUAL" and "VIP-group comment requires manual metadata review" in row["explanation"]
               for row in issues)
    assert all("Group owner" not in row["explanation"] for row in issues)


def test_cli_keeps_traffic_commands_and_reports_remaining_group_metadata(tmp_path):
    from click.testing import CliRunner
    import yaml
    from fwmigrate.main import cli

    source = tmp_path / "source.conf"
    source.write_text(_vip_group_source_text("Group owner"))
    mapping = tmp_path / "mapping.yaml"
    mapping.write_text(yaml.safe_dump({"vdoms": {"root": {"vsys": "vsys1", "virtual_router": "VR"}},
        "interfaces": {"root": {"outside": {"target_interface": "ethernet1/1", "target_zone": "outside"},
                                "inside": {"target_interface": "ethernet1/2", "target_zone": "inside"}}}}))
    output = tmp_path / "output"
    response = CliRunner().invoke(cli, ["migrate", "-i", str(source), "-o", str(output),
        "--zone-map", str(mapping), "--automation-mode", "REVIEW_ONLY"])
    assert response.exit_code == 0, response.output
    report = json.loads((output / "migration_report.json").read_text())
    commands = (output / "palo_alto_config.set").read_text()
    assert report["plan_status"] == "PARTIAL"
    assert any("rulebase security" in row and "inbound" in row for row in commands.splitlines())
    assert any("VIP-group comment requires manual metadata review" in row["reason"] for row in report["coverage"]["unplanned"])

# --- test_central_nat_coverage.py ---
CENTRAL = '''config firewall central-snat-map
edit 20
set srcintf lan
set dstintf wan
set orig-addr all
set dst-addr all
set nat enable
set status disable
set type ipv4
next
end
'''

POLICY = '''config system interface
edit lan
set type physical
set ip 192.0.2.1 255.255.255.0
next
edit wan
set type physical
set ip 203.0.113.1 255.255.255.0
next
end
config firewall policy
edit 1
set name outbound
set srcintf lan
set dstintf wan
set srcaddr all
set dstaddr all
set service ALL
set schedule always
set action accept
set nat enable
next
end
'''


def _central_nat_migrate(text):
    analysis = FortiGateSourceReporter().analyze_source(text)
    original = deepcopy(analysis.extracted)
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}},
            interfaces={'root': {'lan': {'target_interface': 'ethernet1/1', 'target_zone': 'trust'},
                                 'wan': {'target_interface': 'ethernet1/2', 'target_zone': 'untrust'}}}) if 'config system interface' in text
            else PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}),
        source_inventory=analysis.extracted.source_objects, include_interface_zones=True)
    assert analysis.extracted == original
    return result


def test_central_snat_is_manual_coverage_even_when_its_entry_is_disabled():
    result = _central_nat_migrate('''config firewall address
edit host
set type ipmask
set subnet 192.0.2.1 255.255.255.255
next
end
''' + CENTRAL)
    row, = result.coverage['unplanned']
    assert row['source_kind'] == 'central_snat' and row['source_name'] == '20'
    assert row['source_vdom'] == 'root' and row['readiness'] == 'UNSUPPORTED'
    assert result.artifact_status == 'PARTIAL'
    assert not result.plan.nat_rules
    assert result.rendered.commands == ('set vsys vsys1 address host ip-netmask 192.0.2.1/32',)


@pytest.mark.parametrize('extra', [
    CENTRAL,
    'config system settings\nset central-nat enable\nend\n',
    'config system settings\nset central-nat disable\nend\n',
    'config system settings\nunset central-nat\nend\n',
    'config system settings\nset ngfw-mode policy-based\nend\n',
])
def test_central_nat_evidence_needs_mode_review_before_policy_nat_export(extra):
    baseline = _central_nat_migrate(POLICY)
    assert baseline.artifact_status == 'READY'
    assert any('source-translation' in command for command in baseline.rendered.commands)
    result = _central_nat_migrate(POLICY + extra)
    rule, = result.plan.nat_rules
    assert rule.status.value == 'MANUAL_REVIEW'
    assert any('Central NAT' in warning for warning in rule.warnings)
    assert not any(' rulebase nat ' in command for command in result.rendered.commands)
    assert result.artifact_status == 'PARTIAL'


def test_central_nat_review_is_scoped_to_its_source_vdom():
    result = _central_nat_migrate(POLICY + 'config vdom\nedit blue\n' + CENTRAL + 'next\nend\n')
    rule, = result.plan.nat_rules
    assert rule.status.value == 'SUPPORTED' and rule.source_vdom == 'root'
    assert any('source-translation' in command for command in result.rendered.commands)
    assert any(row['source_kind'] == 'central_snat' and row['source_vdom'] == 'blue'
               for row in result.coverage['unplanned'])


def test_central_mode_control_also_blocks_vip_and_dependent_security_rule():
    source = POLICY.replace('set srcintf lan', 'set srcintf wan').replace('set dstintf wan', 'set dstintf lan')
    source = source.replace('set dstaddr all', 'set dstaddr published').replace('set nat enable', 'set nat disable')
    source += '''config firewall vip
edit published
set type static-nat
set extintf wan
set extip 203.0.113.10
set mappedip 192.0.2.10
next
end
'''
    baseline = _central_nat_migrate(source)
    assert any('destination-translation' in command for command in baseline.rendered.commands)
    result = _central_nat_migrate(source + 'config system settings\nset central-nat enable\nend\n')
    assert all(rule.status.value == 'MANUAL_REVIEW' for rule in result.plan.nat_rules)
    assert not any(' rulebase ' in command for command in result.rendered.commands)


def test_web_draft_retains_central_review_after_service_name_override():
    import io
    from fwmigrate.web import create_app

    source = POLICY.replace('set service ALL', 'set service web') + '''config firewall service custom
edit web
set protocol TCP/UDP/SCTP
set tcp-portrange 443
next
end
config system settings
set central-nat enable
end
'''
    client = create_app({'TESTING': True}).test_client()
    preview = client.post('/api/preview', data={'file': (io.BytesIO(source.encode()), 'source.conf')})
    assert preview.status_code == 200
    response = client.post('/api/migration/design/prepare', json={
        'source': preview.get_json()['source_evidence'], 'workflow_mode': 'OFFLINE_EXPORT',
        'service_name_overrides': {'root': {'web': 'target-web'}}})
    assert response.status_code == 200
    rows = response.get_json()['draft']['configuration']
    rules = [row for row in rows if row['family'] == 'nat_rule']
    assert rules and all(row['status'] == 'UNSUPPORTED' for row in rules)
    assert all(any('Central NAT' in reason for reason in row['blocking_reasons']) for row in rules)

# --- test_ip_pool_coverage.py ---
def test_unused_pool_is_manual_work_instead_of_a_complete_independent_export(tmp_path):
    text = '''config firewall address
edit host
set type ipmask
set subnet 192.0.2.1 255.255.255.255
next
end
config firewall ippool
edit unused
set type overload
set startip 198.51.100.1
set endip 198.51.100.1
next
end
'''
    analysis = FortiGateSourceReporter().analyze_source(text)
    source = analysis.extracted.config
    before = deepcopy(source)
    result = run_migration_pipeline(source, analysis.derived,
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1'}}))
    row, = result.coverage['unplanned']
    assert row['source_kind'] == 'ip_pool' and row['source_name'] == 'unused'
    assert row['status'] == 'SOURCE_ONLY' and row['readiness'] == 'UNSUPPORTED'
    assert 'IP-pool' in row['reason']
    assert result.artifact_status == 'PARTIAL' and not result.coverage['complete']
    assert result.rendered.commands == ('set vsys vsys1 address host ip-netmask 192.0.2.1/32',)
    assert source == before

    from click.testing import CliRunner
    from fwmigrate.main import cli

    source_path = tmp_path / 'source.conf'
    source_path.write_text(text)
    mapping = tmp_path / 'mapping.yaml'
    mapping.write_text('vdoms:\n  root:\n    vsys: vsys1\n')
    output = tmp_path / 'output'
    response = CliRunner().invoke(cli, ['migrate', '--input', str(source_path), '--output', str(output),
        '--zone-map', str(mapping), '--automation-mode', 'REVIEW_ONLY'])
    assert response.exit_code == 0, response.output
    assert 'Plan status: PARTIAL' in response.output
    assert 'Unplanned source configuration: 1 (0 recommendation-only, 1 source-only)' in response.output
    assert f"Migration report: {output / 'migration_report.json'}" in response.output

    from fwmigrate.conversion.fortigate_to_palo_alto.application.review import build_review_state
    from fwmigrate.conversion.fortigate_to_palo_alto.design.deterministic import approve_draft, build_deterministic_draft

    state = build_review_state(source, analysis.derived, 'source', include_configuration=True)
    draft = build_deterministic_draft(source, analysis.derived, state['decisions'], source_digest='source')
    gap, = (row for row in draft.configuration if row['source_kind'] == 'ip_pool')
    assert gap['status'] == 'UNSUPPORTED' and gap['operation'] is None
    with pytest.raises(ValueError, match='blocked'):
        approve_draft(state['decisions'], draft, [gap['group_key']])


@pytest.mark.parametrize('nat', ['enable', 'disable'])
def test_real_pool_translation_remains_covered_but_unused_reference_does_not(nat):
    analysis = FortiGateSourceReporter().analyze_source(f'''config system interface
edit inside
set type physical
set ip 192.0.2.1 255.255.255.0
next
edit outside
set type physical
set ip 203.0.113.1 255.255.255.0
next
end
config firewall ippool
edit pool
set type overload
set startip 198.51.100.10
set endip 198.51.100.10
next
end
config firewall policy
edit 1
set srcintf inside
set dstintf outside
set srcaddr all
set dstaddr all
set service ALL
set schedule always
set action accept
set nat {nat}
set ippool enable
set poolname pool
next
end
''')
    result = run_migration_pipeline(analysis.extracted.config, analysis.derived,
        options=PANMigrationOptions(vdoms={'root': {'vsys': 'vsys1', 'virtual_router': 'VR'}},
            interfaces={'root': {'inside': {'target_interface': 'ethernet1/1', 'target_zone': 'trust'},
                                 'outside': {'target_interface': 'ethernet1/2', 'target_zone': 'untrust'}}}))
    assert result.coverage['complete'] == (nat == 'enable')
    assert any(rule.translated_addresses == ('198.51.100.10',) for rule in result.plan.nat_rules) == (nat == 'enable')
    # Default programmatic planning does not request interface-backed zones.
    # A covered pool does not make its blocked NAT consumer executable.
    assert result.artifact_status == 'PARTIAL'
    assert not any('source-translation' in command for command in result.rendered.commands)


@pytest.mark.parametrize('source_kind', ['source_nat', 'vip'])
def test_pool_consumers_include_split_and_combined_nat_but_keep_vdoms_distinct(source_kind):
    source = FGConfig(ip_pools=[FGIPPool(name='pool', vdom=vdom) for vdom in ('root', 'branch')],
        policies=[FGPolicy(policy_id=1, vdom=vdom, poolname=['pool']) for vdom in ('root', 'branch')])
    rule = PlannedNATRule(source_vdom='root', source_kind=source_kind, source_policy_id=1,
        source_translation_type='dynamic-ip-and-port', translated_addresses=('198.51.100.1',))
    plan = PANMigrationPlan(nat_rules=(replace(rule, target_name='split-1'), replace(rule, target_name='split-2')))
    rows = build_migration_coverage(source, plan=plan)['unplanned']
    assert [(row['source_vdom'], row['source_name']) for row in rows] == [('branch', 'pool')]
    assert len(build_migration_coverage(source)['unplanned']) == 2


@pytest.mark.parametrize('failure', ['no_rule', 'interface_snat', 'no_translation', 'wrong_policy', 'ambiguous_policy'])
def test_policy_reference_alone_cannot_hide_an_unrepresented_pool(failure):
    policy = FGPolicy(policy_id=1, poolname=['pool'])
    source = FGConfig(ip_pools=[FGIPPool(name='pool')], policies=[policy])
    rule = PlannedNATRule(source_vdom='root', source_kind='source_nat', source_policy_id=1,
        source_translation_type='dynamic-ip-and-port', translated_addresses=('198.51.100.1',))
    if failure == 'interface_snat':
        rule = replace(rule, source_interface_address=True)
    elif failure == 'no_translation':
        rule = replace(rule, translated_addresses=())
    elif failure == 'wrong_policy':
        rule = replace(rule, source_policy_id=2)
    elif failure == 'ambiguous_policy':
        source.policies.append(policy.model_copy())
    plan = PANMigrationPlan(nat_rules=() if failure == 'no_rule' else (rule,))
    assert build_migration_coverage(source, plan=plan)['unplanned_count'] == 1

NAT_SOURCE = SOURCE
