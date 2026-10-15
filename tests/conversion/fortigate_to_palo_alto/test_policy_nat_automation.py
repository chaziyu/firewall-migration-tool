from copy import deepcopy
from dataclasses import replace

import pytest

from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.planning.policies import inspection_design_groups
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.cli_paths import security_rule


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
