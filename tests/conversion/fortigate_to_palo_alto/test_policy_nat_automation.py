from copy import deepcopy
from dataclasses import replace

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
