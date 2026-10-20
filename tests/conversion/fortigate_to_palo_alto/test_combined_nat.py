import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus
from fwmigrate.conversion.fortigate_to_palo_alto.decisions import PANMigrationDecisionSet
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.plan_dependencies import build_plan_dependency_index, item_key
from fwmigrate.conversion.fortigate_to_palo_alto.planner import FortiGateToPaloAltoPlanner
from fwmigrate.conversion.fortigate_to_palo_alto.rendering.renderer import PANSetRenderer
from fwmigrate.conversion.fortigate_to_palo_alto.target.target_plan_validation import assess_target_plan
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


SOURCE = '''config system interface
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
    plan = plan_source(SOURCE)
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
    SOURCE.replace('198.51.100.0 255.255.255.0', '10.0.0.0 255.255.255.0'),
    SOURCE.replace('set srcaddr clients', 'set srcaddr all'),
    SOURCE.replace('set type overload', 'set type one-to-one'),
    SOURCE + 'config firewall policy\nedit 2\nset action deny\nnext\nend\n',
    SOURCE.replace('set service ALL', 'set service HTTPS'),
])
def test_uncertain_combined_matches_keep_both_rules_blocked(source):
    plan = plan_source(source)
    assert all(rule.status is not PANMigrationStatus.SUPPORTED for rule in plan.nat_rules)
    assert not any(' rulebase nat ' in command for command in PANSetRenderer().render(plan).commands)


def test_combined_translation_requires_approved_egress_and_blocks_consuming_policy():
    plan = plan_source(SOURCE)
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
    plan = plan_source(SOURCE + second)
    assert len(plan.nat_rules) == 2
    assert all(rule.status is PANMigrationStatus.SUPPORTED for rule in plan.nat_rules)
    assert [rule.source_policy_id for rule in plan.nat_rules] == [1, 2]
    assert all(rule.translated_addresses == ('10.0.0.100',) for rule in plan.nat_rules)
    # Sharing the public address or mapped server no longer proves separate partitions.
    for changed in (second.replace('192.0.2.20', '192.0.2.10'), second.replace('10.0.0.20', '10.0.0.10')):
        blocked = plan_source(SOURCE + changed)
        assert not any(rule.source_translation_type and rule.destination_translated_address
                       and rule.status is PANMigrationStatus.SUPPORTED for rule in blocked.nat_rules)
