from copy import deepcopy
from dataclasses import replace

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto.coverage import build_migration_coverage
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PlannedNATRule
from fwmigrate.conversion.fortigate_to_palo_alto.options import PANMigrationOptions
from fwmigrate.conversion.fortigate_to_palo_alto.pipeline import run_migration_pipeline
from fwmigrate.vendors.fortigate.model.ippool import FGIPPool
from fwmigrate.vendors.fortigate.model.policy import FGPolicy
from fwmigrate.vendors.fortigate.model.source import FGConfig
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


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
