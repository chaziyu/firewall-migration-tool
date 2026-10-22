from copy import deepcopy

import pytest

from fwmigrate.conversion.fortigate_to_palo_alto import PANMigrationOptions, run_migration_pipeline
from fwmigrate.vendors.fortigate.source_report import FortiGateSourceReporter


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


def migrate(text):
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
    result = migrate('''config firewall address
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
    baseline = migrate(POLICY)
    assert baseline.artifact_status == 'READY'
    assert any('source-translation' in command for command in baseline.rendered.commands)
    result = migrate(POLICY + extra)
    rule, = result.plan.nat_rules
    assert rule.status.value == 'MANUAL_REVIEW'
    assert any('Central NAT' in warning for warning in rule.warnings)
    assert not any(' rulebase nat ' in command for command in result.rendered.commands)
    assert result.artifact_status == 'PARTIAL'


def test_central_nat_review_is_scoped_to_its_source_vdom():
    result = migrate(POLICY + 'config vdom\nedit blue\n' + CENTRAL + 'next\nend\n')
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
    baseline = migrate(source)
    assert any('destination-translation' in command for command in baseline.rendered.commands)
    result = migrate(source + 'config system settings\nset central-nat enable\nend\n')
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
