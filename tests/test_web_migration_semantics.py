import io
import zipfile

import pytest

from tests.test_web_migration_design import approve, prepare, setup


INTERFACES = '''config system interface
 edit lan1
  set type physical
  set ip 192.0.2.1 255.255.255.0
 next
 edit lan2
  set type physical
  set ip 192.0.3.1 255.255.255.0
 next
 edit wan
  set type physical
  set ip 198.51.100.1 255.255.255.0
 next
end
config firewall address
 edit independent
  set type ipmask
  set subnet 203.0.113.10 255.255.255.255
 next
end
'''


def policy(policy_id, name, *, source='lan1', destination='all', nat='disable', schedule='always', extra=''):
    return f'''config firewall policy
 edit {policy_id}
  set name {name}
  set srcintf {source}
  set dstintf wan
  set srcaddr all
  set dstaddr {destination}
  set service ALL
  set schedule {schedule}
  set action accept
  set nat {nat}
  {extra}
 next
end
'''


def build_and_download(client, payload, data):
    approved = approve(client, payload, data)
    assert approved.status_code == 200, approved.get_json()
    response = client.post('/api/migrate', json={**payload,
        'decision_document': approved.get_json()['decision_document']})
    assert response.status_code == 200, response.get_json()
    result = response.get_json()
    request = {'source': payload['source'], 'artifact': result['artifact']}
    preview = client.post('/api/migration/command-preview', json=request)
    download = client.post('/api/migration/download', json=request)
    bundle = client.post('/api/migration/bundle', json=request)
    assert preview.status_code == download.status_code == bundle.status_code == 200
    assert preview.get_json()['commands'] == result['commands']
    assert download.data == '\n'.join(result['commands']).encode()
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        filename = next(name for name in archive.namelist() if name.endswith('.set'))
        assert archive.read(filename) == download.data
    return result


@pytest.mark.parametrize('intrazone', ['deny', None, 'allow'])
def test_intrazone_semantics_gate_signed_zone_and_policy_export(intrazone):
    setting = f'set intrazone {intrazone}' if intrazone else ''
    source = INTERFACES + f'''config system zone
 edit inside
  set interface lan1 lan2
  {setting}
 next
end
''' + policy(1, 'outbound', source='inside')
    client, payload = setup(None, source=source)
    data, payload = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT'})
    zone = next(row for row in data['draft']['configuration'] if row['source_name'] == 'inside')
    blocked = intrazone != 'allow'
    assert (zone['status'] != 'READY') == blocked
    if blocked:
        assert zone['blocking_reasons']
        assert approve(client, payload, data, [zone['group_key']]).status_code == 409
    result = build_and_download(client, payload, data)
    assert any(' zone inside ' in command for command in result['commands']) != blocked
    assert any('rules outbound ' in command for command in result['commands']) != blocked
    assert any('address independent ' in command for command in result['commands'])
    assert (result['plan_status'] == 'READY') != blocked


@pytest.mark.parametrize('disabled,disjoint', [(False, False), (True, False), (False, True)])
def test_no_nat_exception_gates_later_snat_and_owning_policy(disabled, disjoint):
    source = INTERFACES + policy(20, 'no-nat-first', destination='independent',
        extra='set status disable' if disabled else '') + policy(1, 'nat-later',
        source='lan2' if disjoint else 'lan1', nat='enable', extra='set ippool disable')
    client, payload = setup(None, source=source)
    data, payload = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT'})
    rows = [row for row in data['draft']['configuration'] if row['source_name'] == 'nat-later']
    assert {row['family'] for row in rows} == {'security_rule', 'nat_rule'}
    blocked = not disabled and not disjoint
    assert all((row['status'] != 'READY') == blocked for row in rows)
    if blocked:
        assert all(row['blocking_reasons'] for row in rows)
        assert approve(client, payload, data, [row['group_key'] for row in rows]).status_code == 409
    result = build_and_download(client, payload, data)
    assert any('rulebase nat rules nat-later ' in command for command in result['commands']) != blocked
    assert any('rulebase security rules nat-later ' in command for command in result['commands']) != blocked
    assert any('address independent ' in command for command in result['commands'])
    assert (result['plan_status'] == 'READY') != blocked


@pytest.mark.parametrize('schedule,blocked', [
    ('config firewall schedule onetime\n edit window\n set start 01:00 2026/12/25\n'
     ' set end 02:00 2026/12/25\n next\nend\n', False),
    ('config firewall schedule recurring\n edit window\n set day none\n'
     ' set start 08:00\n set end 17:00\n next\nend\n', True),
])
def test_native_schedules_are_converted_or_block_dependent_signed_exports(schedule, blocked):
    client, payload = setup(None, source=INTERFACES + schedule + policy(1, 'scheduled', schedule='window'))
    data, payload = prepare(client, {**payload, 'workflow_mode': 'OFFLINE_EXPORT'})
    row = next(row for row in data['draft']['configuration'] if row['family'] == 'schedule')
    assert (row['status'] != 'READY') == blocked
    if blocked:
        assert approve(client, payload, data, [row['group_key']]).status_code == 409
    result = build_and_download(client, payload, data)
    if blocked:
        assert not any('schedule window ' in command or 'rules scheduled ' in command for command in result['commands'])
    else:
        assert 'set vsys vsys1 schedule window schedule-type non-recurring [ 2026/12/25@01:00-2026/12/25@02:00 ]' in result['commands']
        assert any('rules scheduled schedule window' in command for command in result['commands'])
    assert (result['plan_status'] == 'READY') != blocked


@pytest.mark.parametrize('feature', ['zone', 'nat', 'schedule'])
def test_destination_evidence_cannot_promote_unrepresented_source_semantics(feature):
    if feature == 'zone':
        source = INTERFACES + '''config system zone
 edit inside
  set interface lan1 lan2
  set intrazone deny
 next
end
''' + policy(1, 'affected', source='inside')
        zones = [('inside', 'ethernet1/1 ethernet1/2'), ('root-wan', 'ethernet1/3')]
        blocked_family = 'zone'
    elif feature == 'nat':
        source = INTERFACES + policy(20, 'exception', destination='independent') + policy(
            1, 'affected', nat='enable', extra='set ippool disable')
        zones = [(f'root-{name}', f'ethernet1/{number}') for number, name in enumerate(('lan1', 'lan2', 'wan'), 1)]
        blocked_family = 'nat_rule'
    else:
        source = INTERFACES + '''config firewall schedule recurring
 edit never
  set day none
  set start 08:00
  set end 17:00
 next
end
''' + policy(1, 'affected', schedule='never')
        zones = [(f'root-{name}', f'ethernet1/{number}') for number, name in enumerate(('lan1', 'lan2', 'wan'), 1)]
        blocked_family = 'schedule'
    ethernet = ''.join(f'<entry name="ethernet1/{number}"><layer3><ip><entry name="{address}/24"/></ip></layer3></entry>'
        for number, address in enumerate(('192.0.2.1', '192.0.3.1', '198.51.100.1'), 1))
    zone_xml = ''.join(f'<entry name="{name}"><network><layer3>'
        + ''.join(f'<member>{interface}</member>' for interface in interfaces.split())
        + '</layer3></network></entry>' for name, interfaces in zones)
    target = ('<config><devices><entry name="fw"><network><interface><ethernet>' + ethernet
        + '</ethernet></interface><virtual-router><entry name="vr-root"/></virtual-router></network>'
        + '<vsys><entry name="vsys1"><zone>' + zone_xml + '</zone></entry></vsys></entry></devices></config>')
    client, payload = setup(target, source=source)
    data, payload = prepare(client, payload)
    allocations = {name: f'ethernet1/{number}' for number, name in enumerate(('lan1', 'lan2', 'wan'), 1)}
    data, payload = prepare(client, {**payload, 'draft_overrides': {
        row['decision_key']: allocations[row['source_name']] for row in data['draft']['decisions']
        if row['target_field'] == 'target_interface'}})
    affected = [row for row in data['draft']['configuration'] if row['family'] in {blocked_family, 'security_rule'}
                and row['source_name'] != 'exception']
    assert affected and all(row['status'] != 'READY' for row in affected)
    assert approve(client, payload, data, [row['group_key'] for row in affected]).status_code == 409
    result = build_and_download(client, payload, data)
    assert result['plan_status'] not in {'READY', 'READY_NO_CHANGES'}
    assert not any('rules affected ' in command or ' zone inside ' in command or 'schedule never ' in command
                   for command in result['commands'])
