from copy import deepcopy
import io
import pytest

from fwmigrate.web import create_app


SOURCE = '''config system interface
    edit "port1"
        set type physical
        set ip 192.0.2.1 255.255.255.0
    next
    edit "vlan10"
        set interface "port1"
        set vlanid 10
        set ip 198.51.100.1 255.255.255.0
    next
end
config firewall address
    edit "net"
        set subnet 192.0.2.0 255.255.255.0
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 192.0.2.254
        set device "port1"
    next
end
'''
TARGET = '''<config><devices><entry name="fw"><network><interface><ethernet>
<entry name="ethernet1/1"><layer3/></entry></ethernet></interface></network>
<vsys><entry name="vsys1"/></vsys></entry></devices></config>'''


def setup(target=TARGET, role='DESTINATION'):
    client = create_app({'TESTING': True, 'WORKSPACE_SIGNING_KEY': 'd' * 32}).test_client()
    def upload(text, vendor, name):
        result = client.post('/api/preview', data={'source_vendor': vendor,
            'file': (io.BytesIO(text.encode()), name)}, content_type='multipart/form-data')
        assert result.status_code == 200, result.get_json()
        return result.get_json()['source_evidence']
    payload = {'source': upload(SOURCE, 'fortigate', 'source.conf')}
    if target is not None:
        payload.update(target_source=upload(target, 'palo_alto', 'target.xml'), reference_role=role)
    return client, payload


def prepare(client, payload):
    response = client.post('/api/migration/design/prepare', json=payload)
    assert response.status_code == 200, response.get_json()
    data = response.get_json()
    return data, {**payload, 'decision_document': data['decision_document']}


def allocate(client, payload):
    data, payload = prepare(client, payload)
    key = next(row['decision_key'] for row in data['draft']['decisions']
               if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    return prepare(client, {**payload, 'draft_overrides': {key: 'ethernet1/1'}})


def approve(client, payload, data, groups=None):
    draft = data['draft']
    keys = groups if groups is not None else [row['decision_key'] for row in draft['decisions'] if row['status'] == 'READY'] + [
        row['group_key'] for row in draft['configuration'] if row['status'] == 'READY']
    return client.post('/api/migration/design/approve', json={**payload, 'draft': draft,
        'draft_digest': draft['digest'], 'selected_groups': keys})


def test_prepare_repeatable_no_authoritative_confirmation():
    client, payload = setup()
    data, payload = prepare(client, payload)
    again, _ = prepare(client, payload)
    assert again['draft'] == data['draft']
    assert all(row['review_state'] == 'PENDING' for row in data['decisions']['decisions'])
    assert 'commands' not in data['draft'] and 'artifact' not in data
    assert any(row['family'] == 'address' and row['status'] == 'READY' for row in data['draft']['configuration'])
    assert any(row['source_name'] == 'port1' and row['status'] == 'NEEDS_INPUT' for row in data['draft']['decisions'])
    port = next(row['decision_key'] for row in data['draft']['decisions']
                if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    route = next(row for row in data['draft']['configuration'] if row['family'] == 'static_route')
    assert port in route['dependencies']


def test_parent_allocation_unlocks_vlan_and_approved_additive_commands():
    client, payload = setup()
    data, payload = allocate(client, payload)
    rows = data['draft']['decisions']
    assert next(row for row in rows if row['source_name'] == 'vlan10' and row['target_field'] == 'target_interface')['proposed_value'] == 'ethernet1/1.10'
    assert next(row for row in rows if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')['operation'] == 'CONFIGURE'
    response = approve(client, payload, data)
    assert response.status_code == 200, response.get_json()
    document = response.get_json()['decision_document']
    result = client.post('/api/migrate', json={**payload, 'decision_document': document})
    assert result.status_code == 200, result.get_json()
    plan = result.get_json()
    commands = plan['commands']
    assert 'set network interface ethernet ethernet1/1 layer3 ip 192.0.2.1/24' in commands
    assert 'set network interface ethernet ethernet1/1 layer3' not in commands
    assert any('units ethernet1/1.10 tag 10' in command for command in commands)
    assert 'set network virtual-router vr-root' in commands
    assert plan['render_dispositions']['CONFIGURE'] >= 1
    assert plan['report']['approved_design_digest'] == data['draft']['digest']
    assert plan['report']['destination_verified']
    for path in ['/api/migration/command-preview', '/api/migration/download', '/api/migration/bundle']:
        response = client.post(path, json={'source': payload['source'], 'artifact': plan['artifact']})
        assert response.status_code == 200, response.get_json()


@pytest.mark.parametrize('change', ['signature', 'role', 'override', 'selection', 'parent'])
def test_approval_rejects_forged_stale_and_incomplete_selection_atomically(change):
    client, payload = setup()
    data, payload = allocate(client, payload)
    if change == 'signature':
        data['draft']['decisions'][0]['operation'] = 'REUSE'
    elif change == 'role':
        payload['reference_role'] = 'TEMPLATE'
    elif change == 'override':
        payload['draft_overrides'] = {key: 'ethernet1/2' for key in payload['draft_overrides']}
    elif change == 'parent':
        payload['decision_document']['decisions'][0]['value'] = 'changed'
        payload['decision_document']['decisions'][0]['review_state'] = 'CONFIRMED'
    groups = None
    if change == 'selection':
        groups = [next(row['decision_key'] for row in data['draft']['decisions'] if row['source_name'] == 'vlan10')]
    response = approve(client, payload, data, groups)
    assert response.status_code == 409, response.get_json()


def test_signed_draft_cannot_be_deployed_and_unsigned_operations_cannot_render():
    client, payload = setup()
    data, payload = allocate(client, payload)
    response = client.post('/api/migration/command-preview', json={'artifact': data['draft']})
    assert response.status_code == 400
    row = payload['decision_document']['decisions'][0]
    row.update(value='vsys1', review_state='CONFIRMED', approved_operation='CREATE')
    assert client.post('/api/migrate', json=payload).status_code == 400


def test_template_and_source_only_cannot_establish_destination_reuse():
    for target, role in [(TARGET, 'TEMPLATE'), (None, None)]:
        client, payload = setup(target, role)
        data, payload = allocate(client, payload)
        assert not data['draft']['destination_verified']
        assert all(row['operation'] != 'REUSE' for row in data['draft']['decisions'])
        assert any(row['code'] == 'DESTINATION_UNVERIFIED' for row in data['draft']['findings'])


def test_changed_approved_parent_and_reference_invalidate_approval():
    client, payload = setup()
    data, payload = allocate(client, payload)
    response = approve(client, payload, data)
    assert response.status_code == 200, response.get_json()
    payload['decision_document'] = response.get_json()['decision_document']
    changed = deepcopy(payload)
    changed['reference_role'] = 'TEMPLATE'
    assert client.post('/api/migrate', json=changed).status_code == 400
    data, _ = prepare(client, changed)
    assert 'design_approval' not in data['decision_document']
    assert not any(row['approved_operation'] for row in data['decisions']['decisions'])
    row = next(row for row in payload['decision_document']['decisions'] if row['source_name'] == 'port1')
    row['value'] = 'ethernet1/2'
    assert client.post('/api/migrate', json=payload).status_code == 400


def test_partial_group_approval_and_decision_export_import_keep_the_boundary():
    client, payload = setup()
    data, payload = allocate(client, payload)
    scope = next(row['decision_key'] for row in data['draft']['decisions'] if row['target_field'] == 'vsys')
    address = next(row['group_key'] for row in data['draft']['configuration'] if row['family'] == 'address')
    response = approve(client, payload, data, [scope, address])
    assert response.status_code == 200, response.get_json()
    document = response.get_json()['decision_document']
    partial = client.post('/api/migrate', json={**payload, 'decision_document': document}).get_json()
    assert partial['plan_status'] != 'READY'
    assert partial['commands'] == ['set system setting target-vsys vsys1', 'set address net ip-netmask 192.0.2.0/24']
    exported = client.post('/api/migration/decisions/export', json={**payload, 'decision_document': document}).get_json()['document']
    assert exported['design_approval'] == document['design_approval']
    imported = client.post('/api/migration/decisions/import', json={**payload, 'document': exported}).get_json()['decision_document']
    assert imported['design_approval'] == document['design_approval']
    data, payload = prepare(client, {**payload, 'decision_document': imported})
    remaining = [row['decision_key'] for row in data['draft']['decisions'] if row['status'] == 'READY' and not row['approved']]
    remaining += [row['group_key'] for row in data['draft']['configuration'] if row['status'] == 'READY' and row['group_key'] != address]
    response = approve(client, payload, data, remaining)
    assert response.status_code == 200, response.get_json()
    final = client.post('/api/migrate', json={**payload, 'decision_document': response.get_json()['decision_document']})
    assert final.get_json()['plan_status'] == 'READY', final.get_json()


@pytest.mark.parametrize('settings', ['<ip><entry name="203.0.113.1/24"/></ip>', '<future-setting>unknown</future-setting>'])
def test_conflicting_or_unknown_target_settings_block_additive_configuration(settings):
    client, payload = setup(TARGET.replace('<layer3/>', f'<layer3>{settings}</layer3>'))
    data, payload = allocate(client, payload)
    row = next(row for row in data['draft']['decisions'] if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    assert row['status'] == 'CONFLICT'
    response = approve(client, payload, data, [row['decision_key']])
    assert response.status_code == 409


def test_template_address_match_does_not_allocate_a_physical_port():
    client, payload = setup(TARGET.replace('<layer3/>', '<layer3><ip><entry name="192.0.2.1/24"/></ip></layer3>'), 'TEMPLATE')
    data, _ = prepare(client, payload)
    physical = next(row for row in data['draft']['decisions'] if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    assert physical['proposed_value'] is None


def test_manual_interface_edit_revokes_operations_without_losing_allocations():
    client, payload = setup()
    data, payload = allocate(client, payload)
    response = approve(client, payload, data)
    payload['decision_document'] = response.get_json()['decision_document']
    data, payload = prepare(client, payload)
    interface = next(row for row in data['decisions']['decisions']
                     if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    response = client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [{'decision_key': interface['key'], 'value': interface['value']}],
        'reviewed_target_evidence': data['target_evidence']})
    assert response.status_code == 200, response.get_json()
    document = response.get_json()['decision_document']
    assert document['draft_required']
    assert 'design_approval' not in document
    assert not any(row['approved_operation'] or row['approval_context'] for row in document['decisions'])
    assert client.post('/api/migrate', json={**payload, 'decision_document': document}).status_code == 400
    refreshed, payload = prepare(client, {**payload, 'decision_document': document})
    assert next(row['value'] for row in refreshed['decisions']['decisions'] if row['key'] == interface['key']) == interface['value']
    approved = approve(client, payload, refreshed)
    assert approved.status_code == 200, approved.get_json()
    assert client.post('/api/migrate', json={**payload,
        'decision_document': approved.get_json()['decision_document']}).get_json()['plan_status'] == 'READY'


def test_template_manual_allocation_survives_refresh_without_destination_provenance():
    client, payload = setup(role='TEMPLATE')
    data, payload = allocate(client, payload)
    interface = next(row for row in data['decisions']['decisions']
                     if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    selection = {'decision_key': interface['key'], 'value': 'ethernet1/1'}
    response = client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [selection], 'reviewed_target_evidence': data['target_evidence']})
    assert response.status_code == 200, response.get_json()
    document = response.get_json()['decision_document']
    row = next(row for row in document['decisions'] if row['key'] == interface['key'])
    assert row['evidence_type'] == 'MANUAL'
    assert row['evidence_target_digest'] is None and row['evidence_target_device'] is None
    refreshed, _ = prepare(client, {**payload, 'decision_document': document})
    assert next(row['value'] for row in refreshed['decisions']['decisions'] if row['key'] == interface['key']) == 'ethernet1/1'
    assert not refreshed['draft']['destination_verified']
    stale = {**data['target_evidence'], 'config_digest': 'changed'}
    assert client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [selection], 'reviewed_target_evidence': stale}).status_code == 400


def test_proposal_edit_after_approval_requires_reapproval_and_keeps_new_value():
    client, payload = setup()
    data, payload = allocate(client, payload)
    payload['decision_document'] = approve(client, payload, data).get_json()['decision_document']
    zone = next(row['decision_key'] for row in data['draft']['decisions'] if row['target_field'] == 'target_zone')
    data, payload = prepare(client, {**payload, 'draft_overrides': {**payload['draft_overrides'], zone: 'new-zone'}})
    assert 'design_approval' not in data['decision_document']
    assert next(row['proposed_value'] for row in data['draft']['decisions'] if row['decision_key'] == zone) == 'new-zone'
    assert client.post('/api/migrate', json=payload).status_code == 400
    response = approve(client, payload, data)
    assert response.status_code == 200, response.get_json()
    plan = client.post('/api/migrate', json={**payload, 'decision_document': response.get_json()['decision_document']})
    assert plan.status_code == 200, plan.get_json()
    assert any('zone new-zone' in command for command in plan.get_json()['commands'])


@pytest.mark.parametrize('change', ['signature', 'unsigned', 'role'])
def test_manual_confirmation_cannot_launder_invalid_design_approval(change):
    client, payload = setup()
    data, payload = allocate(client, payload)
    payload['decision_document'] = approve(client, payload, data).get_json()['decision_document']
    interface = next(row for row in payload['decision_document']['decisions']
                     if row['source_name'] == 'port1' and row['target_field'] == 'target_interface')
    if change == 'signature':
        payload['decision_document']['design_approval']['signature'] = 'invalid'
    elif change == 'unsigned':
        payload['decision_document'].pop('design_approval')
    else:
        payload['reference_role'] = 'UNKNOWN'
    response = client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [{'decision_key': interface['key'], 'value': interface['value']}],
        'reviewed_target_evidence': data['target_evidence']})
    assert response.status_code == 400, response.get_json()
