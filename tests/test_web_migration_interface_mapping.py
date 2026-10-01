import io
from copy import deepcopy
from pathlib import Path

import pytest

from fwmigrate.web import create_app


SOURCE = Path(__file__).parent / 'fixtures' / 'fortigate' / 'palo_alto_mvp.conf'
TARGET = Path(__file__).parent / 'fixtures' / 'palo_alto' / 'integrated_firewall.xml'


def _review(target=False):
    client = create_app({'TESTING': True}).test_client()
    def upload(path, vendor):
        return client.post('/api/preview', data={'source_vendor': vendor,
            'file': (io.BytesIO(path.read_bytes()), path.name)}, content_type='multipart/form-data').get_json()['preview_id']
    payload = {'preview_id': upload(SOURCE, 'fortigate')}
    if target:
        payload['target_preview_id'] = upload(TARGET, 'palo_alto')
    state = client.post('/api/migration/requirements', json=payload).get_json()
    rows = [item for item in state['decisions']['decisions'] if item['target_field'] == 'target_interface']
    return client, {**payload, 'decision_document': state['decision_document'],
                    'reviewed_target_evidence': state['target_evidence']}, rows, state


def test_valid_batch_confirms_only_selected_interfaces_and_preserves_provenance():
    client, payload, rows, _ = _review()
    payload['selections'] = [{'decision_key': item['key'], 'value': f'ethernet1/{index + 1}'} for index, item in enumerate(rows)]
    response = client.post('/api/migration/interfaces/confirm', json=payload)
    assert response.status_code == 200, response.get_json()
    data = response.get_json()
    confirmed = [item for item in data['decision_document']['decisions'] if item['review_state'] == 'CONFIRMED']
    assert len(confirmed) == len(rows) == 2
    assert all(item['target_field'] == 'target_interface' and item['evidence_source'] == 'ENGINEER'
               and item['evidence_type'] == 'MANUAL' for item in confirmed)


@pytest.mark.parametrize('invalid', ['collision', 'duplicate_key', 'unknown_key', 'wrong_field', 'empty', 'stale_source', 'stale_target'])
def test_invalid_batches_are_atomic(invalid):
    client, payload, rows, state = _review()
    original = deepcopy(payload['decision_document'])
    selections = [{'decision_key': item['key'], 'value': f'ethernet1/{index + 1}'} for index, item in enumerate(rows)]
    if invalid == 'collision':
        selections[1]['value'] = selections[0]['value']
    elif invalid == 'duplicate_key':
        selections.append(selections[0])
    elif invalid == 'unknown_key':
        selections[0]['decision_key'] = 'unknown'
    elif invalid == 'wrong_field':
        selections[0]['decision_key'] = next(item['key'] for item in original['decisions'] if item['target_field'] == 'vsys')
    elif invalid == 'empty':
        selections[0]['value'] = ' '
    elif invalid == 'stale_source':
        payload['decision_document']['source_digest'] = 'stale'
    elif invalid == 'stale_target':
        payload['reviewed_target_evidence'] = {'device': 'stale', 'config_digest': 'stale'}
    response = client.post('/api/migration/interfaces/confirm', json={**payload, 'selections': selections})
    assert response.status_code == 400
    if invalid == 'collision':
        errors = response.get_json()['errors']
        assert {item['decision_key'] for item in errors} == {row['key'] for row in rows}
        assert all(len(item['evidence']) == 2 for item in errors)
    refreshed = client.post('/api/migration/requirements', json={'preview_id': payload['preview_id'], 'decision_document': original}).get_json()
    assert refreshed['decisions'] == state['decisions']


def test_existing_reservation_rejected_and_target_selection_bound_to_evidence():
    client, payload, rows, state = _review(target=True)
    row = next(item for item in rows if item['source_name'] == 'lan')
    candidates = state['decision_candidates'][row['key']]
    candidate = next(item for item in candidates if item['value'] == 'ethernet1/1')
    response = client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [{'decision_key': row['key'], 'value': candidate['value']}]})
    assert response.status_code == 200, response.get_json()
    doc = response.get_json()['decision_document']
    selected = next(item for item in doc['decisions'] if item['key'] == row['key'])
    assert selected['evidence_target_digest'] == state['target_evidence']['config_digest']
    assert selected['evidence_target_device'] == state['target_device']
    other = next(item for item in rows if item['key'] != row['key'])
    response = client.post('/api/migration/interfaces/confirm', json={**payload, 'decision_document': doc,
        'selections': [{'decision_key': other['key'], 'value': candidate['value']}]})
    assert response.status_code == 400


def test_stale_target_digest_rejects_target_backed_confirmation():
    client, payload, rows, _ = _review(target=True)
    payload['reviewed_target_evidence']['config_digest'] = 'stale'
    response = client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [{'decision_key': rows[0]['key'], 'value': 'ethernet1/1'}]})
    assert response.status_code == 400


def test_complete_replacement_set_allows_explicit_interface_swap():
    client, payload, rows, _ = _review(target=True)
    doc = payload['decision_document']
    for index, row in enumerate(rows):
        row.update(value=f'ethernet1/{index + 1}', review_state='CONFIRMED')
        next(item for item in doc['decisions'] if item['key'] == row['key']).update(row)
    response = client.post('/api/migration/interfaces/confirm', json={**payload,
        'selections': [{'decision_key': row['key'], 'value': f'ethernet1/{2 - index}'} for index, row in enumerate(rows)]})
    assert response.status_code == 200, response.get_json()
