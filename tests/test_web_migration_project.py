from copy import deepcopy
import pytest
from tests.test_web_migration_design import setup, allocate, prepare, SOURCE


def project_payload(client, payload):
    data, payload = allocate(client, payload)
    return {key: payload[key] for key in ('source', 'target_source', 'reference_role')} | {
        'target_device': data['target_device'], 'workflow_mode': 'offline',
        'proposals': data['draft']['context']['overrides'], 'service_names': {}}


def test_project_roundtrip_reparses_and_restores_proposals_without_authority():
    client, payload = setup()
    payload = project_payload(client, payload)
    project = client.post('/api/migration/project/export', json=payload).get_json()['project']
    fresh, _ = setup()
    result = fresh.post('/api/migration/project/import', json=project)
    assert result.status_code == 200, result.get_json()
    data = result.get_json()
    assert data['preview']['source_evidence'] == project['source']
    assert data['review']['draft']['context']['overrides'] == payload['proposals']
    assert 'design_approval' not in data['review']['decision_document']
    assert all(row['review_state'] != 'CONFIRMED' for row in data['review']['decision_document']['decisions'])
    assert fresh.post('/api/migrate', json={'source': project['source'],
        'decision_document': data['review']['decision_document']}).status_code == 400


@pytest.mark.parametrize('change', ['version', 'pair', 'approval', 'candidate', 'credentials', 'proposal', 'role', 'evidence'])
def test_invalid_project_never_restores_execution_authority(change):
    client, payload = setup()
    project = client.post('/api/migration/project/export', json=project_payload(client, payload)).get_json()['project']
    if change == 'version': project['version'] = 999
    elif change == 'pair': project['pair'] = 'another_pair'
    elif change == 'approval': project['design_approval'] = {'signature': 'forged'}
    elif change == 'candidate': project['deployment_session_id'] = 'forged'
    elif change == 'credentials': project['password'] = 'secret'
    elif change == 'proposal': project['proposals'] = {'key': {'value': 'x'}}
    elif change == 'role': project['reference_role'] = 'guessed'
    else: project['source']['source_text'] = []
    response = client.post('/api/migration/project/import', json=project)
    assert response.status_code == 400 and 'unchanged' in response.get_json()['error']


def test_project_sanitizes_both_evidence_and_reports_unmatched_scope_keys():
    client, payload = setup()
    payload = project_payload(client, payload)
    payload['source']['source_text'] += '\nconfig system admin\n edit admin\n set password ENC seeded-secret\n next\nend\n'
    payload['target_source']['source_text'] = payload['target_source']['source_text'].replace('<network>', '<password>target-secret</password><network>')
    payload['proposals']['["other", "interface", "port1", "target_interface"]'] = 'ethernet1/8'
    response = client.post('/api/migration/project/export', json=payload)
    assert response.status_code == 200, response.get_json()
    assert b'seeded-secret' not in response.data and b'target-secret' not in response.data
    result = client.post('/api/migration/project/import', json=response.get_json()['project'])
    assert result.status_code == 200
    assert response.get_json()['unmatched_entries'] == ['["other", "interface", "port1", "target_interface"]']


def test_project_size_limit_and_service_rename_roundtrip(monkeypatch):
    import fwmigrate.web_api.migration as routes
    client, payload = setup()
    payload['source']['source_text'] = SOURCE + '\nconfig firewall service custom\n edit web\n set tcp-portrange 8443\n next\nend\n'
    payload = project_payload(client, payload)
    payload['service_names'] = {'root': {'web': 'migrated-web', 'unknown': 'ignored'}}
    response = client.post('/api/migration/project/export', json=payload)
    assert response.status_code == 200, response.get_json()
    project = response.get_json()['project']
    restored = client.post('/api/migration/project/import', json=project).get_json()
    assert restored['review']['draft']['context']['service_names'] == {'root': {'web': 'migrated-web'}}
    assert 'service:root/unknown' in response.get_json()['unmatched_entries']
    monkeypatch.setattr(routes, 'PROJECT_MAX_BYTES', 128)
    assert client.post('/api/migration/project/import', json=project).status_code == 400


def test_changed_source_identity_restores_no_stale_proposals():
    client, payload = setup()
    project = client.post('/api/migration/project/export', json=project_payload(client, payload)).get_json()['project']
    project['source']['source_text'] = project['source']['source_text'].replace('192.0.2.1 ', '192.0.2.8 ')
    result = client.post('/api/migration/project/import', json=project).get_json()
    assert result['project']['proposals'] == {}
    assert result['unmatched_entries'] == list(project['proposals'])
