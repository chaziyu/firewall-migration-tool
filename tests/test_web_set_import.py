import io
from copy import deepcopy

import pytest

from fwmigrate.web import create_app
from fwmigrate.web_support.artifact_signing import sign_envelope
from tests.approved_design import TARGET
from tests.deployment.test_palo_alto_ssh import GuardedConnection, fake_netmiko
from tests.test_web_candidate_sessions import CREDS, _ready_artifact

KEY = b'upload-test-signing-key-000000000000'
COMMAND = 'set vsys vsys1 address uploaded ip-netmask 192.0.2.1/32'


@pytest.fixture
def client():
    return create_app({'TESTING': True, 'WEB_MODE': 'local', 'WORKSPACE_SIGNING_KEY': KEY}).test_client()


def review(client, commands=COMMAND, target=TARGET, **values):
    return client.post('/api/deployment/set/prepare-review', data={
        'file': (io.BytesIO(commands.encode()), 'upload.set'),
        'target_file': (io.BytesIO(target), 'destination.xml'),
        'host': CREDS['host'], 'port': str(CREDS['port']), **values,
    })


def approve(client, draft):
    result = client.post('/api/deployment/set/approve', json={'review': draft, 'command_sha256': draft['command_sha256']})
    assert result.status_code == 200, result.get_json()
    return result.get_json()['artifact']


@pytest.mark.parametrize(('message', 'expected'), [
    ('Line 2: Malformed quoting.', 'Line 2: Malformed quoting.'),
    ('SYNTHETIC_UPLOAD_SECRET', 'The uploaded command file is invalid.'),
])
def test_upload_errors_return_only_approved_public_messages(client, monkeypatch, message, expected):
    import fwmigrate.web_api.deployment as deployment_api
    from fwmigrate.deployment.panos_set_import import SetImportError

    monkeypatch.setattr(deployment_api, 'create_set_review', lambda *args: (_ for _ in ()).throw(SetImportError(message)))
    response = review(client)
    assert response.status_code == 400
    assert response.get_json()['error'] == expected
    assert 'SYNTHETIC_UPLOAD_SECRET' not in response.get_data(as_text=True)


def test_artifact_eligibility_errors_return_only_approved_public_messages(client, monkeypatch):
    import fwmigrate.web_api.deployment as deployment_api
    from fwmigrate.conversion.fortigate_to_palo_alto.application import ArtifactEligibilityError

    monkeypatch.setattr(deployment_api, 'approve_set_review',
                        lambda *args: (_ for _ in ()).throw(ArtifactEligibilityError('UNKNOWN_REASON_CODE')))
    response = client.post('/api/deployment/set/approve', json={'review': {}, 'command_sha256': 'digest'})
    assert response.status_code == 400
    assert response.get_json()['error'] == 'Artifact is not eligible; review approval and try again.'
    assert response.get_json()['error_code'] == 'artifact_ineligible'
    assert 'UNKNOWN_REASON_CODE' not in response.get_data(as_text=True)


def test_uploaded_renderer_output_requires_approval_and_reuses_candidate_lifecycle(client, monkeypatch):
    planned = _ready_artifact(client)
    commands = '\n'.join(planned['commands'])
    response = review(client, commands)
    assert response.status_code == 200, response.get_json()
    draft = response.get_json()['review']
    assert client.post('/api/deploy', json={**CREDS, 'artifact': draft}).status_code == 400
    artifact = approve(client, draft)
    assert artifact['commands'] == planned['commands']

    class RecordingConnection(GuardedConnection):
        def __init__(self):
            super().__init__(['ok'] * len(artifact['commands']), ['Job 42', 'FIN: OK'])
            self.candidate = TARGET.decode()
            self.sent = []

        def send_config_set(self, batch, **kwargs):
            self.sent.extend(batch)
            return super().send_config_set(batch, **kwargs)

    connection = RecordingConnection()
    fake_netmiko(monkeypatch, lambda **kwargs: connection)
    response = client.post('/api/deploy', json={**CREDS, 'artifact': artifact})
    assert response.status_code == 200, response.get_json()
    assert response.get_json()['candidate_validated'] is True
    assert connection.sent == artifact['commands']
    assert connection.commits == 0
    session = response.get_json()['deployment_session_id']
    payload = {**CREDS, 'artifact': artifact, 'deployment_session_id': session}
    connection.validation_responses = iter(['Job 43', 'FIN: OK'])
    assert client.post('/api/validate-candidate', json=payload).status_code == 200
    connection.validation_responses = iter(['FIN: OK'])
    assert client.post('/api/commit', json=payload).status_code == 200
    assert connection.commits == 1
    assert client.post('/api/commit', json=payload).status_code == 400


@pytest.mark.parametrize('field', ['commands', 'line_numbers', 'command_count', 'command_sha256', 'context', 'artifact_id'])
def test_upload_tampering_never_connects(client, monkeypatch, field):
    artifact = approve(client, review(client).get_json()['review'])
    artifact[field] = 'changed'
    fake_netmiko(monkeypatch, lambda **kwargs: pytest.fail('Tampered artifact connected'))
    assert client.post('/api/deploy', json={**CREDS, 'artifact': artifact}).status_code == 400


def test_upload_expiry_context_and_secret_errors(client, monkeypatch, caplog):
    draft = review(client).get_json()['review']
    altered = deepcopy(draft)
    altered['commands'] = ['commit']
    assert client.post('/api/deployment/set/approve', json={'review': altered, 'command_sha256': draft['command_sha256']}).status_code == 400
    expired = sign_envelope({**draft, 'expires_at': 0}, KEY)
    assert client.post('/api/deployment/set/approve', json={'review': expired, 'command_sha256': expired['command_sha256']}).status_code == 400
    artifact = approve(client, draft)
    fake_netmiko(monkeypatch, lambda **kwargs: pytest.fail('Wrong target connected'))
    for values in ({'host': 'other'}, {'port': 2222}):
        assert client.post('/api/deploy', json={**CREDS, **values, 'artifact': artifact}).status_code == 400
    result = review(client, 'set mgt-config users admin password SENTINEL_SECRET')
    assert result.status_code == 400
    assert 'SENTINEL_SECRET' not in result.get_data(as_text=True) + caplog.text
    assert review(client, target=TARGET.replace(b'012345678901', b'')).status_code == 400
    assert review(client, COMMAND.replace('vsys1', 'vsys999')).status_code == 400


@pytest.mark.parametrize('field,value', [('serial', 'other'), ('diff', '+ pending'), ('candidate', '<config><changed/></config>')])
def test_uploaded_target_preflight_blocks_all_writes(client, monkeypatch, field, value):
    artifact = approve(client, review(client).get_json()['review'])
    connection = GuardedConnection(['ok'], ['Job 42', 'FIN: OK'])
    connection.candidate = TARGET.decode()
    setattr(connection, field, value)
    fake_netmiko(monkeypatch, lambda **kwargs: connection)
    result = client.post('/api/deploy', json={**CREDS, 'artifact': artifact})
    assert result.status_code == 502
    assert result.get_json()['result']['commands_attempted'] == 0
    assert connection.commits == 0


def test_upload_public_mode_is_disabled():
    client = create_app({'TESTING': True, 'WEB_MODE': 'public'}).test_client()
    assert review(client).status_code == 403
    assert client.post('/api/deployment/set/approve', json={}).status_code == 403


def test_upload_requires_explicit_device_selection_for_multiple_devices(client):
    target = TARGET.replace(b'</devices>', b'<entry name="other" serial="999"><vsys><entry name="vsys1"/></vsys></entry></devices>')
    result = review(client, target=target)
    assert result.status_code == 200, result.get_json()
    assert result.get_json()['review'] is None
    assert len(result.get_json()['devices']) == 2
    assert review(client, target=target, target_device='unknown').status_code == 400
    assert review(client, target=target, target_device='012345678901').get_json()['review']['context']['target_serial'] == '012345678901'


@pytest.mark.parametrize('status', ['FAILED', 'TIMEOUT'])
def test_upload_validation_failure_never_enables_commit(client, monkeypatch, status):
    import fwmigrate.web as web
    from fwmigrate.deployment import PANDeploymentResult, PANValidationResult
    from tests.test_web_candidate_sessions import _SuccessfulDeployer

    artifact = approve(client, review(client).get_json()['review'])

    class Failed(_SuccessfulDeployer):
        def deploy(self, rendered):
            return PANDeploymentResult(True, 1, 1, validation=PANValidationResult('job', status, 'SENTINEL_SECRET'))

    monkeypatch.setattr(web, 'PANSSHDeployer', Failed)
    response = client.post('/api/deploy', json={**CREDS, 'artifact': artifact})
    assert response.status_code == 502
    assert not response.get_json()['deployment_session_id']
    assert 'SENTINEL_SECRET' not in response.get_data(as_text=True)
    assert client.post('/api/commit', json={**CREDS, 'artifact': artifact}).status_code == 400


def test_uploaded_partial_push_reports_original_line_and_requires_reconciliation(client, monkeypatch):
    artifact = approve(client, review(client, '\n' + COMMAND + '\n\n' + COMMAND).get_json()['review'])
    connection = GuardedConnection(['ok', 'Invalid command'], [])
    connection.candidate = TARGET.decode()
    fake_netmiko(monkeypatch, lambda **kwargs: connection)
    result = client.post('/api/deploy', json={**CREDS, 'artifact': artifact})
    assert result.status_code == 502
    assert result.get_json()['failed_line_number'] == 4
    assert result.get_json()['recovery']['state'] == 'PARTIAL_PUSH'
    assert not result.get_json()['deployment_session_id']
    connection.diff = '+ commands from previous attempt'
    retried = client.post('/api/deploy', json={**CREDS, 'artifact': artifact})
    assert retried.status_code == 502
    assert retried.get_json()['result']['commands_attempted'] == 0
    assert connection.commits == 0


@pytest.mark.parametrize('changed', ['expired', 'candidate', 'artifact', 'host'])
def test_upload_revalidation_and_commit_reject_stale_execution(client, monkeypatch, changed):
    import fwmigrate.web as web
    from tests.test_web_candidate_sessions import _SuccessfulDeployer

    artifact = approve(client, review(client).get_json()['review'])
    monkeypatch.setattr(web, 'PANSSHDeployer', _SuccessfulDeployer)
    prepared = client.post('/api/deploy', json={**CREDS, 'artifact': artifact}).get_json()
    payload = {**CREDS, 'artifact': artifact, 'deployment_session_id': prepared['deployment_session_id']}
    if changed == 'expired':
        payload['artifact'] = sign_envelope({**artifact, 'expires_at': 0}, KEY)
    elif changed == 'artifact':
        payload['artifact'] = approve(client, review(client).get_json()['review'])
    elif changed == 'host':
        payload['host'] = 'other'
    else:
        class Drifted(_SuccessfulDeployer):
            def validate(self):
                from fwmigrate.deployment import PANValidationResult
                return PANValidationResult('job', 'SUCCESS', 'ok', '012345678901', 'changed')
        monkeypatch.setattr(web, 'PANSSHDeployer', Drifted)
    assert client.post('/api/validate-candidate', json=payload).status_code in {400, 502}
    assert client.post('/api/commit', json=payload).status_code == 400
