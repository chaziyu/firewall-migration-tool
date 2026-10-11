import io
from copy import deepcopy
from dataclasses import fields
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from fwmigrate import web
from fwmigrate.deployment import PANDeploymentSession
from fwmigrate.web_support.artifact_signing import sign_envelope
from tests.test_web_candidate_sessions import _ready_artifact, _SuccessfulDeployer, CREDS, MINIMAL_FORTIGATE

KEY = 'workspace-test-key-with-at-least-32-bytes'


def test_signed_artifact_survives_restart_and_id_only_requests_fail_closed():
    first = web.create_app({'TESTING': True, 'WORKSPACE_SIGNING_KEY': KEY}).test_client()
    artifact = _ready_artifact(first)
    second = web.create_app({'TESTING': True, 'WORKSPACE_SIGNING_KEY': KEY}).test_client()
    downloaded = second.post('/api/migration/download', json={'artifact': artifact})
    assert downloaded.status_code == 200
    assert downloaded.data.decode() == '\n'.join(artifact['commands'])
    assert second.post('/api/migration/download', json={'artifact_id': artifact['artifact_id']}).status_code == 400
    assert second.post('/api/migrate', json={'preview_id': 'someone-elses-preview'}).status_code == 400


@pytest.mark.parametrize('field', ['commands', 'command_count', 'command_sha256', 'report', 'decision_document', 'mapping', 'artifact_id'])
def test_artifact_tampering_is_rejected_before_deployment(monkeypatch, field):
    client = web.create_app({'TESTING': True, 'WORKSPACE_SIGNING_KEY': KEY}).test_client()
    artifact = deepcopy(_ready_artifact(client))
    artifact[field] = ['set malicious command'] if field == 'commands' else 'changed'
    monkeypatch.setattr(web, 'PANSSHDeployer', lambda *_: pytest.fail('Tampered artifact reached deployment'))
    assert client.post('/api/deploy', json={**CREDS, 'artifact': artifact}).status_code == 400


@pytest.mark.parametrize('field,value', [('command_count', 999), ('command_sha256', 'wrong')])
def test_signed_count_or_hash_mismatch_is_rejected(field, value):
    client = web.create_app({'TESTING': True, 'WORKSPACE_SIGNING_KEY': KEY}).test_client()
    artifact = deepcopy(_ready_artifact(client))
    artifact[field] = value
    artifact = sign_envelope(artifact, KEY.encode())
    response = client.post('/api/migration/download', json={'artifact': artifact})
    assert response.status_code == 400
    assert 'count or SHA-256' in response.get_json()['error']


def test_bundle_cannot_mix_another_engineers_source():
    client = web.create_app({'TESTING': True}).test_client()
    artifact = _ready_artifact(client)
    source = client.post('/api/preview', data={'file': (io.BytesIO(MINIMAL_FORTIGATE.replace(b'host-a', b'other-engineer')), 'other.conf')}).get_json()['source_evidence']
    response = client.post('/api/migration/bundle', json={'artifact': artifact, 'source': source})
    assert response.status_code == 400
    assert 'does not match' in response.get_json()['error']


def test_different_targets_can_deploy_concurrently(monkeypatch):
    app = web.create_app({'TESTING': True})
    artifact = _ready_artifact(app.test_client())
    blocked, release, other = Event(), Event(), Event()
    class Deployer(_SuccessfulDeployer):
        def deploy(self, rendered):
            if self.options.host == CREDS['host']:
                blocked.set()
                assert release.wait(5)
            else:
                other.set()
            return super().deploy(rendered)
    monkeypatch.setattr(web, 'PANSSHDeployer', Deployer)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(lambda: app.test_client().post('/api/deploy', json={**CREDS, 'artifact': artifact}))
        assert blocked.wait(5)
        second = pool.submit(lambda: app.test_client().post('/api/deploy', json={**CREDS, 'host': '192.0.2.51', 'artifact': artifact}))
        try:
            assert other.wait(2), 'An unrelated target was blocked by the first deployment'
            assert second.result(timeout=2).status_code == 200
        finally:
            release.set()
        assert first.result(timeout=5).status_code == 200
    assert {item.name for item in fields(PANDeploymentSession)} == {
        'session_id', 'artifact_id', 'command_count', 'command_sha256', 'host', 'port', 'validation_job_id', 'validated_at', 'device_serial', 'candidate_sha256'}


def test_fortigate_workspace_evidence_redacts_multiline_secrets():
    client = web.create_app({'TESTING': True}).test_client()
    source = b'config system admin\n edit admin\n set password ENC secret-one\n set authpasswd "secret-two"\n set private-key "secret-three\nsecret-four"\n next\nend\n'
    response = client.post('/api/preview', data={'file': (io.BytesIO(source), 'secret.conf')})
    assert response.status_code == 200
    for secret in (b'secret-one', b'secret-two', b'secret-three', b'secret-four'):
        assert secret not in response.data
    assert '[REDACTED]' in response.get_json()['source_evidence']['source_text']


def test_fortigate_sanitizer_preserves_object_names_and_unset():
    from fwmigrate.vendors.fortigate.collection_source import FortiGateCollectedSourceSanitizer
    source = 'config firewall address\n edit password\n unset password\n next\nend\n'
    assert FortiGateCollectedSourceSanitizer().sanitize(source) == source
