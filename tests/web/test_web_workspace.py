import io
from copy import deepcopy

import pytest
from fwmigrate import web
from fwmigrate.web_support.artifact_signing import sign_envelope
from tests.approved_design import approved_migrate

KEY = 'workspace-test-key-with-at-least-32-bytes'
MINIMAL_FORTIGATE = (
    b'config system interface\n'
    b' edit port1\n set ip 192.0.2.1 255.255.255.0\n set allowaccess ping\n next\n'
    b'end\n'
    b'config firewall address\n'
    b' edit host-a\n set subnet 192.0.2.10 255.255.255.255\n next\n'
    b'end\n'
)


def _ready_artifact(client):
    preview = client.post('/api/preview', data={'file': (io.BytesIO(MINIMAL_FORTIGATE), 'fg.conf')}).get_json()
    migrated = approved_migrate(client, json={'source': preview['source_evidence']}).get_json()
    return migrated['artifact']


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
def test_artifact_tampering_is_rejected_before_download(field):
    client = web.create_app({
        'TESTING': True,
        'WORKSPACE_SIGNING_KEY': KEY,
    }).test_client()
    artifact = deepcopy(_ready_artifact(client))
    artifact[field] = ['set malicious command'] if field == 'commands' else 'changed'
    assert client.post('/api/migration/download', json={'artifact': artifact}).status_code == 400


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


def test_fortigate_workspace_evidence_redacts_multiline_secrets():
    client = web.create_app({'TESTING': True}).test_client()
    source = b'config system admin\n edit admin\n SET password ENC secret-one\n ApPeNd authpasswd "secret-two"\n Set private-key "secret-three\nsecret-four"\n next\nend\n'
    response = client.post('/api/preview', data={'file': (io.BytesIO(source), 'secret.conf')})
    assert response.status_code == 200
    for secret in (b'secret-one', b'secret-two', b'secret-three', b'secret-four'):
        assert secret not in response.data
    assert '[REDACTED]' in response.get_json()['source_evidence']['source_text']


def test_fortigate_sanitizer_preserves_object_names_and_unset():
    from fwmigrate.vendors.fortigate.collection_source import FortiGateCollectedSourceSanitizer
    source = 'config firewall address\n edit password\n unset password\n next\nend\n'
    assert FortiGateCollectedSourceSanitizer().sanitize(source) == source


def test_fortigate_sanitizer_preserves_case_and_redacts_secret_operations():
    from fwmigrate.vendors.fortigate.collection_source import FortiGateCollectedSourceSanitizer
    source = ('config system admin\n edit password\n SET password ENC uppercase-secret\n'
              ' ApPeNd private-key "first-secret\nsecond-secret"\n unset password\n'
              ' Set comments "visible"\n next\nend\n')
    sanitized = FortiGateCollectedSourceSanitizer().sanitize(source)
    assert ' SET password "[REDACTED]"' in sanitized
    assert ' ApPeNd private-key "[REDACTED]"' in sanitized
    assert 'unset password' in sanitized
    assert 'Set comments "visible"' in sanitized
    assert 'edit password' in sanitized
    for secret in ('uppercase-secret', 'first-secret', 'second-secret'):
        assert secret not in sanitized
