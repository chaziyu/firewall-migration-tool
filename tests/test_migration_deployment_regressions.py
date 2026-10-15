"""Exercise signed source review through the mode-aware SSH boundary."""
import io
import zipfile

import pytest

from fwmigrate.web import create_app
from fwmigrate.web_support.artifact_signing import sign_envelope
from tests.approved_design import TARGET, approved_payload
from tests.conversion.fortigate_to_palo_alto.test_policy_logging import MAPPING, SOURCE
from tests.deployment.test_palo_alto_ssh import GuardedConnection, fake_netmiko


def evidence(text, vendor):
    return {'vendor': vendor, 'source_text': text}


def test_source_review_artifact_and_mocked_deployment_cover_modes_baseline_logging_and_coverage(monkeypatch):
    client = create_app({'TESTING': True, 'WEB_MODE': 'local'}).test_client()
    target = TARGET.decode().replace('<entry name="vsys1"/>', '<entry name="vsys1"/><entry name="vsys2"/>')
    source = 'config vdom\nedit root\n' + SOURCE.format(logging='set logtraffic all') + '''
next
edit blue
config firewall address
 edit net
  set subnet 203.0.113.0 255.255.255.0
 next
end
next
end
'''
    mapping = {**MAPPING, 'vdoms': {**MAPPING['vdoms'], 'blue': {'vsys': 'vsys2'}}}
    payload = {'source': evidence(source, 'fortigate'), 'target_source': evidence(target, 'palo_alto'),
               'mapping': mapping}
    approved = approved_payload(client, payload)
    response = client.post('/api/migrate', json=approved)
    assert response.status_code == 200, response.get_json()
    result = response.get_json()
    assert result['plan_status'] == 'READY', result
    artifact = result['artifact']
    command_payload = {'source': payload['source'], 'artifact': artifact}
    download = client.post('/api/migration/download', json=command_payload).data.decode()
    preview = client.post('/api/migration/command-preview', json=command_payload).get_json()
    commands = download.splitlines()
    assert 'set vsys vsys1 rulebase security rules traffic log-end yes' in commands
    assert 'set vsys vsys2 address net ip-netmask 203.0.113.0/24' in commands
    assert not any(command.startswith('set system ') for command in commands)
    assert preview['command_text'] == download
    assert preview['command_sha256'] == result['report']['command_sha256']
    for row in result['report']['items']:
        assert set(row['commands']) <= set(commands)
        positions = [commands.index(command) for command in row['commands']]
        assert positions == sorted(positions)
    bundle = client.post('/api/migration/bundle', json=command_payload)
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        name = next(name for name in archive.namelist() if name.endswith('.set'))
        assert archive.read(name).decode() == download

    class RecordingConnection(GuardedConnection):
        def __init__(self):
            super().__init__(['ok'] * len(commands), ['Job 42', 'FIN: OK'])
            self.candidate = target
            self.sent = []

        def send_config_set(self, batch, **kwargs):
            self.sent.extend(batch)
            return super().send_config_set(batch, **kwargs)

    connection = RecordingConnection()
    fake_netmiko(monkeypatch, lambda **kwargs: connection)
    credentials = {'host': 'fw', 'username': 'admin', 'password': 'secret'}
    deployed = client.post('/api/deploy', json={**credentials, 'artifact': artifact})
    assert deployed.status_code == 200, deployed.get_json()
    assert connection.sent == commands
    assert connection.commits == 0
    assert deployed.get_json()['candidate_validated']

    connection = RecordingConnection()
    connection.candidate = target.replace('<entry name="vsys2"/>',
        '<entry name="vsys2"><address><entry name="net"><ip-netmask>10.0.0.1</ip-netmask></entry></address></entry>')
    stale = client.post('/api/deploy', json={**credentials, 'artifact': artifact})
    assert stale.status_code == 502
    assert connection.sent == []
    assert 'Destination changed since review' in stale.get_json()['error']

    unsupported = source.replace('edit blue\n', '''edit blue
config firewall vipgrp
 edit unsupported-vips
  set member missing-vip
 next
end
''')
    partial_payload = {**payload, 'source': evidence(unsupported, 'fortigate')}
    draft = client.post('/api/migration/design/prepare', json=partial_payload).get_json()['draft']
    gap = next(row for row in draft['configuration'] if row['source_kind'] == 'vip_group')
    assert gap['status'] == 'UNSUPPORTED' and gap['source_name'] == 'unsupported-vips'
    partial = client.post('/api/migrate', json=approved_payload(client, partial_payload)).get_json()
    assert partial['plan_status'] == 'PARTIAL'
    assert client.post('/api/deploy', json={**credentials, 'artifact': partial['artifact']}).status_code == 400
    assert connection.sent == []


def test_old_signed_approval_without_baseline_cannot_deploy(monkeypatch):
    from tests.test_web_candidate_sessions import _ready_artifact
    key = b'baseline-regression-test-key-000000'
    client = create_app({'TESTING': True, 'WEB_MODE': 'local', 'WORKSPACE_SIGNING_KEY': key}).test_client()
    artifact = _ready_artifact(client)
    approval = artifact['decision_document']['design_approval']
    approval['context'].pop('baseline_sha256')
    approval['context'].pop('baseline_format')
    for field in ('baseline_sha256', 'baseline_format'):
        artifact['report']['target_evidence'].pop(field)
    artifact['decision_document']['design_approval'] = sign_envelope(approval, key)
    artifact = sign_envelope(artifact, key)
    fake_netmiko(monkeypatch, lambda **kwargs: pytest.fail('Old approval must not connect'))
    response = client.post('/api/deploy', json={'host': 'fw', 'username': 'admin', 'password': 'secret', 'artifact': artifact})
    assert response.status_code == 400
    assert 'baseline evidence is required' in response.get_json()['error']
