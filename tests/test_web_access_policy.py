"""Public file processing and loopback-only device access are separate policies."""
import io

import pytest
from click.testing import CliRunner

from fwmigrate.collection import source_collectors
from fwmigrate.main import cli
from fwmigrate.web import create_app


DEVICE_ROUTES = (
    '/api/collection/test', '/api/collection/collect', '/api/deploy',
    '/api/inspect-candidate', '/api/validate-candidate', '/api/commit',
)


@pytest.mark.parametrize('setting', ['TRUSTED_PROXY_FOR', 'TRUSTED_PROXY_PROTO'])
def test_local_mode_cannot_trust_proxy_headers(setting):
    with pytest.raises(ValueError, match='Proxy trust'):
        create_app({'TESTING': True, 'WEB_MODE': 'local', setting: 1})


@pytest.mark.parametrize('route', DEVICE_ROUTES)
def test_public_proxy_cannot_enable_device_access(route):
    client = create_app({'TESTING': True, 'TRUSTED_PROXY_FOR': 1,
                         'TRUSTED_PROXY_PROTO': 1}).test_client()
    response = client.post(route, json={}, headers={
        'X-Forwarded-For': '127.0.0.1', 'X-Forwarded-Proto': 'https',
    })
    assert response.status_code == 403


def test_forwarded_host_port_and_prefix_are_not_trusted():
    client = create_app({'TESTING': True, 'TRUSTED_PROXY_FOR': 1,
                         'TRUSTED_PROXY_PROTO': 1}).test_client()
    headers = {'X-Forwarded-Host': 'localhost', 'X-Forwarded-Port': '5000',
               'X-Forwarded-Prefix': '/trusted', 'X-Forwarded-Proto': 'https'}
    assert client.get('/api/vendors', base_url='http://attacker.example', headers=headers).status_code == 400
    headers['Origin'] = 'https://attacker.example'
    assert client.post('/api/preview', headers=headers).status_code == 403


def test_public_hostname_requires_explicit_configuration(monkeypatch):
    monkeypatch.delenv('FWMIGRATE_ALLOWED_HOSTS', raising=False)
    monkeypatch.delenv('RENDER_EXTERNAL_HOSTNAME', raising=False)
    host = 'https://firewall-migration-tool.onrender.com'
    assert create_app({'TESTING': True}).test_client().get('/api/vendors', base_url=host).status_code == 400
    monkeypatch.setenv('RENDER_EXTERNAL_HOSTNAME', 'firewall-migration-tool.onrender.com')
    assert create_app({'TESTING': True}).test_client().get('/api/vendors', base_url=host).status_code == 200


@pytest.mark.parametrize('remote_addr', ['127.0.0.1', '::1', '198.51.100.20'])
@pytest.mark.parametrize('route', DEVICE_ROUTES)
def test_public_mode_blocks_device_routes_before_reading_payload(route, remote_addr, monkeypatch):
    client = create_app({
        'TESTING': True, 'ALLOW_REMOTE_COLLECTION': True, 'ALLOW_REMOTE_DEPLOYMENT': True,
    }).test_client()

    def unexpected(*args, **kwargs):
        pytest.fail('Public requests must never reach a device transport')

    monkeypatch.setattr(source_collectors.get('cisco_asa'), 'test_connection', unexpected)
    monkeypatch.setattr(source_collectors.get('cisco_asa'), 'collect', unexpected)
    monkeypatch.setattr('fwmigrate.web.PANSSHDeployer', unexpected)
    response = client.post(route, data='not-json', content_type='application/json',
                           headers={'X-Forwarded-For': '198.51.100.20'},
                           environ_overrides={'REMOTE_ADDR': remote_addr})
    assert response.status_code == 403
    assert client.get('/api/capabilities').json == {'live_device_access': False}
    assert all(not vendor['live_collection'] for vendor in client.get('/api/vendors').json['sources'])


@pytest.mark.parametrize('host', ['localhost', '127.0.0.1', '[::1]'])
def test_local_loopback_device_access_needs_no_login(host, monkeypatch):
    client = create_app({'TESTING': True, 'WEB_MODE': 'local'}).test_client()
    calls = []
    monkeypatch.setattr(source_collectors.get('cisco_asa'), 'test_connection', calls.append)
    response = client.post('/api/collection/test', base_url=f'http://{host}:5000', json={
        'vendor': 'cisco_asa',
        'connection': {'host': '192.0.2.1', 'username': 'synthetic', 'password': 'synthetic'},
    })
    assert response.status_code == 200
    assert len(calls) == 1
    assert client.get('/api/capabilities', base_url=f'http://{host}:5000').json['live_device_access']


@pytest.mark.parametrize('route', DEVICE_ROUTES)
def test_local_mode_rejects_remote_clients_and_proxy_public_hosts(route):
    client = create_app({'TESTING': True, 'WEB_MODE': 'local',
                         'ALLOWED_HOSTS': ['localhost', 'firewall-migration-tool.onrender.com']}).test_client()
    assert client.post(route, json={}, environ_overrides={'REMOTE_ADDR': '198.51.100.20'}).status_code == 403
    assert client.post(route, json={}, base_url='https://firewall-migration-tool.onrender.com').status_code == 403


@pytest.mark.parametrize('mode', ['public', 'local'])
def test_untrusted_host_is_rejected_even_without_origin(mode):
    client = create_app({'TESTING': True, 'WEB_MODE': mode}).test_client()
    assert client.get('/api/vendors', base_url='http://attacker.example:5000').status_code == 400
    assert client.post('/api/preview', base_url='http://attacker.example:5000').status_code == 400


@pytest.mark.parametrize('headers', [
    {'Origin': 'http://attacker.example'}, {'Origin': 'null'},
    {'Origin': 'http://localhost:5000.attacker.example'},
    {'Sec-Fetch-Site': 'cross-site'},
])
def test_cross_origin_writes_fail_before_source_processing(headers, monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail('Cross-origin requests must never reach source processing')

    monkeypatch.setattr('fwmigrate.web_api.source.analyze_request_source', unexpected)
    client = create_app({'TESTING': True, 'WEB_MODE': 'local'}).test_client()
    response = client.post('/api/preview', headers=headers,
                           data={'file': (io.BytesIO(b'synthetic'), 'synthetic.conf')})
    assert response.status_code == 403
    assert response.headers['Cache-Control'] == 'no-store, private'


@pytest.mark.parametrize('mode,origin,status', [
    ('public', 'http://localhost', 400),
    ('public', 'http://127.0.0.1:5173', 403),
    ('local', 'http://127.0.0.1:5173', 400),
    ('local', 'http://localhost:5173', 400),
])
def test_same_origin_and_local_vite_requests(mode, origin, status):
    client = create_app({'TESTING': True, 'WEB_MODE': mode}).test_client()
    # Missing source returns 400 only after the browser request guard accepts it.
    assert client.post('/api/preview', headers={'Origin': origin}).status_code == status


def test_public_https_origin_and_custom_hostname(monkeypatch):
    monkeypatch.setenv('FWMIGRATE_ALLOWED_HOSTS', 'reports.example.com')
    client = create_app({'TESTING': True}).test_client()
    assert client.get('/api/vendors', base_url='https://reports.example.com').status_code == 200
    assert client.post('/api/preview', base_url='https://reports.example.com',
                       headers={'Origin': 'https://reports.example.com'}).status_code == 400
    assert client.post('/api/preview', base_url='https://reports.example.com',
                       headers={'Origin': 'http://reports.example.com'}).status_code == 403


def test_public_mode_still_processes_uploads_and_downloads_without_login():
    client = create_app({'TESTING': True}).test_client()
    source = b'config firewall address\n edit host-a\n set subnet 192.0.2.1 255.255.255.255\n next\nend\n'
    preview = client.post('/api/preview', data={'file': (io.BytesIO(source), 'sample.conf')})
    assert preview.status_code == 200
    workbook = client.post('/api/extract/excel', json={
        'source_vendor': 'fortigate', 'source': preview.json['source_evidence'],
    })
    assert workbook.status_code == 200
    assert workbook.data.startswith(b'PK')
    assert workbook.headers['Cache-Control'] == 'no-store, private'


@pytest.mark.parametrize('host,mode', [('127.0.0.1', 'local'), ('::1', 'local'),
                                      ('localhost', 'local'), ('0.0.0.0', 'public')])
def test_serve_selects_mode_from_bind_address(host, mode, monkeypatch):
    calls = []

    class App:
        def run(self, **kwargs):
            calls.append(kwargs)

    def factory(config):
        assert config == {'WEB_MODE': mode}
        return App()

    monkeypatch.setattr('fwmigrate.web.create_app', factory)
    result = CliRunner().invoke(cli, ['serve', '--host', host])
    assert result.exit_code == 0, result.output
    assert calls == [{'host': host, 'port': 5000, 'debug': False}]


def test_invalid_web_mode_fails_closed():
    with pytest.raises(ValueError, match='WEB_MODE'):
        create_app({'TESTING': True, 'WEB_MODE': 'typo'})
