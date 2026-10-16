"""HTTPS collector trust settings cannot be disabled by request data."""

import pytest

from fwmigrate.collection.checkpoint import CheckPointCollector
from fwmigrate.collection.cisco_ftd import CiscoFTDCollector
from fwmigrate.web import create_app


@pytest.mark.parametrize('collector_type', [CheckPointCollector, CiscoFTDCollector])
@pytest.mark.parametrize('verify', [False, None, 0, 1, 'false', 'true', [], {}])
def test_unverified_tls_is_rejected_before_transport(collector_type, verify):
    collector = collector_type()
    with pytest.raises(ValueError):
        collector.validate_options({'host': 'mgmt', 'username': 'u', 'password': 'p',
                                    'verify_tls': verify})


@pytest.mark.parametrize('collector_type', [CheckPointCollector, CiscoFTDCollector])
@pytest.mark.parametrize('extra', [{}, {'verify_tls': True}])
def test_verified_tls_remains_compatible(collector_type, extra):
    collector = collector_type()
    assert collector.validate_options({'host': 'mgmt', 'username': 'u', 'password': 'p',
                                       **extra})['verify_tls'] is True
    assert 'verify_tls' not in {field['name'] for field in collector.fields}


@pytest.mark.parametrize('vendor', ['checkpoint', 'cisco_ftd'])
def test_transport_verification_does_not_use_mutated_options(vendor):
    class Session:
        headers = {}

        def post(self, url, **kwargs):
            assert self.verify is True
            return self

        def raise_for_status(self):
            pass

        def json(self):
            return {'sid': 'synthetic'}

        def close(self):
            pass

    session = Session()
    session.headers = {'X-auth-access-token': 'synthetic',
                       'DOMAINS': '[{"uuid":"d1","name":"Global"}]'}
    collector = (CheckPointCollector(api_session_factory=lambda: session) if vendor == 'checkpoint'
                 else CiscoFTDCollector(session_factory=lambda: session))
    options = collector.validate_options({'host': 'mgmt', 'username': 'u', 'password': 'p'})
    options['verify_tls'] = False
    collector.test_connection(options)


@pytest.mark.parametrize('vendor', ['checkpoint', 'cisco_ftd'])
@pytest.mark.parametrize('route', ['/api/collection/test', '/api/collection/collect'])
def test_web_rejects_disabled_tls_without_credentials_in_response(vendor, route):
    client = create_app({'TESTING': True, 'WEB_MODE': 'local'}).test_client()
    response = client.post(route, json={'vendor': vendor, 'connection': {
        'host': 'mgmt', 'username': 'u', 'password': 'synthetic-secret', 'verify_tls': False,
    }})
    assert response.status_code == 400
    assert 'synthetic-secret' not in response.get_data(as_text=True)


@pytest.fixture
def local_management_https(tmp_path, monkeypatch):
    # cryptography is supplied by the collection extra; no new test dependency.
    pytest.importorskip('cryptography')
    import json
    import ssl
    from datetime import datetime, timedelta, timezone
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'ca.pem', tmp_path / 'key.pem'
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', '0')))
            body = json.dumps({'sid': 'synthetic'}).encode()
            self.send_response(200)
            self.send_header('X-auth-access-token', 'synthetic')
            self.send_header('DOMAINS', '[{"uuid":"d1","name":"Global"}]')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    monkeypatch.delenv('REQUESTS_CA_BUNDLE', raising=False)
    monkeypatch.delenv('CURL_CA_BUNDLE', raising=False)
    monkeypatch.setenv('NO_PROXY', 'localhost,127.0.0.1')
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, cert_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize('vendor', ['checkpoint', 'cisco_ftd'])
def test_private_ca_is_required_and_certificate_errors_are_private(vendor, local_management_https, monkeypatch):
    port, ca_path = local_management_https
    client = create_app({'TESTING': True, 'WEB_MODE': 'local'}).test_client()
    payload = {'vendor': vendor, 'connection': {
        'host': 'localhost', 'port': port, 'username': 'u', 'password': 'synthetic-secret',
    }}
    response = client.post('/api/collection/test', json=payload)
    assert response.status_code == 502
    assert 'synthetic-secret' not in response.get_data(as_text=True)
    assert 'CERTIFICATE_VERIFY_FAILED' not in response.get_data(as_text=True)
    monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(ca_path))
    assert client.post('/api/collection/test', json=payload).status_code == 200
