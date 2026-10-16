import base64
import io

import pytest
from flask import request

from fwmigrate.web import create_app


def _basic(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_hosted_web_auth_protects_application():
    client = create_app({
        "TESTING": True,
        "REQUIRE_WEB_AUTH": True,
        "WEB_AUTH_USERNAME": "engineer",
        "WEB_AUTH_PASSWORD": "strong-test-password",
    }).test_client()

    unauthenticated = client.get("/api/vendors")
    assert unauthenticated.status_code == 401
    assert "Basic" in unauthenticated.headers["WWW-Authenticate"]

    authenticated = client.get(
        "/api/vendors",
        headers=_basic("engineer", "strong-test-password"),
    )
    assert authenticated.status_code == 200


def test_required_hosted_web_auth_fails_closed_without_password():
    with pytest.raises(RuntimeError, match="FWMIGRATE_WEB_PASSWORD"):
        create_app({"TESTING": True, "REQUIRE_WEB_AUTH": True})


def test_global_request_size_limit_is_enforced():
    client = create_app({
        "TESTING": True,
        "WEB_MODE": "local",
        "MAX_CONTENT_LENGTH": 64,
    }).test_client()

    response = client.post(
        "/api/collection/test",
        data=b"x" * 65,
        content_type="application/json",
    )
    assert response.status_code == 413


def test_customer_uploads_use_memory_only_streams():
    app = create_app({"TESTING": True})
    with app.test_request_context(
        "/api/preview",
        method="POST",
        data={"file": (io.BytesIO(b"x" * 600_000), "customer.conf")},
    ):
        uploaded = request.files["file"]
        assert isinstance(uploaded.stream, io.BytesIO)


def test_api_responses_disable_storage_and_add_browser_security_headers():
    client = create_app({"TESTING": True}).test_client()

    response = client.get("/api/vendors")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store, private"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


@pytest.mark.parametrize('scheme,trust,forwarded,secure', [
    ('https', 0, None, True),
    ('http', 0, None, False),
    ('http', 0, 'https', False),
    ('http', 1, 'https', True),
    ('http', 1, 'https, http', False),
])
def test_hsts_uses_only_the_effective_trusted_scheme(scheme, trust, forwarded, secure):
    client = create_app({'TESTING': True, 'TRUSTED_PROXY_PROTO': trust}).test_client()
    headers = {'X-Forwarded-Proto': forwarded} if forwarded else {}
    response = client.get('/api/vendors', base_url=f'{scheme}://localhost', headers=headers)
    assert response.status_code == 200
    assert response.headers.get('Strict-Transport-Security') == ('max-age=31536000' if secure else None)
    if secure:
        response = client.post('/api/preview', base_url=f'{scheme}://localhost',
                               headers={**headers, 'Origin': 'https://localhost'})
        assert response.status_code == 400  # Accepted origin; missing source.
        assert client.post('/api/preview', base_url=f'{scheme}://localhost',
                           headers={**headers, 'Origin': 'http://localhost'}).status_code == 403


def test_remote_deployment_is_disabled_by_default():
    client = create_app({"TESTING": True}).test_client()

    response = client.post(
        "/api/deploy",
        json={},
        environ_overrides={"REMOTE_ADDR": "198.51.100.20"},
    )

    assert response.status_code == 403
    assert response.get_json()["error"] == "Remote deployment is disabled on this server."


def test_legacy_remote_deployment_flag_cannot_enable_device_access():
    client = create_app({"TESTING": True, "ALLOW_REMOTE_DEPLOYMENT": True}).test_client()
    assert client.post('/api/deploy', json={}).status_code == 403


@pytest.mark.parametrize('exception_type,status', [(ValueError, 400), (RuntimeError, 500)])
def test_global_failures_never_expose_exception_text(exception_type, status, caplog):
    app = create_app({'TESTING': True})

    @app.post('/api/synthetic-failure')
    def fail():
        raise exception_type('Approved design SYNTHETIC_SECRET_SENTINEL')

    response = app.test_client().post('/api/synthetic-failure', json={'password': 'SYNTHETIC_SECRET_SENTINEL'})
    assert response.status_code == status
    assert 'SYNTHETIC_SECRET_SENTINEL' not in response.get_data(as_text=True) + caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize('route', [
    '/api/migration/design/approve', '/api/migration/requirements',
    '/api/migration/interfaces/confirm', '/api/migration/decisions/approve',
    '/api/migration/automation/run', '/api/migration/target-intent/import',
    '/api/migration/target-intent/export', '/api/migration/rules/apply',
    '/api/migration/decisions/export', '/api/migrate',
])
def test_migration_source_failures_are_private(monkeypatch, caplog, route):
    import fwmigrate.web_api.migration as migration

    def fail(*args, **kwargs):
        raise ValueError('Approved design SYNTHETIC_MIGRATION_SECRET')

    monkeypatch.setattr(migration, 'analyze_request_source', fail)
    monkeypatch.setattr(migration, 'verify_envelope', fail)
    client = create_app({'TESTING': True}).test_client()
    response = client.post(route, json={'source': {'password': 'SYNTHETIC_MIGRATION_SECRET'}, 'decision_keys': ['key']})
    assert response.status_code in {400, 409}
    assert 'SYNTHETIC_MIGRATION_SECRET' not in response.get_data(as_text=True) + caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize('route', ['/api/collection/test', '/api/collection/collect'])
def test_collection_validation_does_not_log_credentials(monkeypatch, caplog, route):
    import fwmigrate.web_api.source as source

    def fail(*args, **kwargs):
        raise ValueError('SYNTHETIC_COLLECTION_SECRET')

    monkeypatch.setattr(source.source_collectors, 'get', fail)
    response = create_app({'TESTING': True, 'WEB_MODE': 'local'}).test_client().post(route, json={
        'vendor': 'fortigate', 'connection': {'password': 'SYNTHETIC_COLLECTION_SECRET'},
    })
    assert response.status_code == 400
    assert 'SYNTHETIC_COLLECTION_SECRET' not in response.get_data(as_text=True) + caplog.text
    assert all(record.exc_info is None for record in caplog.records)
