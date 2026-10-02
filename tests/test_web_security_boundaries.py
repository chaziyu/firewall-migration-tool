import base64
import io

import pytest
from flask import request

from fwmigrate.web import create_app


def _basic(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_hosted_web_auth_protects_application_but_not_health_check():
    client = create_app({
        "TESTING": True,
        "REQUIRE_WEB_AUTH": True,
        "WEB_AUTH_USERNAME": "engineer",
        "WEB_AUTH_PASSWORD": "strong-test-password",
    }).test_client()

    health = client.get("/healthz")
    assert health.status_code == 200

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


def test_remote_deployment_is_disabled_by_default():
    client = create_app({"TESTING": True}).test_client()

    response = client.post(
        "/api/deploy",
        json={},
        environ_overrides={"REMOTE_ADDR": "198.51.100.20"},
    )

    assert response.status_code == 403
    assert response.get_json()["error"] == "Remote deployment is disabled on this server."


def test_remote_deployment_requires_web_authentication():
    with pytest.raises(RuntimeError, match="Remote deployment requires configured web authentication"):
        create_app({"TESTING": True, "ALLOW_REMOTE_DEPLOYMENT": True})
