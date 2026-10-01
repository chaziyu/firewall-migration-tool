import base64

import pytest

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
