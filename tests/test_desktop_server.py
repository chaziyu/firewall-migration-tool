from fwmigrate.desktop_server import DESKTOP_TOKEN_HEADER, create_desktop_app
from fwmigrate.web import create_app


def test_desktop_api_requires_per_launch_token():
    client = create_desktop_app("desktop-secret", {"TESTING": True}).test_client()

    assert client.get("/api/vendors").status_code == 401
    assert client.get("/api/vendors", headers={DESKTOP_TOKEN_HEADER: "wrong"}).status_code == 401

    response = client.get("/api/vendors", headers={DESKTOP_TOKEN_HEADER: "desktop-secret"})
    assert response.status_code == 200
    assert "sources" in response.get_json()


def test_desktop_preflight_is_limited_to_known_tauri_origins():
    client = create_desktop_app("desktop-secret", {"TESTING": True}).test_client()

    allowed = client.options(
        "/api/vendors",
        headers={
            "Origin": "http://tauri.localhost",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": DESKTOP_TOKEN_HEADER,
        },
    )
    assert allowed.status_code == 204
    assert allowed.headers["Access-Control-Allow-Origin"] == "http://tauri.localhost"
    assert DESKTOP_TOKEN_HEADER in allowed.headers["Access-Control-Allow-Headers"]

    denied = client.options(
        "/api/vendors",
        headers={"Origin": "https://example.invalid"},
    )
    assert "Access-Control-Allow-Origin" not in denied.headers


def test_standard_web_app_remains_unprotected_for_render_path():
    client = create_app({"TESTING": True}).test_client()
    assert client.get("/api/vendors").status_code == 200
