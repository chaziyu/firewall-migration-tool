from pathlib import Path

from fwmigrate.web import create_app


def test_react_build_is_served(tmp_path: Path):
    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text('<div id="root"></div><script src="/assets/app.js"></script>', encoding="utf-8")
    (assets / "app.js").write_text("React app", encoding="utf-8")
    (dist / "favicon.svg").write_text("<svg></svg>", encoding="utf-8")

    client = create_app({"TESTING": True, "FRONTEND_DIST_DIR": str(dist)}).test_client()

    assert b'<div id="root"></div>' in client.get("/").data
    assert client.get("/assets/app.js").data == b"React app"
    assert client.get("/favicon.svg").data == b"<svg></svg>"
    assert client.get("/favicon.ico").status_code == 200
    assert client.get("/legacy").status_code == 404


def test_frontend_dist_environment_override(tmp_path: Path, monkeypatch):
    dist = tmp_path / "container-frontend"
    dist.mkdir()
    (dist / "index.html").write_text("container frontend", encoding="utf-8")
    monkeypatch.setenv("FWMIGRATE_FRONTEND_DIST_DIR", str(dist))

    client = create_app({"TESTING": True}).test_client()

    assert b"container frontend" in client.get("/").data


def test_react_route_reports_missing_build(tmp_path: Path):
    client = create_app({"TESTING": True, "FRONTEND_DIST_DIR": str(tmp_path / "missing")}).test_client()

    response = client.get("/")

    assert response.status_code == 503
    assert response.get_json() == {"error": "Frontend build is unavailable"}
