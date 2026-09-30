from pathlib import Path

from fwmigrate.web import create_app


def test_react_build_is_served_and_legacy_ui_remains_available(tmp_path: Path):
    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text('<div id="root"></div><script src="/assets/app.js"></script>', encoding="utf-8")
    (assets / "app.js").write_text("React app", encoding="utf-8")

    client = create_app({"TESTING": True, "FRONTEND_DIST_DIR": str(dist)}).test_client()

    assert b'<div id="root"></div>' in client.get("/").data
    assert client.get("/assets/app.js").data == b"React app"
    assert b'id="tab-report"' in client.get("/legacy").data


def test_react_route_falls_back_to_legacy_when_build_is_missing(tmp_path: Path):
    client = create_app({"TESTING": True, "FRONTEND_DIST_DIR": str(tmp_path / "missing")}).test_client()

    assert b'id="tab-report"' in client.get("/").data
