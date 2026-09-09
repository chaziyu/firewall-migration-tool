from __future__ import annotations

import pytest

from fwmigrate.collectors.models import ConnectionResult, SourceSnapshot
from fwmigrate.web_live import create_app


FORTIGATE_CONFIG = """config system global
    set hostname \"FG-WEB-TEST\"
end
config firewall address
    edit \"host1\"
        set subnet 10.10.10.10 255.255.255.255
    next
end
"""


class FakeCollector:
    collect_calls = 0

    def __init__(self, **_kwargs):
        pass

    def test_connection(self):
        return ConnectionResult(
            success=True,
            vendor="fortigate",
            hostname="FG-WEB-TEST",
            software_version="FortiGate-VM64 v7.4.6",
            message="Connection successful",
        )

    def collect(self):
        type(self).collect_calls += 1
        return SourceSnapshot(
            vendor="fortigate",
            hostname="FG-WEB-TEST",
            software_version="FortiGate-VM64 v7.4.6",
            raw_config=FORTIGATE_CONFIG,
            collection_method="ssh-cli",
            commands_executed=["get system status", "show full-configuration"],
            complete=True,
        )


def _credentials():
    return {
        "host": "192.0.2.10",
        "port": 22,
        "username": "admin",
        "password": "secret",
    }


def test_live_source_is_integrated_into_main_page_and_connection_endpoint(monkeypatch):
    import fwmigrate.live_source_api as live_api

    monkeypatch.setattr(live_api, "FortiGateSSHCollector", FakeCollector)
    app = create_app({"TESTING": True})
    client = app.test_client()

    page = client.get("/")
    assert page.status_code == 200
    assert b"Firewall Migration Tool" in page.data
    assert b'id="btn-ingest-file"' in page.data
    assert b'id="btn-ingest-api"' in page.data
    assert b'id="ingest-api-container"' in page.data
    assert b'id="btn-api-extract"' in page.data
    assert b"app.js" in page.data

    legacy = client.get("/live-source")
    assert legacy.status_code == 302
    assert legacy.headers["Location"].endswith("/")

    redirected = client.get("/live-source", follow_redirects=True)
    assert redirected.status_code == 200
    assert b'id="btn-ingest-api"' in redirected.data

    response = client.post("/api/source/fortigate/test", json=_credentials())
    assert response.status_code == 200
    assert response.get_json()["success"] is True
    assert response.get_json()["hostname"] == "FG-WEB-TEST"


def test_pull_then_excel_uses_same_server_side_snapshot(monkeypatch):
    pytest.importorskip("openpyxl")
    import fwmigrate.live_source_api as live_api

    live_api.LIVE_SOURCE_SNAPSHOTS.clear()
    FakeCollector.collect_calls = 0
    monkeypatch.setattr(live_api, "FortiGateSSHCollector", FakeCollector)

    app = create_app({"TESTING": True})
    client = app.test_client()

    pull = client.post("/api/source/fortigate/pull", json=_credentials())
    assert pull.status_code == 200
    payload = pull.get_json()
    assert payload["success"] is True
    assert payload["complete"] is True
    assert payload["collection_id"]
    assert payload["raw_config_bytes"] == len(FORTIGATE_CONFIG.encode("utf-8"))
    assert FakeCollector.collect_calls == 1

    class MustNotReconnect:
        def __init__(self, **_kwargs):
            raise AssertionError("Excel export must not reconnect to the firewall")

    monkeypatch.setattr(live_api, "FortiGateSSHCollector", MustNotReconnect)
    excel = client.post(
        "/api/source/fortigate/extract/excel",
        json={"collection_id": payload["collection_id"]},
    )

    assert excel.status_code == 200
    assert excel.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert excel.headers["X-Source-Config-SHA256"] == payload["sha256"]
    assert excel.headers["X-Source-Collection-Complete"] == "true"
    assert FakeCollector.collect_calls == 1


def test_excel_rejects_unknown_collection_id():
    app = create_app({"TESTING": True})
    client = app.test_client()

    response = client.post(
        "/api/source/fortigate/extract/excel",
        json={"collection_id": "missing"},
    )
    assert response.status_code == 404
    assert "expired" in response.get_json()["error"].lower()
