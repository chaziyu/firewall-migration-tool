from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

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
    assert b"Connect FortiGate over SSH" in page.data
    assert b"FortiGate over SSH" in page.data
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
    load_workbook = pytest.importorskip("openpyxl").load_workbook
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
    workbook = load_workbook(BytesIO(excel.data))
    assert {"Summary", "Addresses", "Source Inventory", "Extraction Coverage"}.issubset(
        workbook.sheetnames
    )
    assert workbook["Summary"]["B6"].value == "FG-WEB-TEST"
    assert workbook["Addresses"]["A4"].value == "host1"

    stored_snapshot = live_api.LIVE_SOURCE_SNAPSHOTS[payload["collection_id"]]
    assert "secret" not in stored_snapshot.model_dump_json()


def test_excel_rejects_unknown_collection_id():
    app = create_app({"TESTING": True})
    client = app.test_client()

    response = client.post(
        "/api/source/fortigate/extract/excel",
        json={"collection_id": "missing"},
    )
    assert response.status_code == 404
    assert "expired" in response.get_json()["error"].lower()


def test_excel_rejects_missing_collection_id():
    app = create_app({"TESTING": True})
    response = app.test_client().post(
        "/api/source/fortigate/extract/excel", json={}
    )
    assert response.status_code == 400
    assert "collection_id" in response.get_json()["error"]


def test_main_frontend_uses_live_source_contract():
    app_js = (Path(__file__).parents[1] / "src/fwmigrate/static/app.js").read_text(
        encoding="utf-8"
    )
    live_handler = app_js.split("// 5. Live FortiGate SSH Ingestion Handler", 1)[1].split(
        "// 6. File Dropzone & Handling", 1
    )[0]
    assert "/api/source/fortigate/pull" in live_handler
    assert "/api/source/fortigate/extract/excel" in app_js
    assert "/api/ingest/${selectedSourceVendor}" not in app_js
    assert "fetchMigrationPreview();" not in live_handler
    assert "verify_host_key" in live_handler
    assert '|| "22"' in live_handler


def test_live_snapshot_lookup_validates_expiry_and_missing_ids(monkeypatch):
    import fwmigrate.live_source_api as live_api

    live_api.LIVE_SOURCE_SNAPSHOTS.clear()
    snapshot = SourceSnapshot(
        vendor="fortigate",
        raw_config=FORTIGATE_CONFIG,
        collection_method="ssh-cli",
    )
    collection_id = live_api._store_snapshot(snapshot)
    assert live_api._get_live_snapshot(collection_id) is snapshot

    with pytest.raises(ValueError, match="collection_id"):
        live_api._get_live_snapshot("")
    with pytest.raises(LookupError, match="not found or has expired"):
        live_api._get_live_snapshot("missing")

    expired_id = "expired"
    live_api.LIVE_SOURCE_SNAPSHOTS[expired_id] = snapshot.model_copy(
        update={"collected_at": datetime.now(timezone.utc) - live_api._SNAPSHOT_TTL - timedelta(seconds=1)}
    )
    with pytest.raises(LookupError, match="not found or has expired"):
        live_api._get_live_snapshot(expired_id)
    assert expired_id not in live_api.LIVE_SOURCE_SNAPSHOTS


def test_live_snapshot_store_evicts_oldest_entry():
    import fwmigrate.live_source_api as live_api

    live_api.LIVE_SOURCE_SNAPSHOTS.clear()
    collection_ids = [
        live_api._store_snapshot(
            SourceSnapshot(
                vendor="fortigate",
                raw_config=f"config system global\nset hostname \"{index}\"\nend\n",
                collection_method="ssh-cli",
            )
        )
        for index in range(live_api._MAX_SNAPSHOTS + 1)
    ]
    assert len(live_api.LIVE_SOURCE_SNAPSHOTS) == live_api._MAX_SNAPSHOTS
    assert collection_ids[0] not in live_api.LIVE_SOURCE_SNAPSHOTS
