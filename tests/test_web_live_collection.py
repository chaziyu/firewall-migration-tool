import io

from openpyxl import load_workbook

from fwmigrate.collection import cisco_asa
from fwmigrate.web import create_app


SOURCE = "hostname asa\ninterface GigabitEthernet0/1\n nameif outside\n ip address 203.0.113.1 255.255.255.0\n"


def _payload(password="do-not-persist"):
    return {"vendor": "cisco_asa", "connection": {
        "host": "192.0.2.1", "port": 22, "username": "admin", "password": password,
    }}


def test_connection_failure_does_not_return_credentials(monkeypatch):
    monkeypatch.setattr(cisco_asa, "test_connection", lambda options: (_ for _ in ()).throw(RuntimeError(options["password"])))
    response = create_app({"TESTING": True}).test_client().post("/api/collection/test", json=_payload())
    assert response.status_code == 502
    assert b"do-not-persist" not in response.data


def test_asa_collection_uses_existing_preview_cache_and_excel(monkeypatch):
    monkeypatch.setattr(cisco_asa, "collect", lambda options: cisco_asa.CollectedSource(
        "cisco_asa", SOURCE, "live-cisco-asa.cfg", {"method": "ssh"}
    ))
    client = create_app({"TESTING": True}).test_client()
    response = client.post("/api/collection/collect", json=_payload())
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["collection"]["status"] == "SUCCESS"
    assert payload["preview_id"]
    assert "do-not-persist" not in str(payload)

    workbook = client.post("/api/extract/excel", data={
        "source_vendor": "cisco_asa", "preview_id": payload["preview_id"],
    })
    assert workbook.status_code == 200
    assert "Interfaces" in load_workbook(io.BytesIO(workbook.data), read_only=True).sheetnames


def test_collection_rejects_unsupported_vendors_and_invalid_ports():
    client = create_app({"TESTING": True}).test_client()
    assert client.post("/api/collection/collect", json={**_payload(), "vendor": "cisco_ftd"}).status_code == 400
    assert client.post("/api/collection/test", json={**_payload(), "connection": {**_payload()["connection"], "port": 70000}}).status_code == 400
