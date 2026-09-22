import io

from openpyxl import load_workbook

from fwmigrate.web import create_app


ASA_SOURCE = (
    "hostname asa\n"
    "username admin password 0 web-secret\n"
    "interface GigabitEthernet0/1\n"
    " nameif outside\n"
    " ip address 203.0.113.1 255.255.255.0\n"
    "object network WEB\n"
    " host 10.0.0.10\n"
    "access-list OUT extended permit tcp object WEB any eq 443\n"
)


def _post(client, path, **fields):
    data = {"source_vendor": "cisco_asa", **fields}
    if path == "/api/preview" or "file" not in data:
        data["file"] = (io.BytesIO(ASA_SOURCE.encode()), "asa.cfg")
    return client.post(path, data=data, content_type="multipart/form-data")


def test_source_preview_and_excel_use_opaque_cached_asa_analysis():
    client = create_app({"TESTING": True}).test_client()

    preview = _post(client, "/api/preview")
    assert preview.status_code == 200
    payload = preview.get_json()
    assert payload["vendor"] == "cisco_asa"
    assert payload["summary"]["interfaces"] == 1
    assert "canonical_ir" not in str(payload)

    workbook = _post(client, "/api/extract/excel", preview_id=payload["preview_id"])
    assert workbook.status_code == 200
    assert workbook.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    sheets = load_workbook(io.BytesIO(workbook.data), read_only=True).sheetnames
    assert "Interfaces" in sheets
    assert "web-secret" not in workbook.data.decode("latin1", errors="ignore")


def test_source_excel_rejects_missing_input_and_unknown_vendor():
    client = create_app({"TESTING": True}).test_client()

    missing = client.post("/api/extract/excel", data={"source_vendor": "cisco_asa"})
    assert missing.status_code == 400

    unknown = _post(client, "/api/preview", source_vendor="unknown")
    assert unknown.status_code == 400


def test_source_excel_vendor_mismatch_does_not_use_cached_preview():
    client = create_app({"TESTING": True}).test_client()
    preview = _post(client, "/api/preview").get_json()

    response = client.post(
        "/api/extract/excel",
        data={"source_vendor": "unknown", "preview_id": preview["preview_id"]},
        content_type="multipart/form-data",
    )
    assert response.status_code == 422
