import io
from pathlib import Path

from fwmigrate.web import create_app


SOURCE = Path(__file__).parents[2] / "fixtures" / "fortigate" / "palo_alto_mvp.conf"
TARGET = Path(__file__).parents[2] / "fixtures" / "palo_alto" / "integrated_firewall.xml"


def _preview(client, path, vendor):
    return client.post("/api/preview", data={
        "source_vendor": vendor,
        "file": (io.BytesIO(path.read_bytes()), path.name),
    }, content_type="multipart/form-data").get_json()["preview_id"]


def test_confirmed_target_conflict_is_report_only():
    client = create_app({"TESTING": True}).test_client()
    source_preview = _preview(client, SOURCE, "fortigate")
    target_preview = _preview(client, TARGET, "palo_alto")
    requirements = client.post("/api/migration/requirements", json={
        "preview_id": source_preview,
        "target_preview_id": target_preview,
    }).get_json()
    document = requirements["decision_document"]
    for item in document["decisions"]:
        if item["source_kind"] == "interface" and item["source_name"] == "lan" and item["target_field"] == "target_interface":
            item.update(value="ethernet1/1", review_state="CONFIRMED")
        if item["source_kind"] == "interface" and item["source_name"] == "lan" and item["target_field"] == "target_zone":
            item.update(value="untrust", review_state="CONFIRMED")
    result = client.post("/api/migrate", json={
        "preview_id": source_preview,
        "decision_document": document,
        "target_preview_id": target_preview,
        "target_device": "integrated-fw",
    }).get_json()
    findings = result["target_findings"]
    assert any(item["code"] == "TARGET_ZONE_CONFLICT" for item in findings)
    assert result["support_guidance"]
