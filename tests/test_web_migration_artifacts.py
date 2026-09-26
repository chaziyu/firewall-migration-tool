import hashlib
import io
import json
import zipfile
from pathlib import Path

from fwmigrate.web import create_app
import fwmigrate.web as web
from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationPlan, PANMigrationStatus, PlannedAddress


FIXTURE = Path(__file__).parent / "fixtures" / "fortigate" / "palo_alto_mvp.conf"
MAPPING = {
    "vdoms": {"root": {"vsys": "vsys1", "virtual_router": "default"}},
    "interfaces": {"root": {
        "lan": {"target_interface": "ethernet1/1", "target_zone": "trust"},
        "wan": {"target_interface": "ethernet1/2", "target_zone": "untrust"},
        "trust": {"target_zone": "trust"},
        "untrust": {"target_zone": "untrust"},
    }},
}


def test_preview_download_and_bundle_share_one_rendered_artifact():
    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={
        "file": (io.BytesIO(FIXTURE.read_bytes()), FIXTURE.name),
    }, content_type="multipart/form-data").get_json()
    plan = client.post("/api/migrate", json={
        "preview_id": preview["preview_id"], "mapping": MAPPING,
    }).get_json()
    assert plan["commands"] > 0
    assert set(plan["render_dispositions"]) == {"CREATE", "REUSE", "BLOCK"}
    assert all(item["decision_keys"] and "render_disposition" in item for item in plan["report"]["items"])

    payload = {"artifact_id": plan["artifact_id"]}
    command_preview = client.post("/api/migration/command-preview", json=payload)
    download = client.post("/api/migration/download", json=payload)
    bundle_response = client.post("/api/migration/bundle", json=payload)

    assert command_preview.status_code == download.status_code == bundle_response.status_code == 200
    preview_data = command_preview.get_json()
    assert preview_data["command_count"] == plan["commands"]
    assert hashlib.sha256("\n".join(preview_data["commands"]).encode()).hexdigest() == preview_data["command_sha256"]
    assert preview_data["command_sha256"] == plan["report"]["command_sha256"]
    assert plan["report"]["summary"]["render_dispositions"] == plan["render_dispositions"]
    assert preview_data["command_text"].encode() == download.data
    with zipfile.ZipFile(io.BytesIO(bundle_response.data)) as archive:
        assert archive.read("palo_alto_config.set") == download.data
        assert json.loads(archive.read("migration_report.json"))["command_sha256"] == preview_data["command_sha256"]


def test_preview_and_download_block_empty_migration_artifact():
    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={
        "file": (io.BytesIO(FIXTURE.read_bytes()), FIXTURE.name),
    }, content_type="multipart/form-data").get_json()
    plan = client.post("/api/migrate", json={"preview_id": preview["preview_id"], "mapping": {}}).get_json()
    payload = {"artifact_id": plan["artifact_id"]}

    assert client.post("/api/migration/command-preview", json=payload).status_code == 422
    assert client.post("/api/migration/download", json=payload).status_code == 422


def test_all_reuse_migration_is_ready_with_an_empty_artifact(monkeypatch):
    class Planner:
        def plan(self, *_args, **_kwargs):
            return PANMigrationPlan(addresses=(PlannedAddress(source_vdom="root", source_kind="address",
                source_object_type="address", source_name="already-there", target_vsys="vsys1",
                target_name="already-there", status=PANMigrationStatus.SUPPORTED,
                address_type="ip-netmask", value="192.0.2.1/32"),))

    monkeypatch.setattr(web.migration_planners, "get", lambda *_args: Planner())
    monkeypatch.setattr(web, "classify_target_object_reuse", lambda plan, *_args: ({
            "status": "EXACT_MATCH", "family": "address", "source_vdom": "root",
            "source_kind": "address", "target_vsys": "vsys1",
            "source_name": "already-there", "target_name": "already-there",
        },))
    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={
        "file": (io.BytesIO(FIXTURE.read_bytes()), FIXTURE.name),
    }, content_type="multipart/form-data").get_json()
    result = client.post("/api/migrate", json={"preview_id": preview["preview_id"], "mapping": MAPPING}).get_json()
    payload = {"artifact_id": result["artifact_id"]}
    command_preview = client.post("/api/migration/command-preview", json=payload)
    download = client.post("/api/migration/download", json=payload)
    bundle = client.post("/api/migration/bundle", json=payload)

    assert result["plan_status"] == "READY_NO_CHANGES"
    assert result["render_summary"] == {"create": 0, "reuse": 1, "blocked": 0, "satisfied": 1, "command_renderable": 0}
    assert command_preview.status_code == download.status_code == bundle.status_code == 200
    preview_data = command_preview.get_json()
    assert preview_data["commands"] == [] and preview_data["command_text"] == ""
    assert preview_data["command_count"] == 0 and preview_data["no_changes_required"] is True
    assert preview_data["command_sha256"] == hashlib.sha256(b"").hexdigest()
    assert download.data == b""
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        assert archive.read("palo_alto_config.set") == b""


def test_artifact_report_contains_safe_target_review_provenance():
    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={
        "file": (io.BytesIO(FIXTURE.read_bytes()), FIXTURE.name),
    }, content_type="multipart/form-data").get_json()["preview_id"]
    target = client.post("/api/preview", data={
        "source_vendor": "palo_alto",
        "file": (io.BytesIO((Path(__file__).parent / "fixtures" / "palo_alto" / "integrated_firewall.xml").read_bytes()), "target.xml"),
    }, content_type="multipart/form-data").get_json()["preview_id"]
    result = client.post("/api/migrate", json={
        "preview_id": preview, "mapping": MAPPING,
        "target_preview_id": target, "target_device": "integrated-fw",
    }).get_json()
    report = result["report"]
    assert report["target_evidence"]["vendor"] == "palo_alto"
    assert report["target_evidence"]["device"] == "integrated-fw"
    assert "target_findings" in report["review"]
    assert "support_guidance" in report["review"]
