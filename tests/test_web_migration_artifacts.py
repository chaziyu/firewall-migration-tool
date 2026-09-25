import hashlib
import io
import json
import zipfile
from pathlib import Path

from fwmigrate.web import create_app


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

    payload = {"artifact_id": plan["artifact_id"]}
    command_preview = client.post("/api/migration/command-preview", json=payload)
    download = client.post("/api/migration/download", json=payload)
    bundle_response = client.post("/api/migration/bundle", json=payload)

    assert command_preview.status_code == download.status_code == bundle_response.status_code == 200
    preview_data = command_preview.get_json()
    assert preview_data["command_count"] == plan["commands"]
    assert hashlib.sha256("\n".join(preview_data["commands"]).encode()).hexdigest() == preview_data["command_sha256"]
    assert preview_data["command_sha256"] == plan["report"]["command_sha256"]
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
