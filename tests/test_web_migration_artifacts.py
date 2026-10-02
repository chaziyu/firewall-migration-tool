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


def test_duplicate_interface_imports_cannot_reach_reviewed_artifact_commands():
    from copy import deepcopy

    client = create_app({"TESTING": True}).test_client()
    preview_id = client.post('/api/preview', data={'source_vendor': 'fortigate',
        'file': (io.BytesIO(FIXTURE.read_bytes()), FIXTURE.name)}, content_type='multipart/form-data').get_json()['source_evidence']
    mapping = deepcopy(MAPPING)
    mapping['interfaces']['root']['wan']['target_interface'] = 'ethernet1/1'
    result = client.post('/api/migrate', json={'source': preview_id, 'mapping': mapping}).get_json()
    assert len([item for item in result['target_findings'] if item['code'] == 'TARGET_INTERFACE_ALREADY_ASSIGNED']) == 2
    artifact = {'artifact': result['artifact'], 'source': preview_id}
    command_preview = client.post('/api/migration/command-preview', json=artifact).get_json()
    command_download = client.post('/api/migration/download', json=artifact).data.decode()
    assert 'set network interface' not in command_download
    assert 'set zone ' not in command_download
    assert 'set rulebase security' not in command_download
    assert 'set address web-host' in command_download
    assert command_preview['command_sha256'] == result['report']['command_sha256']
    assert command_preview['command_text'] == command_download
    bundle = client.post('/api/migration/bundle', json=artifact)
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        command_file = next(name for name in archive.namelist() if name.endswith('.set'))
        assert archive.read(command_file).decode() == command_download


def test_preview_download_and_bundle_share_one_rendered_artifact():
    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={
        "file": (io.BytesIO(FIXTURE.read_bytes()), FIXTURE.name),
    }, content_type="multipart/form-data").get_json()
    plan = client.post("/api/migrate", json={
        "source": preview["source_evidence"], "mapping": MAPPING,
    }).get_json()
    assert plan["command_count"] > 0
    assert set(plan["render_dispositions"]) == {"CREATE", "REUSE", "BLOCK"}
    assert all(item["decision_keys"] and "render_disposition" in item for item in plan["report"]["items"])

    payload = {"artifact": plan["artifact"], "source": preview["source_evidence"]}
    command_preview = client.post("/api/migration/command-preview", json=payload)
    download = client.post("/api/migration/download", json=payload)
    bundle_response = client.post("/api/migration/bundle", json=payload)

    assert command_preview.status_code == download.status_code == bundle_response.status_code == 200
    preview_data = command_preview.get_json()
    assert preview_data["command_count"] == plan["command_count"]
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
    plan = client.post("/api/migrate", json={"source": preview["source_evidence"], "mapping": {}}).get_json()
    payload = {"artifact": plan["artifact"], "source": preview["source_evidence"]}

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
    result = client.post("/api/migrate", json={"source": preview["source_evidence"], "mapping": MAPPING}).get_json()
    payload = {"artifact": result["artifact"], "source": preview["source_evidence"]}
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
    }, content_type="multipart/form-data").get_json()["source_evidence"]
    target = client.post("/api/preview", data={
        "source_vendor": "palo_alto",
        "file": (io.BytesIO((Path(__file__).parent / "fixtures" / "palo_alto" / "integrated_firewall.xml").read_bytes()), "target.xml"),
    }, content_type="multipart/form-data").get_json()["source_evidence"]
    result = client.post("/api/migrate", json={
        "source": preview, "mapping": MAPPING,
        "target_source": target, "target_device": "integrated-fw",
    }).get_json()
    report = result["report"]
    assert report["target_evidence"]["vendor"] == "palo_alto"
    assert report["target_evidence"]["device"] == "integrated-fw"
    assert "target_findings" in report["review"]
    assert "support_guidance" in report["review"]


def test_compact_plan_keeps_identical_signed_evidence_and_exports(monkeypatch):
    monkeypatch.setattr(web.uuid, 'uuid4', lambda: type('ID', (), {'hex': 'stable-artifact'})())
    client = create_app({'TESTING': True}).test_client()
    source = client.post('/api/preview', data={'source_vendor': 'fortigate',
        'file': (io.BytesIO(FIXTURE.read_bytes()), FIXTURE.name)}, content_type='multipart/form-data').get_json()['source_evidence']
    payload = {'source': source, 'mapping': MAPPING}
    full_response = client.post('/api/migrate', json=payload)
    compact_response = client.post('/api/migrate', json={**payload, 'compact_response': True})
    full, compact = full_response.get_json(), compact_response.get_json()
    assert full_response.status_code == compact_response.status_code == 200
    assert compact['artifact'] == full['artifact']
    assert compact['artifact']['report'] == full['report']
    assert compact['artifact']['decision_document'] == full['decision_document']
    assert compact['artifact']['commands'] == full['commands']
    assert compact['artifact']['report']['review']['recommendations'] == full['recommendations']
    assert compact['artifact']['report']['review']['support_guidance'] == full['support_guidance']
    for key in compact:
        assert compact[key] == full[key]
    assert not {'commands', 'report', 'decision_document', 'decisions'} & compact.keys()
    assert len(compact_response.data) < len(full_response.data)
    artifact = {'artifact': compact['artifact'], 'source': source}
    preview = client.post('/api/migration/command-preview', json=artifact).get_json()
    download = client.post('/api/migration/download', json=artifact)
    assert preview['command_sha256'] == compact['command_sha256']
    assert preview['command_text'].encode() == download.data
    bundle = client.post('/api/migration/bundle', json=artifact)
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        assert archive.read('palo_alto_config.set') == download.data
        assert json.loads(archive.read('migration_decisions.json')) == full['decision_document']
