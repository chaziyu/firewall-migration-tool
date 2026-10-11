from tests.approved_design import approved_migrate, approved_payload
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


def test_mixed_policy_match_stays_blocked_and_visible_in_review_and_bundle():
    client = create_app({'TESTING': True}).test_client()
    source_text = FIXTURE.read_bytes().replace(b'set srcaddr "web-host"',
        b'set srcaddr "web-host"\n        set srcaddr6 "v6-source"\n        set nat enable')
    source = client.post('/api/preview', data={
        'file': (io.BytesIO(source_text), 'mixed.conf')}).get_json()['source_evidence']
    prepared = approved_payload(client, {'source': source, 'mapping': MAPPING})
    draft = client.post('/api/migration/design/prepare', json=prepared).get_json()['draft']
    security = [row for row in draft['configuration'] if row['family'] == 'security_rule']
    assert security and all(row['status'] == 'UNSUPPORTED' for row in security)
    result = client.post('/api/migrate', json=prepared).get_json()
    assert not any('set rulebase security' in command for command in result['commands'])
    assert not any('set rulebase nat rules allow-web' in command for command in result['commands'])
    blocked = [row for row in result['report']['items'] if row['source_kind'] in {'policy', 'source_nat'}]
    assert blocked and all(row['render_disposition'] == 'BLOCK' for row in blocked)
    assert any(row['source_kind'] == 'source_nat' for row in blocked)
    assert any("explicit source srcaddr6 = ['v6-source']" in row['warnings'] for row in blocked)
    bundle = client.post('/api/migration/bundle', json={'source': source, 'artifact': result['artifact']})
    assert bundle.status_code == 200
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        report = json.loads(archive.read('migration_report.json'))
        assert report['items'] == result['report']['items']
        assert b'v6-source' in archive.read('migration_report.json')


def test_duplicate_interface_imports_cannot_reach_reviewed_artifact_commands():
    from copy import deepcopy

    client = create_app({"TESTING": True}).test_client()
    preview_id = client.post('/api/preview', data={'source_vendor': 'fortigate',
        'file': (io.BytesIO(FIXTURE.read_bytes()), FIXTURE.name)}, content_type='multipart/form-data').get_json()['source_evidence']
    mapping = deepcopy(MAPPING)
    mapping['interfaces']['root']['wan']['target_interface'] = 'ethernet1/1'
    result = approved_migrate(client, json={'source': preview_id, 'mapping': mapping}).get_json()
    assert result['plan_status'] != 'READY'
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
    plan = approved_migrate(client, json={
        "source": preview["source_evidence"], "mapping": MAPPING,
    }).get_json()
    assert plan["command_count"] > 0
    assert set(plan["render_dispositions"]) >= {"CREATE", "REUSE", "BLOCK"}
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
    plan = client.post("/api/migrate", json=approved_payload(client, {"source": preview["source_evidence"]}, configuration=False)).get_json()
    payload = {"artifact": plan["artifact"], "source": preview["source_evidence"]}

    assert client.post("/api/migration/command-preview", json=payload).status_code == 422
    assert client.post("/api/migration/download", json=payload).status_code == 422


def test_all_reuse_migration_is_ready_with_an_empty_artifact():
    from tests.test_web_candidate_sessions import MINIMAL_FORTIGATE, CREDS
    from tests.approved_design import TARGET
    client = create_app({"TESTING": True}).test_client()
    source = client.post('/api/preview', data={'file': (io.BytesIO(MINIMAL_FORTIGATE), 'source.conf')}).get_json()['source_evidence']
    target_xml = TARGET.replace(b'<vsys><entry name="vsys1"/>',
        b'<vsys><entry name="vsys1"><address><entry name="host-a"><ip-netmask>192.0.2.10/32</ip-netmask></entry></address></entry>')
    target = client.post('/api/preview', data={'source_vendor': 'palo_alto',
        'file': (io.BytesIO(target_xml), 'target.xml')}).get_json()['source_evidence']
    result = approved_migrate(client, json={'source': source, 'target_source': target}).get_json()
    payload = {'artifact': result['artifact'], 'source': source}
    command_preview = client.post('/api/migration/command-preview', json=payload)
    download = client.post('/api/migration/download', json=payload)
    bundle = client.post('/api/migration/bundle', json=payload)
    assert result['plan_status'] == 'READY_NO_CHANGES'
    assert result['render_summary'] == {'create': 0, 'reuse': 1, 'blocked': 0, 'satisfied': 1, 'command_renderable': 0}
    assert command_preview.status_code == download.status_code == bundle.status_code == 200
    preview_data = command_preview.get_json()
    assert preview_data['commands'] == [] and preview_data['command_text'] == ''
    assert preview_data['command_count'] == 0 and preview_data['no_changes_required'] is True
    assert preview_data['command_sha256'] == hashlib.sha256(b'').hexdigest()
    assert download.data == b''
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        assert archive.read('palo_alto_config.set') == b''
    assert client.post('/api/deploy', json={**CREDS, 'artifact': result['artifact']}).status_code == 400


def test_artifact_report_contains_safe_target_review_provenance():
    client = create_app({"TESTING": True}).test_client()
    preview = client.post("/api/preview", data={
        "file": (io.BytesIO(FIXTURE.read_bytes()), FIXTURE.name),
    }, content_type="multipart/form-data").get_json()["source_evidence"]
    target = client.post("/api/preview", data={
        "source_vendor": "palo_alto",
        "file": (io.BytesIO((Path(__file__).parent / "fixtures" / "palo_alto" / "integrated_firewall.xml").read_bytes()), "target.xml"),
    }, content_type="multipart/form-data").get_json()["source_evidence"]
    result = approved_migrate(client, json={
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
    payload = approved_payload(client, {'source': source, 'mapping': MAPPING})
    full_response = client.post("/api/migrate", json=payload)
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
