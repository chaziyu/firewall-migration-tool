import hashlib
import io
import json
from pathlib import Path
import time
import zipfile

from fwmigrate.web import create_app
from fwmigrate.web_support.artifact_signing import sign_envelope


FIXTURE = Path(__file__).parent / "fixtures" / "fortigate" / "multi_vendor_explicit.conf"
PREFIX = "/api/migration/fortigate_to_juniper_srx"


def _source():
    text = FIXTURE.read_text(encoding="utf-8")
    text = text.replace('set interface "lan" "app-vlan"', 'set interface "lan"', 1)
    return {"vendor": "fortigate", "source_text": text, "source_name": "synthetic.conf"}


def _options():
    return {
        "source_vdom": "root",
        "target_context": "root",
        "target_version": "25.2R1",
        "target_mode": "standalone",
        "routing_table": "inet.0",
        "timezone": "Asia/Kuala_Lumpur",
        "interfaces": {"root": {
            "lan": {"target_interface": "ge-0/0/0", "unit": 0},
            "wan": {"target_interface": "ge-0/0/1", "unit": 0},
            "app-vlan": {"target_interface": "ge-0/0/0", "unit": 120},
        }},
        "zones": {"root": {"inside": "inside-zone", "outside": "outside-zone"}},
    }


def _target(source_text=""):
    return {
        "target_source": {
            "vendor": "juniper_srx", "source_text": source_text,
            "source_name": "synthetic-target.set",
        },
        "target_metadata": {
            "context": "root", "version": "25.2R1", "mode": "standalone",
            "complete_families": [
                "addresses", "applications", "interfaces", "zones", "static_routes",
                "schedules", "policies", "nat",
            ],
        },
    }


def _build_artifact(client):
    payload = {"source": _source(), "options": _options()}
    prepared = client.post(f"{PREFIX}/design/prepare", json=payload)
    assert prepared.status_code == 200
    review = prepared.get_json()
    selected = [
        item["key"] for item in review["report"]["items"]
        if item["render_disposition"] == "CREATE"
    ]
    approved = client.post(f"{PREFIX}/design/approve", json={
        **payload,
        "draft": review["draft"],
        "selected_items": selected,
    })
    assert approved.status_code == 200
    approval = approved.get_json()["approval"]
    built = client.post(f"{PREFIX}/build", json={**payload, "approval": approval})
    assert built.status_code == 200
    return payload, built.get_json()["artifact"]


def test_disabled_source_route_cannot_be_approved_or_downloaded_as_active():
    client = create_app({"TESTING": True, "WORKSPACE_SIGNING_KEY": b"s" * 32}).test_client()
    source = _source()
    source["source_text"] = source["source_text"].replace("set distance 10", "set distance 10\n                set status disable")
    payload = {"source": source, "options": _options()}
    prepared = client.post(f"{PREFIX}/design/prepare", json=payload)
    assert prepared.status_code == 200
    review = prepared.json
    route = next(item for item in review["report"]["items"] if item["family"] == "static_route" and item["source_name"] == "1")
    assert route["render_disposition"] == "BLOCK"
    rejected = client.post(f"{PREFIX}/design/approve", json={**payload, "draft": review["draft"], "selected_items": [route["key"]]})
    assert rejected.status_code == 400
    selected = [item["key"] for item in review["report"]["items"] if item["render_disposition"] == "CREATE"]
    approved = client.post(f"{PREFIX}/design/approve", json={**payload, "draft": review["draft"], "selected_items": selected})
    assert approved.status_code == 200
    built = client.post(f"{PREFIX}/build", json={**payload, "approval": approved.json["approval"]})
    assert built.status_code == 200
    downloaded = client.post(f"{PREFIX}/commands", json={"artifact": built.json["artifact"]})
    assert downloaded.status_code == 200
    assert "static route 0.0.0.0/0 " not in downloaded.data.decode()


def test_srx_review_approval_build_preview_download_and_bundle_use_same_bytes():
    app = create_app({
        "TESTING": True,
        "WEB_MODE": "local",
        "WORKSPACE_SIGNING_KEY": "s" * 32,
    })
    client = app.test_client()
    payload, artifact = _build_artifact(client)

    command_bytes = artifact["command_text"].encode("utf-8")
    assert artifact["command_sha256"] == hashlib.sha256(command_bytes).hexdigest()
    assert artifact["report"]["deployment_available"] is False
    assert artifact["report"]["destination_verified"] is False

    preview = client.post(f"{PREFIX}/command-preview", json={"artifact": artifact})
    assert preview.status_code == 200
    assert preview.get_json()["text"].encode("utf-8") == command_bytes

    download = client.post(f"{PREFIX}/commands", json={"artifact": artifact})
    assert download.status_code == 200
    assert "attachment" in download.headers["Content-Disposition"]
    assert "juniper_config.set" in download.headers["Content-Disposition"]
    assert download.data == command_bytes

    bundle_response = client.post(f"{PREFIX}/bundle", json={**payload, "artifact": artifact})
    assert bundle_response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(bundle_response.data)) as bundle:
        assert set(bundle.namelist()) == {
            "juniper_config.set", "migration_report.json", "migration_decisions.json",
            "target_mapping.yaml", "source_inventory.xlsx",
        }
        assert bundle.read("juniper_config.set") == command_bytes
        report = json.loads(bundle.read("migration_report.json"))
        assert report["command_sha256"] == artifact["command_sha256"]
        assert bundle.read("source_inventory.xlsx").startswith(b"PK")


def test_srx_rejects_stale_source_tampering_and_pan_deployment_transport(monkeypatch):
    import fwmigrate.web as web

    def unexpected_transport(_options):
        raise AssertionError("SRX artifacts must be rejected before PAN-OS transport")

    monkeypatch.setattr(web, "PANSSHDeployer", unexpected_transport)
    app = create_app({
        "TESTING": True,
        "WEB_MODE": "local",
        "WORKSPACE_SIGNING_KEY": "t" * 32,
    })
    client = app.test_client()
    payload, artifact = _build_artifact(client)

    stale_source = {**payload["source"], "source_text": payload["source"]["source_text"] + "\n"}
    stale_bundle = client.post(f"{PREFIX}/bundle", json={"source": stale_source, "artifact": artifact})
    assert stale_bundle.status_code == 400

    tampered = {**artifact, "command_text": artifact["command_text"] + "set system host-name unsafe\n"}
    preview = client.post(f"{PREFIX}/command-preview", json={"artifact": tampered})
    assert preview.status_code == 400
    assert client.post(f"{PREFIX}/commands", json={"artifact": tampered}).status_code == 400
    unsigned = {key: value for key, value in artifact.items() if key != "signature"}
    assert client.post(f"{PREFIX}/commands", json={"artifact": unsigned}).status_code == 400

    deployment = client.post("/api/deploy", json={
        "artifact": artifact,
        "options": {"host": "192.0.2.10", "username": "reviewer", "password": "unused"},
    })
    assert deployment.status_code == 400
    assert "signed ready design" in deployment.get_json()["error"].lower()

    expired = {**artifact, "expires_at": time.time() - 1}
    expired["design_approval"] = {**artifact["design_approval"], "expires_at": expired["expires_at"]}
    expired_response = client.post(f"{PREFIX}/command-preview", json={"artifact": sign_envelope(expired, b"t" * 32)})
    assert expired_response.status_code == 400

    cross_pair = {**artifact, "target_vendor": "palo_alto"}
    pair_response = client.post(f"{PREFIX}/command-preview", json={"artifact": sign_envelope(cross_pair, b"t" * 32)})
    assert pair_response.status_code == 400


def test_srx_mapping_import_restores_only_source_bound_proposals():
    app = create_app({"TESTING": True, "WEB_MODE": "local", "WORKSPACE_SIGNING_KEY": "u" * 32})
    client = app.test_client()
    source = _source()
    exported = client.post(f"{PREFIX}/decisions/export", json={"source": source, "options": _options()})
    assert exported.status_code == 200
    document = exported.get_json()["document"]
    document["design_approval"] = {"signature": "untrusted"}
    imported = client.post(f"{PREFIX}/decisions/import", json={"source": source, "document": document})
    assert imported.status_code == 200
    assert imported.get_json()["options"]["source_vdom"] == "root"
    assert "design_approval" not in imported.get_json()["options"]

    stale = client.post(f"{PREFIX}/decisions/import", json={
        "source": {**source, "source_text": source["source_text"] + "\n"},
        "document": document,
    })
    assert stale.status_code == 400


def test_srx_destination_comparison_binds_target_snapshot_to_approval():
    app = create_app({"TESTING": True, "WEB_MODE": "local", "WORKSPACE_SIGNING_KEY": "v" * 32})
    client = app.test_client()
    payload = {"source": _source(), "options": _options(), **_target()}

    prepared = client.post(f"{PREFIX}/design/prepare", json=payload)
    assert prepared.status_code == 200
    review = prepared.get_json()
    assert review["report"]["workflow_mode"] == "DESTINATION_AWARE"
    assert review["report"]["destination_verified"] is False
    assert review["report"]["destination_snapshot_compared"] is True
    assert review["report"]["snapshot_evidence_complete"] is True
    assert review["draft"]["target_digest"] == review["report"]["target_digest"]
    assert any(item["render_disposition"] == "CREATE" and item["family"] == "policy"
               for item in review["report"]["items"])

    selected = [item["key"] for item in review["report"]["items"]
                if item["render_disposition"] == "CREATE"]
    approved = client.post(f"{PREFIX}/design/approve", json={
        **payload, "draft": review["draft"], "selected_items": selected,
    })
    assert approved.status_code == 200
    approval = approved.get_json()["approval"]
    assert approval["target_digest"] == review["report"]["target_digest"]

    built = client.post(f"{PREFIX}/build", json={**payload, "approval": approval})
    assert built.status_code == 200
    artifact = built.get_json()["artifact"]
    assert artifact["target_digest"] == approval["target_digest"]
    assert "set security policies from-zone" in artifact["command_text"]
    assert artifact["report"]["destination_verified"] is False
    assert artifact["report"]["destination_snapshot_compared"] is True
    downloaded = client.post(f"{PREFIX}/commands", json={"artifact": artifact})
    assert downloaded.status_code == 200
    assert downloaded.data == artifact["command_text"].encode("utf-8")

    changed_target = {**payload, **_target("set system host-name changed\n")}
    changed = client.post(f"{PREFIX}/build", json={**changed_target, "approval": approval})
    assert changed.status_code == 400
