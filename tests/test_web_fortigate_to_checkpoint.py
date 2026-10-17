from io import BytesIO
import json
import zipfile

import fwmigrate.web as web_module
from fwmigrate.web import create_app
from tests.conversion.fortigate_to_checkpoint.conftest import SOURCE


OPTIONS = {
    "source_vdom": "root",
    "management_target": "cp-mgmt-test",
    "management_domain": "Default Domain",
    "management_api_version": "1.8.1",
    "gaia_target": "cp-gw-test",
    "policy_package": "Migration Package",
    "access_layer": "Network",
    "install_on": ["cp-gw-test"],
    "insertion_anchor": "Cleanup Drop",
    "insertion_relation": "above",
    "target_cleanup_action": "Drop",
}


def test_checkpoint_web_approval_previews_and_downloads_exact_split_bytes(monkeypatch):
    transport_calls = []
    monkeypatch.setattr(web_module, "PANSSHDeployer", lambda *_args, **_kwargs: transport_calls.append("constructed"))
    app = create_app({"TESTING": True, "WORKSPACE_SIGNING_KEY": b"x" * 32})
    client = app.test_client()
    source = {"vendor": "fortigate", "source_text": SOURCE}
    options = dict(OPTIONS)
    prefix = "/api/migration/fortigate_to_checkpoint"

    prepared = client.post(prefix + "/design/prepare", json={"source": source, "options": options})
    assert prepared.status_code == 200, prepared.json
    selected = [item["key"] for item in prepared.json["report"]["items"]
                if item["render_disposition"] == "CREATE"]
    assert selected
    approved = client.post(prefix + "/design/approve", json={
        "source": source, "options": options, "draft": prepared.json["draft"],
        "selected_items": selected,
    })
    assert approved.status_code == 200, approved.json
    built = client.post(prefix + "/build", json={
        "source": source, "options": options, "approval": approved.json["approval"],
    })
    assert built.status_code == 200, built.json
    artifact = built.json["artifact"]
    assert artifact["deployment_available"] is False

    preview = client.post(prefix + "/artifact-preview", json={"source": source, "artifact": artifact})
    assert preview.status_code == 200, preview.json
    for route, filename in (("management-operations", "checkpoint_management_operations.json"),
                            ("gaia-config", "gaia_config.clish"),
                            ("bindings", "checkpoint_bindings.json")):
        response = client.post(prefix + "/" + route, json={"source": source, "artifact": artifact})
        assert response.status_code == 200
        assert response.data.decode("utf-8") == preview.json["files"][filename]["text"]

    bundle = client.post(prefix + "/bundle", json={"source": source, "artifact": artifact})
    assert bundle.status_code == 200
    with zipfile.ZipFile(BytesIO(bundle.data)) as archive:
        for filename in ("checkpoint_management_operations.json", "gaia_config.clish", "checkpoint_bindings.json"):
            assert archive.read(filename).decode("utf-8") == preview.json["files"][filename]["text"]
        report = json.loads(archive.read("migration_report.json"))
        assert report["file_sha256"] == artifact["file_sha256"]

    for path in ("/api/deploy", "/api/inspect-candidate", "/api/validate-candidate", "/api/commit"):
        response = client.post(path, json={"artifact": artifact})
        assert response.status_code in {400, 403}
    assert transport_calls == []


def test_checkpoint_web_rejects_stale_source_target_upload_and_tampered_artifact():
    app = create_app({"TESTING": True, "WORKSPACE_SIGNING_KEY": b"x" * 32})
    client = app.test_client()
    source = {"vendor": "fortigate", "source_text": SOURCE}
    prefix = "/api/migration/fortigate_to_checkpoint"
    prepared = client.post(prefix + "/design/prepare", json={"source": source, "options": OPTIONS})
    selected = [item["key"] for item in prepared.json["report"]["items"]
                if item["render_disposition"] == "CREATE"]
    approved = client.post(prefix + "/design/approve", json={"source": source, "options": OPTIONS,
                                                                 "draft": prepared.json["draft"],
                                                                 "selected_items": selected})
    built = client.post(prefix + "/build", json={"source": source, "options": OPTIONS,
                                                   "approval": approved.json["approval"]})
    artifact = built.json["artifact"]

    stale_source = {"vendor": "fortigate", "source_text": SOURCE + "\n# changed"}
    stale = client.post(prefix + "/artifact-preview", json={"source": stale_source, "artifact": artifact})
    assert stale.status_code == 400
    target = client.post(prefix + "/design/prepare", json={"source": source, "options": OPTIONS,
                                                              "target_source": {"source_text": "target"}})
    assert target.status_code == 400

    tampered = json.loads(json.dumps(artifact))
    tampered["files"]["gaia_config.clish"]["content"] += "save config\n"
    rejected = client.post(prefix + "/artifact-preview", json={"source": source, "artifact": tampered})
    assert rejected.status_code == 400

    deployment = client.post("/api/deploy", json={"artifact": artifact})
    assert deployment.status_code in {400, 403}
