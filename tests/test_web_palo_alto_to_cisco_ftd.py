from io import BytesIO
import json
from pathlib import Path
import zipfile

from fwmigrate.web import create_app


BASE = "/api/migration/palo_alto_to_cisco_ftd"


def payload():
    return {
        "source": {
            "vendor": "palo_alto",
            "source_text": (Path(__file__).parent / "fixtures/palo_alto/ftd_policy_explicit.xml").read_text(encoding="utf-8"),
        },
        "options": {"target_mode": "new"},
    }


def build(client, data):
    prepared = client.post(BASE + "/design/prepare", json=data)
    assert prepared.status_code == 200, prepared.get_json()
    review = prepared.get_json()
    keys = [row["key"] for row in review["report"]["items"] if row["render_disposition"] in {"CREATE", "REUSE"}]
    approved = client.post(BASE + "/design/approve", json={**data, "draft": review["draft"], "selected_items": keys})
    assert approved.status_code == 200, approved.get_json()
    signed = approved.get_json()["approval"]
    built = client.post(BASE + "/build", json={**data, "approval": signed})
    assert built.status_code == 200, built.get_json()
    return review, signed, built.get_json()["artifact"]


def test_exact_signed_multifile_preview_download_bundle_and_integrity():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    data = payload()
    review, approval, artifact = build(client, data)
    assert artifact["report"]["fmc_operation_count"] > 0
    assert artifact["deployment_available"] is False

    policy = next(row["key"] for row in review["report"]["items"] if row["family"] == "policy")
    assert client.post(BASE + "/design/approve", json={**data, "draft": review["draft"], "selected_items": [policy]}).status_code == 400

    preview = client.post(BASE + "/artifact-preview", json={**data, "artifact": artifact})
    assert preview.status_code == 200

    bundle = client.post(BASE + "/bundle", json={**data, "artifact": artifact})
    assert bundle.status_code == 200

    with zipfile.ZipFile(BytesIO(bundle.data)) as archive:
        for kind, name in [
            ("fmc-operations", "cisco_fmc_operations.json"),
            ("fmc-curl", "cisco_fmc_curl.sh"),
            ("bindings", "cisco_fmc_bindings.json"),
            ("instructions", "ftd_application_instructions.txt"),
        ]:
            response = client.post(BASE + "/" + kind, json={**data, "artifact": artifact})
            assert response.status_code == 200
            assert response.data == archive.read(name) == preview.get_json()["files"][name]["text"].encode("utf-8") == artifact["files"][name]["content"].encode("utf-8")
        assert {"migration_report.json", "migration_decisions.json", "source_inventory.xlsx", "target_mapping.yaml"} <= set(archive.namelist())

    changed = {**data, "options": {**data["options"], "policy_name": "another-policy"}}
    assert client.post(BASE + "/build", json={**changed, "approval": approval}).status_code == 400
    assert client.post(BASE + "/artifact-preview", json={**data, "artifact": {**artifact, "source_digest": "foreign"}}).status_code == 400


def test_wrong_pair_source_and_import_cannot_grant_approval():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    data = payload()
    _, _, artifact = build(client, data)
    replaced = {**data, "source": {**data["source"], "source_text": data["source"]["source_text"].replace("pan-lab-01", "other-device")}}
    assert client.post(BASE + "/bundle", json={**replaced, "artifact": artifact}).status_code == 400
    document = client.post(BASE + "/decisions/export", json=data).get_json()["document"]
    imported = client.post(BASE + "/decisions/import", json={**data, "document": document})
    assert imported.status_code == 200
    assert set(imported.get_json()) == {"success", "options"}
    assert client.post(BASE + "/decisions/import", json={**data, "document": {**document, "pair_id": "fortigate_to_cisco_ftd"}}).status_code == 400


def test_existing_target_ui_contract_reuse_and_stale_metadata():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    data = payload()
    data["options"] = {"target_mode": "existing", "domain_name": "Global", "domain_id": "e276abec-e0f2-11e3-8169-6d9ed49b625f"}
    unproven = client.post(BASE + "/design/prepare", json=data).get_json()
    assert not any(row["render_disposition"] in {"CREATE", "REUSE"} for row in unproven["report"]["items"])

    target_text = (Path(__file__).parent / "fixtures/cisco_ftd/pan_migration_target_fmc_770.json").read_text(encoding="utf-8")
    data["target_source"] = {"vendor": "cisco_ftd", "source_text": target_text}
    data["target_metadata"] = {
        "context": "Global",
        "version": "7.7.0",
        "mode": "fmc",
        "complete_families": ["objects", "services", "zones", "devices"],
    }
    review, approval, _ = build(client, data)
    assert any(row["render_disposition"] == "REUSE" for row in review["report"]["items"])
    stale = {**data, "target_metadata": {**data["target_metadata"], "complete_families": ["objects"]}}
    assert client.post(BASE + "/build", json={**stale, "approval": approval}).status_code == 400
