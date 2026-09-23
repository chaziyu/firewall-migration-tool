import io
import json
import zipfile
from fwmigrate.web import create_app
from tests.fixture_paths import CISCO_ASA_FIXTURE
from pathlib import Path

MIGRATION_FIXTURE = Path(__file__).parent / "fixtures" / "fortigate" / "palo_alto_mvp.conf"


def _preview(client):
    response = client.post("/api/preview", data={"file": (io.BytesIO(MIGRATION_FIXTURE.read_bytes()), MIGRATION_FIXTURE.name)}, content_type="multipart/form-data")
    assert response.status_code == 200
    return response.get_json()["preview_id"]


def test_migration_endpoint_rejects_unsupported_pair():
    client = create_app({"TESTING": True}).test_client()
    response = client.post(
        "/api/migrate",
        data={
            "source_vendor": "cisco_asa",
            "target_vendor": "palo_alto",
            "include_report": "true",
            "file": (io.BytesIO(CISCO_ASA_FIXTURE.read_bytes()), CISCO_ASA_FIXTURE.name),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert response.get_json() == {"success": False, "error": "Only fortigate -> palo_alto is supported"}


def test_mapping_yaml_import_preserves_vdom_scopes():
    client = create_app({"TESTING": True}).test_client()
    response = client.post("/api/migration/mapping/import", json={"yaml": "vdoms:\n  root:\n    vsys: vsys1\ninterfaces:\n  root:\n    port1:\n      target_zone: trust\n  blue:\n    port1:\n      target_zone: dmz\n"})
    assert response.status_code == 200
    assert response.get_json()["mapping"]["interfaces"]["blue"]["port1"]["target_zone"] == "dmz"


def test_plan_reports_missing_mappings_and_blocks_empty_bundle():
    client = create_app({"TESTING": True}).test_client()
    preview_id = _preview(client)
    requirements = client.post("/api/migration/requirements", json={"preview_id": preview_id}).get_json()["requirements"]
    assert {item["source_vdom"] for item in requirements["vdoms"]} == {"root"}
    plan = client.post("/api/migrate", json={"preview_id": preview_id, "mapping": {}}).get_json()
    assert plan["plan_status"] == "NEEDS_MAPPING"
    assert plan["commands"] == 0
    assert plan["missing_mappings"]
    bundle = client.post("/api/migration/bundle", json={"artifact_id": plan["artifact_id"]})
    assert bundle.status_code == 422


def test_complete_mappings_create_zip_for_same_plan_artifact():
    client = create_app({"TESTING": True}).test_client()
    preview_id = _preview(client)
    mapping = {
        "vdoms": {"root": {"vsys": "vsys1", "virtual_router": "default"}},
        "interfaces": {"root": {
            "lan": {"target_interface": "ethernet1/1", "target_zone": "trust"},
            "wan": {"target_interface": "ethernet1/2", "target_zone": "untrust"},
            "trust": {"target_zone": "trust"},
            "untrust": {"target_zone": "untrust"},
        }},
    }
    plan = client.post("/api/migrate", json={"preview_id": preview_id, "mapping": mapping}).get_json()
    assert plan["commands"] > 0
    response = client.post("/api/migration/bundle", json={"artifact_id": plan["artifact_id"]})
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert set(archive.namelist()) == {"palo_alto_config.set", "migration_report.json", "target_mapping.yaml", "source_inventory.xlsx"}
        assert archive.read("palo_alto_config.set").strip()
        report = json.loads(archive.read("migration_report.json"))
        assert report["commands"] == plan["commands"]
        import yaml
        assert yaml.safe_load(archive.read("target_mapping.yaml")) == mapping


def test_vsys_only_mapping_renders_objects_and_keeps_policy_for_review():
    client = create_app({"TESTING": True}).test_client()
    preview_id = _preview(client)
    plan = client.post("/api/migrate", json={
        "preview_id": preview_id,
        "mapping": {"vdoms": {"root": {"vsys": "vsys1", "virtual_router": "default"}}},
    }).get_json()
    assert plan["plan_status"] == "PARTIAL"
    assert plan["commands"] > 0
    assert plan["counts"]["renderable"] > 0
    policies = [item for item in plan["report"]["items"] if item["source_kind"] == "policy"]
    assert policies and all(not item["renderable"] for item in policies)
    response = client.post("/api/migration/bundle", json={"artifact_id": plan["artifact_id"]})
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        commands = archive.read("palo_alto_config.set").decode()
        report = json.loads(archive.read("migration_report.json"))
    assert "allow-web" not in commands
    assert any(item["source_name"] == "allow-web" and not item["renderable"] for item in report["items"])


def test_deploy_rejects_empty_rendered_artifact_before_credentials():
    client = create_app({"TESTING": True}).test_client()
    preview_id = _preview(client)
    plan = client.post("/api/migrate", json={"preview_id": preview_id, "mapping": {}}).get_json()
    response = client.post("/api/deploy", json={"artifact_id": plan["artifact_id"]})
    assert response.status_code == 400
    assert "no renderable commands" in response.get_json()["error"]


def test_terraform_endpoints_are_removed():
    client = create_app({"TESTING": True}).test_client()
    for path in (
        "/api/terraform/prepare",
        "/api/terraform/plan",
        "/api/terraform/approve",
        "/api/terraform/apply/stream",
        "/api/terraform/destroy/stream",
        "/api/download/state",
        "/api/download/package",
    ):
        assert client.post(path).status_code == 404


def test_migration_workflow_uses_planning_terminology():
    client = create_app({"TESTING": True}).test_client()
    response = client.get("/")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Plan migration" in html
    assert "Planned PAN-OS configuration" in html
    assert "Live migration" in html
    assert "Convert config" not in html
    assert "Convert configuration" not in html
    assert "Target configuration" not in html
