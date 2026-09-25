import io
import json
import zipfile
from fwmigrate.web import create_app
from tests.fixture_paths import CISCO_ASA_FIXTURE
from pathlib import Path

MIGRATION_FIXTURE = Path(__file__).parent / "fixtures" / "fortigate" / "palo_alto_mvp.conf"
PANOS_TARGET_FIXTURE = Path(__file__).parent / "fixtures" / "palo_alto" / "integrated_firewall.xml"


def _preview(client):
    response = client.post("/api/preview", data={"file": (io.BytesIO(MIGRATION_FIXTURE.read_bytes()), MIGRATION_FIXTURE.name)}, content_type="multipart/form-data")
    assert response.status_code == 200
    return response.get_json()["preview_id"]


def _target_preview(client):
    response = client.post("/api/preview", data={
        "source_vendor": "palo_alto",
        "file": (io.BytesIO(PANOS_TARGET_FIXTURE.read_bytes()), PANOS_TARGET_FIXTURE.name),
    }, content_type="multipart/form-data")
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


def test_target_preview_adds_pending_evidence_based_suggestions():
    client = create_app({"TESTING": True}).test_client()
    source_preview = _preview(client)
    target_preview = _target_preview(client)
    response = client.post("/api/migration/requirements", json={
        "preview_id": source_preview,
        "target_preview_id": target_preview,
    })
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["target_devices"] == ["integrated-fw"]
    decisions = {(item["source_name"], item["target_field"]): item for item in payload["decisions"]["decisions"]}
    lan = decisions[("lan", "target_interface")]
    assert lan["suggested_value"] == "ethernet1/1"
    assert lan["mode"] == "SUGGESTED"
    assert lan["review_state"] == "PENDING"
    assert decisions[("root", "vsys")]["suggested_value"] == "vsys1"
    assert decisions[("root", "virtual_router")]["suggested_value"] == "vr-main"


def test_target_preview_rejects_wrong_vendor_preview():
    client = create_app({"TESTING": True}).test_client()
    source_preview = _preview(client)
    response = client.post("/api/migration/requirements", json={
        "preview_id": source_preview,
        "target_preview_id": source_preview,
    })
    assert response.status_code == 400
    assert "PAN-OS target" in response.get_json()["error"]


def test_decision_documents_round_trip_confirmed_values_and_reject_other_sources():
    client = create_app({"TESTING": True}).test_client()
    preview_id = _preview(client)
    requirements = client.post("/api/migration/requirements", json={"preview_id": preview_id}).get_json()
    document = requirements["decision_document"]
    assert requirements["decisions"]["decisions"]

    mapping = {
        "vdoms": {"root": {"vsys": "vsys1", "virtual_router": "vr-production"}},
        "interfaces": {"root": {
            "lan": {"target_interface": "ethernet1/1", "target_zone": "trust"},
            "wan": {"target_interface": "ethernet1/2", "target_zone": "untrust"},
            "trust": {"target_zone": "trust"},
            "untrust": {"target_zone": "untrust"},
        }},
    }
    for decision in document["decisions"]:
        value = (mapping.get("vdoms", {}).get(decision["source_vdom"], {}).get(decision["target_field"])
                 if decision["source_kind"] == "vdom" else
                 mapping.get("interfaces", {}).get(decision["source_vdom"], {}).get(decision["source_name"], {}).get(decision["target_field"]))
        if value is not None:
            decision["value"] = value
            decision["review_state"] = "CONFIRMED"

    planned = client.post("/api/migrate", json={
        "preview_id": preview_id, "decision_document": document,
    })
    assert planned.status_code == 200
    assert planned.get_json()["commands"] > 0

    # Same-named interfaces in different VDOMs remain distinct decision identities.
    from fwmigrate.conversion.fortigate_to_palo_alto import PANDecisionReviewState, PANMigrationDecision
    document["decisions"].append(PANMigrationDecision(
        "blue", "interface", "port1", "target_zone", value="dmz",
        review_state=PANDecisionReviewState.CONFIRMED,
    ).to_dict())
    exported = client.post("/api/migration/decisions/export", json={
        "preview_id": preview_id, "decision_document": document,
    })
    assert exported.status_code == 200
    saved = exported.get_json()["document"]
    imported = client.post("/api/migration/decisions/import", json={
        "preview_id": preview_id, "document": saved,
    })
    assert imported.status_code == 200
    restored = imported.get_json()
    assert restored["decision_document"] == saved
    assert restored["mapping"]["vdoms"]["root"]["virtual_router"] == "vr-production"
    assert restored["mapping"]["interfaces"]["root"]["lan"]["target_interface"] == "ethernet1/1"
    assert restored["mapping"]["interfaces"]["blue"]["port1"]["target_zone"] == "dmz"

    malformed = json.loads(json.dumps(saved))
    malformed["decisions"][0].pop("key", None)
    malformed["decisions"][0]["target_field"] = "unknown"
    rejected = client.post("/api/migration/decisions/import", json={
        "preview_id": preview_id, "document": malformed,
    })
    assert rejected.status_code == 400

    changed_source = client.post("/api/preview", data={
        "file": (io.BytesIO(MIGRATION_FIXTURE.read_bytes() + b"\n# source digest change\n"), MIGRATION_FIXTURE.name),
    }, content_type="multipart/form-data").get_json()["preview_id"]
    mismatch = client.post("/api/migration/decisions/import", json={
        "preview_id": changed_source, "document": saved,
    })
    assert mismatch.status_code == 400
    assert "different source" in mismatch.get_json()["error"]


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
        assert set(archive.namelist()) == {"palo_alto_config.set", "migration_report.json", "migration_decisions.json", "target_mapping.yaml", "source_inventory.xlsx"}
        assert archive.read("palo_alto_config.set").strip()
        report = json.loads(archive.read("migration_report.json"))
        decisions = json.loads(archive.read("migration_decisions.json"))
        assert report["commands"] == plan["commands"]
        assert decisions["format_version"] == 1
        assert decisions["source_vendor"] == "fortigate"
        root_vsys = next(item for item in decisions["decisions"] if item["source_kind"] == "vdom" and item["target_field"] == "vsys")
        assert root_vsys["value"] == "vsys1"
        assert root_vsys["review_state"] == "CONFIRMED"
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
    assert "Migration review" in html
    assert 'id="mapping-filter"' in html and 'id="decision-pending-only"' in html
    assert 'id="decision-select-visible"' in html and 'id="decision-clear-selection"' in html
    assert 'id="decision-set-selected"' in html and 'id="decision-use-suggestion"' in html
    assert 'id="migration-plan-items"' in html and 'id="migration-plan-filter"' in html
    assert 'id="migration-command-preview"' in html and 'id="migration-copy-commands"' in html
    assert html.index('id="migration-mapping"') < html.index('id="migration-build"') < html.index('id="migration-plan"')
    assert 'class="card output-card hidden" id="migration-build"' in html
    assert 'class="export-steps hidden" id="migration-export"' in html
    assert "Download .set" in html and "Download bundle" in html
    assert "Plan migration is under development." not in html
    assert "Configuration Report" in html
    assert "Planned PAN-OS configuration" in html
    assert "Live migration" in html
    assert "FIREWALL OPERATIONS" not in html
    assert "START HERE" not in html
    assert 'id="source-card-description"' not in html
    assert 'class="file-ready"' not in html
    assert 'id="report-filename"' not in html
    assert html.count('id="report-detail-modal"') == 1
    assert 'class="report-detail-modal hidden"' in html
    assert 'role="dialog" aria-modal="true" aria-labelledby="report-detail-title"' in html
    assert 'id="report-detail-close"' in html and 'id="report-detail-body"' in html
    assert 'id="report-detail-panel"' not in html
    assert html.count('id="report-summary"') == 1
    assert "Download Excel" in html
    assert "Push candidate" in html
    assert "Validate candidate" in html
    assert "Activity log" in html
    assert "Execution log" not in html
    assert 'id="tab-extract"' not in html
    assert 'id="mode-extract-form"' not in html
    assert html.count('id="btn-extract-excel"') == 1
    report_start = html.index('id="report-container"')
    report_end = html.index("</section>", report_start)
    assert report_start < html.index('id="btn-extract-excel"') < report_end
    assert 'id="validation-groups-heading">Issue groups</h3>' in html
    assert "Select an issue group to filter the findings below." in html
    assert 'id="validation-details-heading"' in html and "Validation details" in html
    assert 'id="validation-filter-clear"' in html and ">Clear</button>" in html
    assert "Your source inventory" not in html
    assert "Convert config" not in html
    assert "Convert configuration" not in html
    assert "Target configuration" not in html
