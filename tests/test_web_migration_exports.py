import io
import json
import zipfile
from types import SimpleNamespace
from fwmigrate.web import _deployment_validation_feedback, create_app
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
    assert payload["target_device_metadata"][0]["name"] == "integrated-fw"
    assert payload["target_evidence"]["vendor"] == "palo_alto"
    decisions = {(item["source_name"], item["target_field"]): item for item in payload["decisions"]["decisions"]}
    lan = decisions[("lan", "target_interface")]
    assert lan["suggested_value"] == "ethernet1/1"
    assert lan["mode"] == "SUGGESTED"
    assert lan["review_state"] == "PENDING"
    assert lan["evidence_source"] == "TARGET"
    assert lan["evidence_type"] == "TARGET_INTERFACE_ADDRESS"
    assert payload["decision_evidence"][lan["key"]] == "TARGET"
    assert payload["evidence_summary"]["target_backed"] >= 1
    suggested_candidate = next(item for item in payload["decision_candidates"][lan["key"]]
                               if item["value"] == lan["suggested_value"])
    assert suggested_candidate["class"] == "STRONG"
    assert "source_ip" in payload["decision_context"][lan["key"]]
    assert "decision_candidates" not in payload["decision_document"]
    assert set(payload["review_summary"]) == {"auto_resolved", "ready_to_confirm", "choose_candidate", "needs_input", "conflicts", "confirmed"}
    lan_group = next(item for item in payload["review_groups"] if item["source_name"] == "lan")
    assert {item["target_field"] for item in lan_group["decisions"]} >= {"target_interface", "target_zone"}
    assert lan_group["queue"] in {"READY_TO_CONFIRM", "CHOOSE_CANDIDATE", "NEEDS_INPUT"}
    assert decisions[("root", "vsys")]["suggested_value"] == "vsys1"
    assert decisions[("root", "virtual_router")]["suggested_value"] == "vr-main"


def test_target_intent_import_export_and_bulk_approval_recheck_current_evidence():
    client = create_app({"TESTING": True}).test_client()
    source_preview, target_preview = _preview(client), _target_preview(client)
    requirements = client.post("/api/migration/requirements", json={
        "preview_id": source_preview, "target_preview_id": target_preview,
    }).get_json()
    imported = client.post("/api/migration/target-intent/import", json={
        "preview_id": source_preview, "decision_document": requirements["decision_document"],
        "yaml": "interfaces:\n  lan: ethernet1/1\n",
    })
    assert imported.status_code == 200
    imported_document = imported.get_json()["decision_document"]
    lan = next(item for item in imported_document["decisions"]
               if item["source_kind"] == "interface" and item["source_name"] == "lan"
               and item["target_field"] == "target_interface")
    assert lan["review_state"] == "CONFIRMED" and lan["value"] == "ethernet1/1"
    exported = client.post("/api/migration/target-intent/export", json={
        "preview_id": source_preview, "decision_document": imported_document,
    })
    assert exported.status_code == 200
    assert "lan: ethernet1/1" in exported.get_json()["yaml"]

    safe_keys = [key for key, item in requirements["auto_decisions"].items()
                 if item["status"] in {"VERIFIED", "DERIVED"}]
    assert safe_keys
    approved = client.post("/api/migration/decisions/approve", json={
        "preview_id": source_preview, "decision_document": requirements["decision_document"],
        "decision_keys": safe_keys, "target_preview_id": target_preview,
    })
    assert approved.status_code == 200
    assert approved.get_json()["approved_count"] == len(safe_keys)
    approved_items = {item["key"]: item for item in approved.get_json()["decisions"]["decisions"]}
    assert all(approved_items[key]["review_state"] == "CONFIRMED" for key in safe_keys)

    manual_key = next(key for key, item in requirements["auto_decisions"].items()
                      if item["status"] == "MANUAL")
    rejected = client.post("/api/migration/decisions/approve", json={
        "preview_id": source_preview, "decision_document": requirements["decision_document"],
        "decision_keys": [manual_key], "target_preview_id": target_preview,
    })
    assert rejected.status_code == 400


def test_fixed_point_automation_requires_opt_in_policies_and_records_engineer_provenance():
    client = create_app({"TESTING": True}).test_client()
    source_preview, target_preview = _preview(client), _target_preview(client)
    requirements = client.post("/api/migration/requirements", json={
        "preview_id": source_preview, "target_preview_id": target_preview,
    }).get_json()
    request = {"preview_id": source_preview, "target_preview_id": target_preview,
               "decision_document": requirements["decision_document"]}

    disabled = client.post("/api/migration/automation/run", json=request)
    assert disabled.status_code == 200
    assert disabled.get_json()["audit"] == []
    assert not any(item["review_state"] == "CONFIRMED"
                   for item in disabled.get_json()["decisions"]["decisions"])

    enabled = client.post("/api/migration/automation/run", json={**request, "enabled_policies": [
        "AUTO_APPLY_VERIFIED", "AUTO_APPLY_DERIVED",
    ]})
    assert enabled.status_code == 200
    payload = enabled.get_json()
    assert payload["stable"] is True
    assert payload["audit"]
    confirmed = [item for item in payload["decisions"]["decisions"] if item["review_state"] == "CONFIRMED"]
    assert confirmed
    assert all(item["evidence_source"] == "ENGINEER"
               and item["evidence_type"] == "ENGINEER_AUTOMATION_POLICY" for item in confirmed)
    rejected = client.post("/api/migration/automation/run", json={**request, "enabled_policies": ["AUTO_APPLY_CANDIDATE"]})
    assert rejected.status_code == 400


def test_source_only_requirements_show_facts_and_next_action_without_candidates():
    client = create_app({"TESTING": True}).test_client()
    source_preview = _preview(client)
    payload = client.post("/api/migration/requirements", json={"preview_id": source_preview}).get_json()
    decision = next(item for item in payload["decisions"]["decisions"]
                    if item["source_kind"] == "interface" and item["target_field"] == "target_interface")
    assert payload["decision_candidates"] == {}
    context = payload["decision_context"][decision["key"]]
    assert context["affected_count"] >= 0
    assert context["next_action"].startswith("Upload PAN-OS target XML")


def test_zone_rule_applies_only_requested_related_decisions_and_confirms_them():
    client = create_app({"TESTING": True}).test_client()
    preview_id = _preview(client)
    requirements = client.post("/api/migration/requirements", json={"preview_id": preview_id}).get_json()
    document = requirements["decision_document"]
    zone = next(item for item in document["decisions"]
                if item["source_kind"] == "zone" and item["source_name"] == "trust" and item["target_field"] == "target_zone")
    zone.update(value="TRUST", review_state="CONFIRMED")
    member = next(item for item in document["decisions"]
                  if item["source_kind"] == "interface" and item["source_name"] == "lan" and item["target_field"] == "target_zone")
    response = client.post("/api/migration/rules/apply", json={
        "preview_id": preview_id, "decision_document": document,
        "rule_type": "APPLY_ZONE_TO_MEMBERS", "source_key": zone["key"],
        "value": "TRUST", "apply_to": [member["key"]],
    })
    assert response.status_code == 200
    updated = next(item for item in response.get_json()["decision_document"]["decisions"] if item["key"] == member["key"])
    assert updated["value"] == "TRUST" and updated["review_state"] == "CONFIRMED"
    assert updated["evidence_type"] == "ENGINEER_ZONE_TO_MEMBERS"

    unrelated = client.post("/api/migration/rules/apply", json={
        "preview_id": preview_id, "decision_document": document,
        "rule_type": "APPLY_ZONE_TO_MEMBERS", "source_key": zone["key"],
        "value": "TRUST", "apply_to": ['["blue","interface","lan","target_zone"]'],
    })
    assert unrelated.status_code == 400


def test_changed_target_evidence_restores_decisions_and_reports_staleness():
    client = create_app({"TESTING": True}).test_client()
    source_preview = _preview(client)
    first_target = _target_preview(client)
    first = client.post("/api/migration/requirements", json={
        "preview_id": source_preview,
        "target_preview_id": first_target,
    }).get_json()
    document = first["decision_document"]
    decision = next(item for item in document["decisions"]
                    if item["source_kind"] == "vdom" and item["target_field"] == "vsys")
    decision.update(value="vsys1", review_state="CONFIRMED")

    second_target_response = client.post("/api/preview", data={
        "source_vendor": "palo_alto",
        "file": (io.BytesIO(PANOS_TARGET_FIXTURE.read_bytes() + b"\n"), "changed-target.xml"),
    }, content_type="multipart/form-data")
    assert second_target_response.status_code == 200
    second_target = second_target_response.get_json()["preview_id"]
    second = client.post("/api/migration/requirements", json={
        "preview_id": source_preview,
        "target_preview_id": second_target,
        "decision_document": document,
    })
    assert second.status_code == 200
    payload = second.get_json()
    restored = next(item for item in payload["decisions"]["decisions"]
                    if item["source_kind"] == "vdom" and item["target_field"] == "vsys")
    assert restored["value"] == "vsys1"
    assert restored["review_state"] == "CONFIRMED"
    assert payload["target_evidence_changed"] is True

    migration = client.post("/api/migrate", json={
        "preview_id": source_preview,
        "decision_document": document,
        "target_preview_id": second_target,
        "target_device": "integrated-fw",
    })
    assert migration.status_code == 200
    migrated = migration.get_json()
    assert migrated["target_evidence_changed"] is True
    assert migrated["report"]["review"]["target_evidence_changed"] is True


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

    legacy = json.loads(json.dumps(saved))
    legacy["format_version"] = 1
    accepted = client.post("/api/migration/decisions/import", json={
        "preview_id": preview_id, "document": legacy,
    })
    assert accepted.status_code == 200


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
        assert decisions["format_version"] == 2
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


def test_candidate_validation_failure_maps_to_rendered_migration_item_when_unique():
    rendered = SimpleNamespace(report={"items": [{"source_vdom": "root", "source_kind": "service",
        "source_name": "web-https", "target_name": "web-https", "decision_keys": ["decision-1"], "commands": [
            "set vsys vsys1 service web-https protocol tcp port 443"]}]})
    document = {"decisions": [{"source_vdom": "root", "source_name": "web-https", "key": "decision-1"},
                              {"source_vdom": "root", "source_name": "web-https", "key": "wrong-kind-decision"}]}
    validation = SimpleNamespace(status="FAILED", response="validation error: service web-https is invalid")
    feedback = _deployment_validation_feedback(rendered, document, validation)
    assert feedback["mapping_status"] == "MAPPED"
    assert feedback["migration_items"][0]["decision_keys"] == ["decision-1"]
    assert feedback["migration_items"][0]["generated_commands"][0].endswith("port 443")


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
    assert 'id="migration-recommendation-fields"' in html
    assert "Confirm all mapping suggestions" in html
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


def test_migration_recommendations_are_review_only_and_reported():
    client = create_app({"TESTING": True}).test_client()
    fixture = Path(__file__).parent / "fixtures" / "fortigate" / "identity_authentication_full.conf"
    preview = client.post("/api/preview", data={
        "file": (io.BytesIO(fixture.read_bytes()), fixture.name),
    }, content_type="multipart/form-data").get_json()["preview_id"]

    requirements = client.post("/api/migration/requirements", json={"preview_id": preview}).get_json()
    assert requirements["recommendations"]
    assert any(item["family"] == "Users/Admin" for item in requirements["recommendations"])
    assert all("review_state" not in item and "planner_value" not in item for item in requirements["recommendations"])

    plan = client.post("/api/migrate", json={"preview_id": preview, "mapping": {}}).get_json()
    assert plan["recommendations"] == plan["report"]["review"]["recommendations"]
