from copy import deepcopy
import hashlib
import io
import json
import zipfile

import pytest
from click.testing import CliRunner

import fwmigrate.main as migration_cli
from fwmigrate.conversion.workflow_registry import MigrationWorkflowRegistration, MigrationWorkflowRegistry
from fwmigrate.main import cli
from fwmigrate.web import create_app
from fwmigrate.web_support.artifact_signing import sign_envelope
from tests.conversion.palo_alto_to_fortigate.conftest import SOURCE, options as mapping_fixture


PREFIX = "/api/migration/palo_alto_to_fortigate"
KEY = b"r" * 32


@pytest.fixture
def setup_reverse():
    from fwmigrate.source_reporting import source_reporters

    analysis = source_reporters.get("palo_alto").analyze_source(SOURCE)
    options = mapping_fixture.__wrapped__(analysis)
    client = create_app({"TESTING": True, "WEB_MODE": "local", "WORKSPACE_SIGNING_KEY": KEY, "API_RATE_LIMIT_PER_MINUTE": 10000}).test_client()
    return client, {"source": {"vendor": "palo_alto", "source_text": SOURCE}, "options": options}


def approved_artifact(client, payload):
    response = client.post(PREFIX + "/design/prepare", json=payload)
    assert response.status_code == 200, response.get_json()
    draft = response.get_json()["draft"]
    selected = [r["key"] for r in draft["configuration"] if r["family"] == "policy"]
    response = client.post(PREFIX + "/design/approve", json={**payload, "draft": draft, "selected_items": selected})
    assert response.status_code == 200, response.get_json()
    approval = response.get_json()["approval"]
    response = client.post(PREFIX + "/build", json={**payload, "approval": approval})
    assert response.status_code == 200, response.get_json()
    return response.get_json()["artifact"], approval


def test_web_approval_preview_download_bundle_share_exact_bytes(setup_reverse):
    client, payload = setup_reverse
    artifact, _ = approved_artifact(client, payload)
    preview = client.post(PREFIX + "/command-preview", json={"artifact": artifact})
    commands = client.post(PREFIX + "/commands", json={"artifact": artifact})
    bundle = client.post(PREFIX + "/bundle", json={"artifact": artifact, "source": payload["source"]})
    assert preview.status_code == commands.status_code == bundle.status_code == 200
    assert "attachment" in commands.headers["Content-Disposition"]
    assert "fortigate_config.conf" in commands.headers["Content-Disposition"]
    assert preview.get_json()["text"].encode() == commands.data
    assert hashlib.sha256(commands.data).hexdigest() == artifact["command_sha256"]
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        assert archive.read("fortigate_config.conf") == commands.data
        assert archive.read("source_inventory.xlsx").startswith(b"PK")
        assert json.loads(archive.read("migration_decisions.json"))["source_vendor"] == "palo_alto"


def test_proposal_first_api_approval_bundle_and_cli_use_one_resolved_design(setup_reverse, tmp_path):
    import yaml

    client, payload = setup_reverse
    payload["options"] = {"profile": {"ports": ["port1", "port2"]}}
    review_response = client.post(PREFIX + "/design/prepare", json=payload)
    assert review_response.status_code == 200
    review = review_response.get_json()
    assert review["resolved_options"]["vdom"] == "root"
    assert review["resolved_options"]["zones"] == {"trust": "trust", "untrust": "untrust"}
    assert review["effective_values"][0]["field"] == "schedule"
    assert review["draft"]["context"]["requested_options"]["interfaces"] == {}
    assert all(row["review_state"] == "PENDING" for row in review["proposals"])
    artifact, _ = approved_artifact(client, payload)
    assert "config firewall policy" in artifact["commands"]
    assert artifact["report"]["target_proposals"] == review["proposals"]
    command_bytes = client.post(PREFIX + "/commands", json={"artifact": artifact}).data
    preview = client.post(PREFIX + "/command-preview", json={"artifact": artifact}).get_json()
    assert preview["text"].encode() == command_bytes
    response = client.post(PREFIX + "/bundle", json={"artifact": artifact, "source": payload["source"]})
    assert response.status_code == 200
    with zipfile.ZipFile(io.BytesIO(response.data)) as archive:
        assert archive.read("fortigate_config.conf") == command_bytes
        mapping_text = archive.read("target_mapping.yaml").decode()
        assert yaml.safe_load(mapping_text) == review["resolved_options"]
        report = json.loads(archive.read("migration_report.json"))
        assert report["effective_values"] == review["effective_values"]
    source, mapping, output = tmp_path / "panos.xml", tmp_path / "mapping.yaml", tmp_path / "output"
    source.write_text(SOURCE, encoding="utf-8")
    mapping.write_text(mapping_text, encoding="utf-8")
    result = CliRunner().invoke(cli, ["migrate", "-i", str(source), "-o", str(output), "--source-vendor", "palo_alto", "--target-vendor", "fortigate", "--format", "cli", "--zone-map", str(mapping)])
    assert result.exit_code == 0, result.output
    assert (output / "fortigate_config.conf").read_bytes() == command_bytes
    exported = client.post(PREFIX + "/decisions/export", json=payload).get_json()["document"]
    assert exported["options"] == review["resolved_options"]
    restored = client.post(PREFIX + "/decisions/import", json={"source": payload["source"], "document": {**exported, "approval": artifact["design_approval"]}}).get_json()
    assert restored["options"] == review["resolved_options"]
    assert "approval" not in restored


def test_client_proposal_labels_cannot_change_server_resolution(setup_reverse):
    client, payload = setup_reverse
    payload["options"] = {"profile": {"ports": ["port1", "port2"]}}
    payload["resolved_options"] = {"vdom": "forged"}
    payload["effective_values"] = [{"field": "disabled", "value": "no", "origin": "AUTO"}]
    review = client.post(PREFIX + "/design/prepare", json=payload).get_json()
    assert review["resolved_options"]["vdom"] == "root"
    assert all(row["field"] != "disabled" for row in review["effective_values"])


@pytest.mark.parametrize("change", ["unsigned", "options", "source", "expired", "cross_pair", "items"])
def test_web_build_rejects_forged_stale_or_wrong_pair_approval(setup_reverse, change):
    client, payload = setup_reverse
    _, approval = approved_artifact(client, payload)
    payload = deepcopy(payload)
    if change == "unsigned":
        approval.pop("signature")
    elif change == "options":
        payload["options"]["interfaces"]["ethernet1/1"] = "port3"
    elif change == "source":
        payload["source"]["source_text"] = SOURCE.replace("10.0.0.0/24", "10.1.0.0/24")
    else:
        if change == "expired":
            approval["expires_at"] = 0
        elif change == "cross_pair":
            approval["envelope_type"] = "pan_design_approval"
        else:
            approval["configuration"] = {}
        approval = sign_envelope(approval, KEY)
    response = client.post(PREFIX + "/build", json={**payload, "approval": approval})
    assert response.status_code == 400
    assert "artifact" not in response.get_json()


def test_web_never_accepts_client_commands_or_unapproved_artifacts(setup_reverse):
    client, payload = setup_reverse
    assert client.post(PREFIX + "/build", json={**payload, "commands": ["config firewall policy"]}).status_code == 400
    artifact, _ = approved_artifact(client, payload)
    artifact["commands"].append("end")
    assert client.post(PREFIX + "/commands", json={"artifact": artifact}).status_code == 400
    artifact, _ = approved_artifact(client, payload)
    artifact.pop("signature")
    assert client.post(PREFIX + "/commands", json={"artifact": artifact}).status_code == 400


@pytest.mark.parametrize("endpoint", ["/api/deploy", "/api/inspect-candidate", "/api/validate-candidate", "/api/commit"])
def test_reverse_artifact_never_reaches_panos_device_transport(setup_reverse, monkeypatch, endpoint):
    import fwmigrate.web as web

    client, payload = setup_reverse
    artifact, _ = approved_artifact(client, payload)
    monkeypatch.setattr(web, "PANSSHDeployer", lambda *_: pytest.fail("Reverse artifact must not connect"))
    response = client.post(endpoint, json={"artifact": artifact, "host": "fw", "port": 22, "username": "admin", "password": "secret", "deployment_session_id": "forged"})
    assert response.status_code in {400, 409}


def test_mapping_import_requires_pair_and_source_and_drops_approval(setup_reverse):
    client, payload = setup_reverse
    document = client.post(PREFIX + "/decisions/export", json=payload).get_json()["document"]
    document["design_approval"] = {"signature": "forged"}
    imported = client.post(PREFIX + "/decisions/import", json={**payload, "document": document})
    assert imported.status_code == 200
    assert "approval" not in imported.get_json()
    document["target_vendor"] = "palo_alto"
    assert client.post(PREFIX + "/decisions/import", json={**payload, "document": document}).status_code == 400


def test_target_context_change_revokes_approval(setup_reverse):
    client, payload = setup_reverse
    _, approval = approved_artifact(client, payload)
    changed = {**payload, "target_source": {"vendor": "fortigate", "source_text": "config firewall address\nend\n"}, "approval": approval}
    assert client.post(PREFIX + "/build", json=changed).status_code == 400


def test_reverse_cli_exports_same_native_format_and_report(setup_reverse, tmp_path):
    _, payload = setup_reverse
    source, mapping, output = tmp_path / "source.xml", tmp_path / "mapping.yaml", tmp_path / "output"
    source.write_text(SOURCE, encoding="utf-8")
    mapping.write_text(json.dumps(payload["options"]), encoding="utf-8")
    result = CliRunner().invoke(cli, ["migrate", "-i", str(source), "-o", str(output), "--source-vendor", "palo_alto", "--target-vendor", "fortigate", "--format", "cli", "--zone-map", str(mapping)])
    assert result.exit_code == 0, result.output
    commands = (output / "fortigate_config.conf").read_bytes()
    assert b"config firewall policy" in commands
    assert json.loads((output / "migration_report.json").read_text())["command_sha256"] == hashlib.sha256(commands).hexdigest()


def test_new_pair_cli_dispatches_to_pair_owned_application(tmp_path, monkeypatch):
    source, output = tmp_path / "source.conf", tmp_path / "output"
    source.write_text("config firewall address\nend\n", encoding="utf-8")
    received = {}

    def export(**kwargs):
        received.update(kwargs)

    workflows = MigrationWorkflowRegistry()
    workflows.register(MigrationWorkflowRegistration(
        pair_id="fortigate_to_juniper_srx",
        source_vendor="fortigate",
        target_vendor="juniper_srx",
        display_name="FortiGate to Juniper SRX",
        api_prefix="/api/migration/fortigate_to_juniper_srx",
        supported_formats=("set",),
        export_available=True,
        destination_aware_available=False,
        deployment_available=False,
        cli_application=export,
    ))
    monkeypatch.setattr(migration_cli, "migration_workflows", workflows)

    result = CliRunner().invoke(cli, [
        "migrate", "-i", str(source), "-o", str(output),
        "--source-vendor", "FortiGate", "--target-vendor", "Juniper_SRX",
    ])

    assert result.exit_code == 0, result.output
    assert received == {
        "input_path": str(source),
        "output_path": str(output),
        "format": "set",
        "mapping_path": None,
        "target_config_path": None,
    }


@pytest.mark.parametrize("option", ["--target-device", "--target-intent", "--automation-mode"])
def test_new_pair_cli_rejects_explicit_pan_only_options(option, tmp_path, monkeypatch):
    source = tmp_path / "source.conf"
    source.write_text("config firewall address\nend\n", encoding="utf-8")
    workflows = MigrationWorkflowRegistry()
    workflows.register(MigrationWorkflowRegistration(
        pair_id="fortigate_to_juniper_srx",
        source_vendor="fortigate",
        target_vendor="juniper_srx",
        display_name="FortiGate to Juniper SRX",
        api_prefix="/api/migration/fortigate_to_juniper_srx",
        supported_formats=("set",),
        export_available=True,
        destination_aware_available=False,
        deployment_available=False,
        cli_application=lambda **_kwargs: pytest.fail("PAN-only option reached pair application"),
    ))
    monkeypatch.setattr(migration_cli, "migration_workflows", workflows)
    args = [
        "migrate", "-i", str(source), "-o", str(tmp_path / "output"),
        "--source-vendor", "fortigate", "--target-vendor", "juniper_srx", option,
    ]
    if option == "--target-device":
        args.append("serial")
    elif option == "--target-intent":
        intent = tmp_path / "intent.yaml"
        intent.write_text("{}", encoding="utf-8")
        args[-1] = str(intent)
        args.insert(-1, option)
    elif option == "--automation-mode":
        args.append("VERIFIED_AND_DERIVED")

    result = CliRunner().invoke(cli, args)

    assert result.exit_code != 0
    assert "PAN-OS-specific" in result.output


def test_invalid_api_payloads_are_rejected_without_server_errors(setup_reverse):
    client, payload = setup_reverse
    for value in (None, [], {**payload, "options": {"interfaces": []}}, {**payload, "options": {"profile": {"password": "do-not-echo"}}}):
        response = client.post(PREFIX + "/design/prepare", json=value)
        assert response.status_code == 400
        assert b"do-not-echo" not in response.data


def test_source_secrets_never_enter_draft_commands_report_or_workbook(setup_reverse):
    from fwmigrate.source_reporting import source_reporters

    client, payload = setup_reverse
    seed = 'fake-password-hash-must-not-export'
    text = SOURCE.replace('<address>', '<local-user-database><user><entry name="operator"><phash>' + seed + '</phash></entry></user></local-user-database><address>', 1)
    analysis = source_reporters.get('palo_alto').analyze_source(text)
    payload = {'source': {'vendor': 'palo_alto', 'source_text': text}, 'options': mapping_fixture.__wrapped__(analysis)}
    prepared = client.post(PREFIX + '/design/prepare', json=payload)
    assert prepared.status_code == 200
    assert seed.encode() not in prepared.data
    artifact, _ = approved_artifact(client, payload)
    assert seed not in json.dumps(artifact)
    bundle = client.post(PREFIX + '/bundle', json={**payload, 'artifact': artifact})
    assert bundle.status_code == 200
    with zipfile.ZipFile(io.BytesIO(bundle.data)) as archive:
        for name in archive.namelist():
            content = archive.read(name)
            if name.endswith('.xlsx'):
                with zipfile.ZipFile(io.BytesIO(content)) as workbook:
                    assert all(seed.encode() not in workbook.read(part) for part in workbook.namelist())
            else:
                assert seed.encode() not in content
