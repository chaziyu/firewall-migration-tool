"""Transport for reviewed FortiGate to Check Point offline artifacts."""

import io
import json
import zipfile

import yaml
from flask import Response, jsonify, request, send_file

from fwmigrate.conversion.fortigate_to_checkpoint.application import (
    BINDINGS_FILE, COMMANDS_FILE, GAIA_FILE, MANAGEMENT_FILE, approve_design, build_artifact,
    build_review, export_decisions, import_decisions, verify_export_artifact, source_vdoms,
)
from fwmigrate.collection.snapshot import parse_snapshot
from fwmigrate.source_reporting import source_reporters
from fwmigrate.web_support.artifact_signing import sign_envelope, verify_envelope
from fwmigrate.web_support.request_source import analyze_request_source, _require_complete_collection


def register_fortigate_to_checkpoint_routes(app, signing_key):
    prefix = "/api/migration/fortigate_to_checkpoint"
    file_names = {
        "management-operations": (MANAGEMENT_FILE, "application/json"),
        "gaia-config": (GAIA_FILE, "text/plain"),
        "bindings": (BINDINGS_FILE, "application/json"),
        "management-commands": (COMMANDS_FILE, "text/plain"),
    }

    def source_entry(payload):
        entry = analyze_request_source(payload, "fortigate")
        _require_complete_collection(entry)
        return entry

    def target_evidence(payload):
        if payload.get("target_source") is None and not request.files.get("target_file"):
            if payload.get("target_metadata") is not None:
                raise ValueError("Target metadata requires a destination snapshot")
            return {}
        entry = analyze_request_source(payload, "checkpoint", target=True)
        _require_complete_collection(entry)
        text = entry.evidence.get("source_text") if isinstance(entry.evidence, dict) else None
        if not isinstance(text, str):
            text = parse_snapshot(json.dumps(entry.evidence).encode("utf-8")).source_text
        return {"target": entry.analysis, "target_source_text": text,
                "target_metadata": payload.get("target_metadata")}

    def approved_artifact(payload, entry):
        artifact = verify_export_artifact(verify_envelope(payload.get("artifact"), signing_key))
        if artifact.get("source_digest") != entry.source_digest:
            raise ValueError("Check Point artifact belongs to a different source")
        return artifact

    def client_options(review):
        return {key: value if value is not None else "" for key, value in review["options"].to_dict().items()}

    def handle(action):
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError("A JSON object is required")
            if action in {"artifact-preview", "management-operations", "management-commands", "gaia-config", "bindings", "bundle"}:
                entry = source_entry(payload)
                artifact = approved_artifact(payload, entry)
                if action == "artifact-preview":
                    return jsonify({"success": True,
                                    "files": {name: {"text": row["content"],
                                                     "sha256": row["sha256"],
                                                     "byte_count": row["byte_count"]}
                                               for name, row in artifact["files"].items()},
                                    "report": artifact["report"]})
                if action in file_names:
                    name, mimetype = file_names[action]
                    raw = artifact["files"][name]["content"].encode("utf-8")
                    return Response(raw, mimetype=mimetype,
                                    headers={"Content-Disposition": f'attachment; filename="{name}"'})
                bundle = io.BytesIO()
                with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name in artifact["files"]:
                        archive.writestr(name, artifact["files"][name]["content"].encode("utf-8"))
                    archive.writestr("migration_report.json",
                                     json.dumps(artifact["report"], ensure_ascii=False,
                                                sort_keys=True, indent=2) + "\n")
                    archive.writestr("migration_decisions.json", json.dumps(
                        export_decisions(artifact["source_digest"], artifact["options"]),
                        ensure_ascii=False, sort_keys=True, indent=2) + "\n")
                bundle.seek(0)
                return send_file(bundle, mimetype="application/zip", as_attachment=True,
                                 download_name="migration_fortigate_to_checkpoint.zip")

            entry = source_entry(payload)
            if action == "decisions/import":
                return jsonify({"success": True,
                                "options": import_decisions(payload.get("document"), entry.source_digest)})
            options = payload.get("options", {})
            if not isinstance(options, dict):
                raise ValueError("Check Point target mapping options must be an object")
            if action == "decisions/export":
                return jsonify({"success": True,
                                "document": export_decisions(entry.source_digest, options)})
            destination = target_evidence(payload)
            review = build_review(entry.analysis, options, entry.source_digest, **destination)
            if action == "requirements":
                return jsonify({"success": True, "source_digest": entry.source_digest,
                                "options": client_options(review),
                                "source_vdoms": source_vdoms(entry.analysis.extracted.config),
                                "requirements": review["requirements"], "report": review["report"]})
            if action == "design/prepare":
                return jsonify({"success": True, "source_digest": entry.source_digest,
                                "options": client_options(review),
                                "source_vdoms": source_vdoms(entry.analysis.extracted.config),
                                "draft": sign_envelope(review["draft"], signing_key),
                                "requirements": review["requirements"], "report": review["report"]})
            if action == "design/approve":
                draft = verify_envelope(payload.get("draft"), signing_key)
                approval = approve_design(review, draft, payload.get("selected_items"))
                return jsonify({"success": True,
                                "approval": sign_envelope(approval, signing_key)})
            if action == "build":
                approval = verify_envelope(payload.get("approval"), signing_key)
                artifact = build_artifact(entry.analysis, options, entry.source_digest, approval, **destination)
                return jsonify({"success": True,
                                "artifact": sign_envelope(artifact, signing_key)})
            raise ValueError("Unsupported Check Point migration action")
        except (ValueError, TypeError, KeyError):
            return jsonify({"success": False,
                            "error": "Invalid, blocked or stale FortiGate to Check Point request. Check source scope, target mapping, approval, and dependencies."}), 400

    actions = ("requirements", "design/prepare", "design/approve", "build",
               "artifact-preview", "management-operations", "management-commands", "gaia-config", "bindings",
               "bundle", "decisions/import", "decisions/export")
    for action in actions:
        app.add_url_rule(f"{prefix}/{action}", "fg_checkpoint_migration_" + action.replace("/", "_"),
                         lambda action=action: handle(action), methods=["POST"])
