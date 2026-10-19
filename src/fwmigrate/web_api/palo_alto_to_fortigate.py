"""Transport for reviewed PAN-OS to FortiGate CLI exports; no device execution."""
import io
import json
import zipfile
import yaml

from flask import Response, jsonify, request, send_file

from fwmigrate.conversion.palo_alto_to_fortigate.application import (
    approve_design, build_artifact, build_review, export_decisions, import_decisions, verify_export_artifact,
)
from fwmigrate.source_reporting import source_reporters
from fwmigrate.web_support.artifact_signing import sign_envelope, verify_envelope
from fwmigrate.web_support.request_source import analyze_request_source, _require_complete_collection


def register_palo_alto_to_fortigate_routes(app, signing_key):
    prefix = "/api/migration/palo_alto_to_fortigate"

    def handle(action):
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError("A JSON object is required")
            if action in {"command-preview", "commands", "bundle"}:
                artifact = verify_export_artifact(verify_envelope(payload.get("artifact"), signing_key))
                command_text = "\n".join(artifact["commands"])
                if action == "command-preview":
                    return jsonify({"success": True, "text": command_text, "command_sha256": artifact["command_sha256"]})
                if action == "commands":
                    return Response(command_text.encode("utf-8"), mimetype="text/plain",
                                    headers={"Content-Disposition": 'attachment; filename="fortigate_config.conf"'})
                entry = analyze_request_source(payload, "palo_alto")
                _require_complete_collection(entry)
                if entry.source_digest != artifact["report"]["source_digest"]:
                    raise ValueError("Bundle source differs from the approved artifact")
                workbook, bundle = io.BytesIO(), io.BytesIO()
                source_reporters.get("palo_alto").export_excel(entry.analysis, workbook, source_name=entry.source_name)
                with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("fortigate_config.conf", command_text.encode())
                    archive.writestr("migration_report.json", json.dumps(artifact["report"], indent=2))
                    archive.writestr("migration_decisions.json", json.dumps(export_decisions(entry.source_digest, artifact["design_approval"]["context"]["options"]), indent=2))
                    archive.writestr("target_mapping.yaml", yaml.safe_dump(artifact["design_approval"]["context"]["options"], sort_keys=False))
                    archive.writestr("source_inventory.xlsx", workbook.getvalue())
                bundle.seek(0)
                return send_file(bundle, mimetype="application/zip", as_attachment=True, download_name="migration_palo_alto_to_fortigate.zip")

            entry = analyze_request_source(payload, "palo_alto")
            _require_complete_collection(entry)
            options = payload.get("options", {})
            if not isinstance(options, dict):
                raise ValueError("Target mapping options must be an object")
            if action == "decisions/import":
                return jsonify({"success": True, "options": import_decisions(payload.get("document"), entry.source_digest)})
            if action == "decisions/export":
                return jsonify({"success": True, "document": export_decisions(entry.source_digest, options)})
            target = None
            if payload.get("target_source") is not None:
                target = analyze_request_source(payload, "fortigate", target=True)
                _require_complete_collection(target)
            kwargs = {"target": target.analysis if target else None, "target_digest": target.source_digest if target else None}
            if action == "build":
                approval = verify_envelope(payload.get("approval"), signing_key)
                artifact = build_artifact(entry.analysis, options, entry.source_digest, approval, **kwargs)
                return jsonify({"success": True, "artifact": sign_envelope(artifact, signing_key)})
            review = build_review(entry.analysis, options, entry.source_digest, **kwargs)
            if action == "design/approve":
                signed_draft = verify_envelope(payload.get("draft"), signing_key)
                approval = approve_design(review, signed_draft, payload.get("selected_items"))
                return jsonify({"success": True, "approval": sign_envelope(approval, signing_key)})
            review["draft"] = sign_envelope(review["draft"], signing_key)
            return jsonify({"success": True, "source_digest": entry.source_digest, **review})
        except (ValueError, TypeError, KeyError):
            return jsonify({"success": False, "error": "Invalid, blocked or stale FortiGate migration request. Check source scope, target choices, approval and dependencies."}), 400

    for action in ("requirements", "design/prepare", "design/approve", "build", "command-preview", "commands", "bundle", "decisions/import", "decisions/export"):
        app.add_url_rule(prefix + "/" + action, "fg_migration_" + action.replace("/", "_"),
                         lambda action=action: handle(action), methods=["POST"])
