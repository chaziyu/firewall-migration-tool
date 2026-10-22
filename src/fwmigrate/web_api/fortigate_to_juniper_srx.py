"""Transport for signed, offline FortiGate to Juniper SRX exports."""

import io
import json
import zipfile

import yaml
from flask import Response, jsonify, request, send_file

from fwmigrate.conversion.fortigate_to_juniper_srx.application import (
    approve_design,
    build_artifact,
    build_review,
    export_decisions,
    import_decisions,
    options_mapping,
    propose_new_target,
    verify_export_artifact,
)
from fwmigrate.source_reporting import source_reporters
from fwmigrate.collection.snapshot import parse_snapshot
from fwmigrate.web_support.artifact_signing import sign_envelope, verify_envelope
from fwmigrate.web_support.request_source import analyze_request_source, _require_complete_collection


def register_fortigate_to_juniper_srx_routes(app, signing_key):
    prefix = "/api/migration/fortigate_to_juniper_srx"

    def target_source(payload):
        if payload.get("target_source") is None and not request.files.get("target_file"):
            return None, None, None
        entry = analyze_request_source(payload, "juniper_srx", target=True)
        _require_complete_collection(entry)
        target_text = entry.evidence.get("source_text") if isinstance(entry.evidence, dict) else None
        if not isinstance(target_text, str):
            snapshot = parse_snapshot(json.dumps(entry.evidence).encode("utf-8"))
            target_text = snapshot.source_text
        metadata = payload.get("target_metadata")
        return entry.analysis, target_text, metadata

    def handle(action):
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError("A JSON object is required")
            if action in {"command-preview", "commands", "bundle"}:
                artifact = verify_export_artifact(
                    verify_envelope(payload.get("artifact"), signing_key)
                )
                command_bytes = artifact["command_text"].encode("utf-8")
                if action == "command-preview":
                    return jsonify({
                        "success": True,
                        "text": artifact["command_text"],
                        "command_sha256": artifact["command_sha256"],
                    })
                if action == "commands":
                    return Response(
                        command_bytes,
                        mimetype="text/plain",
                        headers={"Content-Disposition": 'attachment; filename="juniper_config.set"'},
                    )

                entry = analyze_request_source(payload, "fortigate")
                _require_complete_collection(entry)
                if entry.source_digest != artifact["report"]["source_digest"]:
                    raise ValueError("Bundle source differs from the approved artifact")
                workbook = io.BytesIO()
                source_reporters.get("fortigate").export_excel(
                    entry.analysis, workbook, source_name=entry.source_name,
                )
                bundle = io.BytesIO()
                with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("juniper_config.set", command_bytes)
                    archive.writestr("migration_report.json", json.dumps(artifact["report"], indent=2))
                    archive.writestr(
                        "migration_decisions.json",
                        json.dumps(export_decisions(artifact["source_digest"], artifact["options"]), indent=2),
                    )
                    archive.writestr(
                        "target_mapping.yaml",
                        yaml.safe_dump(artifact["options"], sort_keys=False),
                    )
                    archive.writestr("source_inventory.xlsx", workbook.getvalue())
                bundle.seek(0)
                return send_file(
                    bundle,
                    mimetype="application/zip",
                    as_attachment=True,
                    download_name="migration_fortigate_to_juniper_srx.zip",
                )

            entry = analyze_request_source(payload, "fortigate")
            _require_complete_collection(entry)
            if action == "decisions/import":
                return jsonify({
                    "success": True,
                    "options": import_decisions(payload.get("document"), entry.source_digest),
                })
            options = payload.get("options", {})
            if not isinstance(options, dict):
                raise ValueError("SRX target mapping options must be an object")
            if action == "decisions/export":
                return jsonify({
                    "success": True,
                    "document": export_decisions(entry.source_digest, options),
                })
            if action == "proposals":
                if payload.get("target_source") is not None or request.files.get("target_file"):
                    raise ValueError("New-device proposals cannot assume an existing target is empty")
                proposed = propose_new_target(entry.analysis.extracted.config, entry.analysis.derived, options)
                return jsonify({"success": True, "options": options_mapping(proposed),
                    "hardware_verified": False, "approval_required": True})
            target, target_text, target_metadata = target_source(payload)
            review = build_review(
                entry.analysis, options, entry.source_digest, target=target,
                target_source_text=target_text, target_metadata=target_metadata,
            )
            if action == "requirements":
                return jsonify({
                    "success": True,
                    "source_digest": entry.source_digest,
                    "requirements": review["requirements"],
                    "options": options_mapping(review["options"]),
                    "report": review["report"],
                })
            if action == "design/prepare":
                return jsonify({
                    "success": True,
                    "source_digest": entry.source_digest,
                    "draft": sign_envelope(review["draft"], signing_key),
                    "requirements": review["requirements"],
                    "options": options_mapping(review["options"]),
                    "report": review["report"],
                })
            if action == "design/approve":
                signed_draft = verify_envelope(payload.get("draft"), signing_key)
                approval = approve_design(review, signed_draft, payload.get("selected_items"))
                return jsonify({"success": True, "approval": sign_envelope(approval, signing_key)})
            if action == "build":
                approval = verify_envelope(payload.get("approval"), signing_key)
                artifact = build_artifact(
                    entry.analysis, options, entry.source_digest, approval, target=target,
                    target_source_text=target_text, target_metadata=target_metadata,
                )
                return jsonify({"success": True, "artifact": sign_envelope(artifact, signing_key)})
            raise ValueError("Unsupported SRX migration action")
        except (ValueError, TypeError, KeyError):
            return jsonify({
                "success": False,
                "error": "Invalid, blocked or stale FortiGate migration request. Check source scope, target choices, approval and dependencies.",
            }), 400

    actions = (
        "requirements", "proposals", "design/prepare", "design/approve", "build",
        "command-preview", "commands", "bundle", "decisions/import", "decisions/export",
    )
    for action in actions:
        app.add_url_rule(
            f"{prefix}/{action}",
            "fg_srx_migration_" + action.replace("/", "_"),
            lambda action=action: handle(action),
            methods=["POST"],
        )
