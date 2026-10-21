"""Transport for reviewed PAN-OS to Cisco FTD offline artifacts."""

import io
import json
import zipfile

from flask import Response, jsonify, request, send_file
import yaml

from fwmigrate.collection.snapshot import parse_snapshot
from fwmigrate.conversion.palo_alto_to_cisco_ftd.application import (
    approve_design,
    build_artifact,
    build_review,
    export_decisions,
    import_decisions,
    source_scopes,
    verify_export_artifact,
)
from fwmigrate.source_reporting import source_reporters
from fwmigrate.web_support.artifact_signing import sign_envelope, verify_envelope
from fwmigrate.web_support.request_source import (
    _require_complete_collection,
    analyze_request_source,
)


OPERATION_FILE = "cisco_fmc_operations.json"
BINDINGS_FILE = "cisco_fmc_bindings.json"
CURL_FILE = "cisco_fmc_curl.sh"
INSTRUCTIONS_FILE = "ftd_application_instructions.txt"


def register_palo_alto_to_cisco_ftd_routes(app, signing_key):
    prefix = "/api/migration/palo_alto_to_cisco_ftd"
    file_names = {
        "fmc-operations": (OPERATION_FILE, "application/json"),
        "bindings": (BINDINGS_FILE, "application/json"),
        "fmc-curl": (CURL_FILE, "text/plain"),
        "instructions": (INSTRUCTIONS_FILE, "text/plain"),
    }

    def source_entry(payload):
        entry = analyze_request_source(payload, "palo_alto")
        _require_complete_collection(entry)
        return entry

    def target_evidence(payload):
        if payload.get("target_source") is None and not request.files.get("target_file"):
            if payload.get("target_metadata") is not None:
                raise ValueError("Target metadata requires a destination snapshot")
            return {}
        entry = analyze_request_source(payload, "cisco_ftd", target=True)
        _require_complete_collection(entry)
        text = entry.evidence.get("source_text") if isinstance(entry.evidence, dict) else None
        if not isinstance(text, str):
            text = parse_snapshot(json.dumps(entry.evidence).encode("utf-8")).source_text
        return {
            "target": entry.analysis,
            "target_source_text": text,
            "target_metadata": payload.get("target_metadata"),
        }

    def approved_artifact(payload, entry):
        artifact = verify_export_artifact(verify_envelope(payload.get("artifact"), signing_key))
        if artifact.get("source_digest") != entry.source_digest:
            raise ValueError("Cisco FTD artifact belongs to a different source")
        return artifact

    def client_options(review):
        return {key: value if value is not None else "" for key, value in review["options"].to_dict().items()}

    def handle(action):
        payload = request.get_json(silent=True)
        try:
            if not isinstance(payload, dict):
                raise ValueError("A JSON object is required")
            if action in {
                "artifact-preview", "fmc-operations", "bindings", "fmc-curl", "instructions", "bundle",
            }:
                entry = source_entry(payload)
                artifact = approved_artifact(payload, entry)
                if action == "artifact-preview":
                    return jsonify({
                        "success": True,
                        "files": {
                            name: {
                                "text": row["content"],
                                "sha256": row["sha256"],
                                "byte_count": row["byte_count"],
                            }
                            for name, row in artifact["files"].items()
                        },
                        "report": artifact["report"],
                    })
                if action in file_names:
                    name, mimetype = file_names[action]
                    if name not in artifact["files"]:
                        raise ValueError(f"File {name} not found in artifact")
                    raw = artifact["files"][name]["content"].encode("utf-8")
                    return Response(
                        raw,
                        mimetype=mimetype,
                        headers={"Content-Disposition": f'attachment; filename="{name}"'},
                    )
                bundle = io.BytesIO()
                with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
                    for name in artifact["files"]:
                        archive.writestr(name, artifact["files"][name]["content"].encode("utf-8"))
                    archive.writestr(
                        "migration_report.json",
                        json.dumps(artifact["report"], ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    )
                    archive.writestr(
                        "migration_decisions.json",
                        json.dumps(
                            export_decisions(artifact["source_digest"], artifact["options"]),
                            ensure_ascii=False,
                            sort_keys=True,
                            indent=2,
                        )
                        + "\n",
                    )
                    archive.writestr("target_mapping.yaml", yaml.safe_dump(artifact["options"], sort_keys=True))
                    workbook = io.BytesIO()
                    source_reporters.get("palo_alto").export_excel(entry.analysis, workbook, source_name=entry.source_name)
                    archive.writestr("source_inventory.xlsx", workbook.getvalue())
                bundle.seek(0)
                return send_file(
                    bundle,
                    mimetype="application/zip",
                    as_attachment=True,
                    download_name="migration_palo_alto_to_cisco_ftd.zip",
                )

            entry = source_entry(payload)
            if action == "decisions/import":
                return jsonify({
                    "success": True,
                    "options": import_decisions(payload.get("document"), entry.source_digest),
                })
            options = payload.get("options", {})
            if not isinstance(options, dict):
                raise ValueError("Cisco FTD target mapping options must be an object")
            if action == "decisions/export":
                return jsonify({
                    "success": True,
                    "document": export_decisions(entry.source_digest, options),
                })
            destination = target_evidence(payload)
            review = build_review(entry.analysis, options, entry.source_digest, **destination)
            if action == "requirements":
                return jsonify({
                    "success": True,
                    "source_digest": entry.source_digest,
                    "options": client_options(review),
                    "source_scopes": source_scopes(entry.analysis),
                    "requirements": review["requirements"],
                    "report": review["report"],
                })
            if action == "design/prepare":
                return jsonify({
                    "success": True,
                    "source_digest": entry.source_digest,
                    "source_scopes": source_scopes(entry.analysis),
                    "options": client_options(review),
                    "draft": sign_envelope(review["draft"], signing_key),
                    "requirements": review["requirements"],
                    "report": review["report"],
                })
            if action == "design/approve":
                draft = verify_envelope(payload.get("draft"), signing_key)
                approval = approve_design(review, draft, payload.get("selected_items"))
                return jsonify({
                    "success": True,
                    "approval": sign_envelope(approval, signing_key),
                })
            if action == "build":
                approval = verify_envelope(payload.get("approval"), signing_key)
                artifact = build_artifact(entry.analysis, options, entry.source_digest, approval, **destination)
                return jsonify({
                    "success": True,
                    "artifact": sign_envelope(artifact, signing_key),
                })
            raise ValueError("Unsupported Cisco FTD migration action")
        except (ValueError, TypeError, KeyError):
            return jsonify({
                "success": False,
                "error": "Invalid, blocked or stale PAN-OS to Cisco FTD request. Check source scope, target mapping, approval, and dependencies.",
            }), 400

    actions = (
        "requirements",
        "design/prepare",
        "design/approve",
        "build",
        "artifact-preview",
        "fmc-operations",
        "bindings",
        "fmc-curl",
        "instructions",
        "bundle",
        "decisions/import",
        "decisions/export",
    )
    for action in actions:
        app.add_url_rule(
            f"{prefix}/{action}",
            "pan_cisco_ftd_migration_" + action.replace("/", "_"),
            lambda action=action: handle(action),
            methods=["POST"],
        )
