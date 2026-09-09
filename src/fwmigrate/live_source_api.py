from __future__ import annotations

import io
import uuid
from typing import Any

from flask import jsonify, request, send_file

from fwmigrate.collectors.fortigate import FortiGateSSHCollector
from fwmigrate.collectors.models import SourceSnapshot
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.report.excel_exporter import (
    ExcelExportUnavailableError,
    IRExcelExporter,
    XLSX_MIMETYPE,
)

# In-memory only. Credentials are never stored. The raw snapshot remains server-side
# so Excel generation uses the exact configuration that was pulled and reviewed.
LIVE_SOURCE_SNAPSHOTS: dict[str, SourceSnapshot] = {}
_MAX_SNAPSHOTS = 10


def _fortigate_collector_from_payload(payload: dict[str, Any]) -> FortiGateSSHCollector:
    host = str(payload.get("host") or "").strip()
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    port = int(payload.get("port") or 22)
    verify_host_key = bool(payload.get("verify_host_key", False))
    if not host or not username or not password:
        raise ValueError("FortiGate host, username, and password are required.")
    if port < 1 or port > 65535:
        raise ValueError("SSH port must be between 1 and 65535.")
    return FortiGateSSHCollector(
        host=host,
        port=port,
        username=username,
        password=password,
        verify_host_key=verify_host_key,
    )


def _snapshot_summary(collection_id: str, snapshot: SourceSnapshot) -> dict[str, Any]:
    return {
        "success": snapshot.complete,
        "collection_id": collection_id,
        "vendor": snapshot.vendor,
        "hostname": snapshot.hostname,
        "software_version": snapshot.software_version,
        "collection_method": snapshot.collection_method,
        "commands_executed": snapshot.commands_executed,
        "collected_at": snapshot.collected_at.isoformat(),
        "complete": snapshot.complete,
        "warnings": snapshot.warnings,
        "errors": snapshot.errors,
        "sha256": snapshot.sha256,
        "raw_config_bytes": len(snapshot.raw_config.encode("utf-8")),
    }


def _store_snapshot(snapshot: SourceSnapshot) -> str:
    # Keep memory bounded. This is deliberately not persistent storage.
    while len(LIVE_SOURCE_SNAPSHOTS) >= _MAX_SNAPSHOTS:
        oldest = next(iter(LIVE_SOURCE_SNAPSHOTS))
        LIVE_SOURCE_SNAPSHOTS.pop(oldest, None)
    collection_id = str(uuid.uuid4())
    LIVE_SOURCE_SNAPSHOTS[collection_id] = snapshot
    return collection_id


def _apply_supported_collection_metadata(snapshot: SourceSnapshot, ir_config) -> None:
    """Project live-collection facts into fields defined by IRMetadata only.

    Collection-only details such as SHA-256 and command history remain in the
    SourceSnapshot/API response until the IR schema has an explicit provenance
    field for them. Do not attach undeclared attributes to the Pydantic model.
    """
    ir_config.metadata.input_type = "Live SSH Collection"
    if snapshot.hostname and not ir_config.metadata.hostname:
        ir_config.metadata.hostname = snapshot.hostname
    if snapshot.software_version and not ir_config.metadata.source_version:
        ir_config.metadata.source_version = snapshot.software_version


def _build_excel(snapshot: SourceSnapshot) -> bytes:
    parser = PluginRegistry.get_parser("fortigate")
    extraction = parser.extract(snapshot.raw_config)
    ir_config = extraction.canonical_ir
    _apply_supported_collection_metadata(snapshot, ir_config)

    return IRExcelExporter(
        ir_config,
        extraction_result=extraction,
    ).generate()


def register_live_source_routes(app) -> None:
    """Register FortiGate live source collection endpoints.

    This layer only handles source acquisition, extraction, and source-inventory
    Excel export. It does not invoke target conversion, optimization, Terraform,
    or deployment logic.
    """

    @app.route("/api/source/fortigate/test", methods=["POST"])
    def source_fortigate_test():
        try:
            payload = request.get_json(silent=True) or {}
            result = _fortigate_collector_from_payload(payload).test_connection()
            status = 200 if result.success else 502
            return jsonify(result.model_dump(mode="json")), status
        except (TypeError, ValueError) as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 502

    @app.route("/api/source/fortigate/pull", methods=["POST"])
    def source_fortigate_pull():
        try:
            payload = request.get_json(silent=True) or {}
            snapshot = _fortigate_collector_from_payload(payload).collect()
            if not snapshot.complete:
                return jsonify({
                    **_snapshot_summary("", snapshot),
                    "success": False,
                    "stage": "collection",
                    "error": "FortiGate configuration collection was incomplete.",
                }), 422

            collection_id = _store_snapshot(snapshot)
            return jsonify(_snapshot_summary(collection_id, snapshot)), 200
        except (TypeError, ValueError) as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 502

    @app.route("/api/source/fortigate/extract/excel", methods=["POST"])
    def source_fortigate_extract_excel():
        try:
            payload = request.get_json(silent=True) or {}
            collection_id = str(payload.get("collection_id") or "").strip()

            if collection_id:
                snapshot = LIVE_SOURCE_SNAPSHOTS.get(collection_id)
                if snapshot is None:
                    return jsonify({
                        "success": False,
                        "error": "Live source collection was not found or has expired. Pull the configuration again.",
                    }), 404
            else:
                # Backward-compatible direct mode for API/CLI consumers.
                snapshot = _fortigate_collector_from_payload(payload).collect()

            if not snapshot.complete:
                return jsonify({
                    "success": False,
                    "stage": "collection",
                    "error": "FortiGate configuration collection was incomplete.",
                    "warnings": snapshot.warnings,
                    "errors": snapshot.errors,
                    "sha256": snapshot.sha256,
                }), 422

            workbook = io.BytesIO(_build_excel(snapshot))
            workbook.seek(0)
            safe_host = (snapshot.hostname or "fortigate").replace("/", "_").replace("\\", "_")
            response = send_file(
                workbook,
                mimetype=XLSX_MIMETYPE,
                as_attachment=True,
                download_name=f"firewall_inventory_{safe_host}.xlsx",
            )
            response.headers["X-Source-Config-SHA256"] = snapshot.sha256
            response.headers["X-Source-Collection-Complete"] = "true"
            return response
        except ExcelExportUnavailableError as exc:
            return jsonify({"success": False, "error": str(exc)}), 503
        except (TypeError, ValueError) as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 502
