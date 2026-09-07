from __future__ import annotations

import io
from typing import Any

from flask import jsonify, request, send_file

from fwmigrate.collectors.fortigate import FortiGateSSHCollector
from fwmigrate.core.registry import PluginRegistry
from fwmigrate.report.excel_exporter import (
    ExcelExportUnavailableError,
    IRExcelExporter,
    XLSX_MIMETYPE,
)


def _fortigate_collector_from_payload(payload: dict[str, Any]) -> FortiGateSSHCollector:
    host = str(payload.get("host") or "").strip()
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    port = int(payload.get("port") or 22)
    verify_host_key = bool(payload.get("verify_host_key", False))
    if not host or not username or not password:
        raise ValueError("FortiGate host, username, and password are required.")
    return FortiGateSSHCollector(
        host=host,
        port=port,
        username=username,
        password=password,
        verify_host_key=verify_host_key,
    )


def register_live_source_routes(app) -> None:
    """Register live source collection endpoints without target conversion logic."""

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

    @app.route("/api/source/fortigate/extract/excel", methods=["POST"])
    def source_fortigate_extract_excel():
        try:
            payload = request.get_json(silent=True) or {}
            collector = _fortigate_collector_from_payload(payload)
            snapshot = collector.collect()
            if not snapshot.complete:
                return jsonify({
                    "success": False,
                    "stage": "collection",
                    "error": "FortiGate configuration collection was incomplete.",
                    "warnings": snapshot.warnings,
                    "errors": snapshot.errors,
                    "sha256": snapshot.sha256,
                }), 422

            parser = PluginRegistry.get_parser("fortigate")
            extraction = parser.extract(snapshot.raw_config)
            ir_config = extraction.canonical_ir
            ir_config.metadata.input_type = "Live SSH Collection"
            metadata = dict(ir_config.metadata.source_attributes or {})
            metadata["live_collection"] = {
                "vendor": snapshot.vendor,
                "hostname": snapshot.hostname,
                "software_version": snapshot.software_version,
                "collection_method": snapshot.collection_method,
                "commands_executed": snapshot.commands_executed,
                "collected_at": snapshot.collected_at.isoformat(),
                "complete": snapshot.complete,
                "warnings": snapshot.warnings,
                "sha256": snapshot.sha256,
                "raw_config_bytes": len(snapshot.raw_config.encode("utf-8")),
            }
            ir_config.metadata.source_attributes = metadata

            workbook = io.BytesIO(
                IRExcelExporter(
                    ir_config,
                    extraction_result=extraction,
                ).generate()
            )
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
