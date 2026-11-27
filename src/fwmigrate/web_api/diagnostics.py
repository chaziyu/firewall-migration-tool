"""HTTP endpoints for Phase 2 security audit, local-only exposure probe, and HTML audit report export."""

from __future__ import annotations

import io
import logging

from flask import jsonify, request, send_file
from werkzeug.exceptions import HTTPException

from fwmigrate.source_reporting.exposure import probe_exposure_targets
from fwmigrate.source_reporting.lifecycle import (
    build_fortigate_lifecycle_card,
    build_paloalto_lifecycle_card,
    evaluate_fortigate_lifecycle,
    evaluate_paloalto_lifecycle,
)
from fwmigrate.source_reporting.pm_checklist import (
    evaluate_fortigate_pm_checklist,
    evaluate_paloalto_pm_checklist,
    export_pm_checklist_excel,
)
from fwmigrate.vendors.fortigate.security_audit import (
    build_fortigate_security_audit,
    export_fortigate_audit_html,
    find_fortigate_exposure,
)
from fwmigrate.vendors.palo_alto.security_audit import (
    build_paloalto_security_audit,
    export_paloalto_audit_html,
    find_paloalto_exposure,
)
from fwmigrate.web_support.public_errors import safe_validation_message
from fwmigrate.web_support.reporting import ConfigurationDecodeError, SourceSizeError, _safe_vendor_filename
from fwmigrate.web_support.request_controls import limit_export_response, live_device_access_allowed
from fwmigrate.web_support.request_source import analyze_request_source

_LOGGER = logging.getLogger(__name__)
_SUPPORTED_VENDORS = frozenset({"fortigate", "palo_alto"})


def _parse_audit_request():
    payload = request.get_json(silent=True, cache=False)
    if not isinstance(payload, dict):
        raise ValueError("Diagnostic request must be a JSON object")
    vendor = str(payload.get("source_vendor") or "").strip().lower()
    if vendor not in _SUPPORTED_VENDORS:
        raise ValueError("Security diagnostics support fortigate and palo_alto only")
    entry = analyze_request_source(payload, vendor, use_cache=True)
    return vendor, entry


def register_diagnostic_routes(app) -> None:
    @app.route("/api/source/audit", methods=["POST"])
    def source_security_audit():
        """Run static security audit (certs, exposure, posture, hygiene, quick audit)."""
        try:
            vendor, entry = _parse_audit_request()
            if vendor == "fortigate":
                audit = build_fortigate_security_audit(
                    entry.analysis.extracted.config,
                    entry.analysis.derived,
                    metadata=entry.analysis.extracted.source_metadata,
                )
            else:
                audit = build_paloalto_security_audit(
                    entry.analysis.config,
                    entry.analysis.derived,
                )
            audit.pop("vpn_health", None)
            return jsonify({"success": True, **audit})
        except ConfigurationDecodeError:
            return jsonify({"success": False, "error": "Configuration file is not valid UTF-8."}), 400
        except SourceSizeError:
            raise
        except ValueError as exc:
            return jsonify({"success": False, "error": safe_validation_message(exc, "Invalid security audit request")}), 400
        except HTTPException:
            raise
        except Exception:
            _LOGGER.exception("Security audit failed")
            return jsonify({"success": False, "error": "Security audit failed"}), 500

    @app.route("/api/source/exposure-probe", methods=["POST"])
    def source_exposure_probe():
        """Perform local-only TCP/TLS/SSH reachability checks on exposed public management targets."""
        if not live_device_access_allowed(app):
            return jsonify({"success": False, "error": "Live exposure probing is disabled on this server."}), 403
        try:
            vendor, entry = _parse_audit_request()
            if vendor == "fortigate":
                findings = find_fortigate_exposure(entry.analysis.extracted.config)
            else:
                findings = find_paloalto_exposure(entry.analysis.config, entry.analysis.derived)
            connect_fn = app.config.get("EXPOSURE_PROBE_CONNECT_FN")
            probe_result = probe_exposure_targets(findings, connect_fn=connect_fn)
            return jsonify({"success": True, "vendor": vendor, **probe_result})
        except ConfigurationDecodeError:
            return jsonify({"success": False, "error": "Configuration file is not valid UTF-8."}), 400
        except SourceSizeError:
            raise
        except ValueError as exc:
            return jsonify({"success": False, "error": safe_validation_message(exc, "Invalid exposure probe request")}), 400
        except HTTPException:
            raise
        except Exception:
            _LOGGER.exception("Exposure reachability probe failed")
            return jsonify({"success": False, "error": "Exposure reachability probe failed"}), 500

    @app.route("/api/source/audit-report", methods=["POST"])
    @limit_export_response
    def source_audit_report():
        """Export standalone, script-free HTML / Print-to-PDF security audit report."""
        try:
            vendor, entry = _parse_audit_request()
            filename = entry.source_name or f"{vendor}_config"
            if vendor == "fortigate":
                meta = entry.analysis.extracted.source_metadata
                lifecycle = build_fortigate_lifecycle_card(
                    evaluate_fortigate_lifecycle(
                        meta.hardware_model if meta else None,
                        meta.fortios_version if meta else None,
                        serial_raw=meta.serial_number if meta else None,
                        cache_only=True,
                    )
                )
                html_bytes = export_fortigate_audit_html(
                    entry.analysis.extracted.config,
                    entry.analysis.derived,
                    metadata=meta,
                    lifecycle_card=lifecycle,
                    filename=filename,
                )
            else:
                config = entry.analysis.config
                version = config.detail_version or config.source_version
                lifecycle = build_paloalto_lifecycle_card(
                    evaluate_paloalto_lifecycle(
                        version,
                        is_exact_version=bool(config.detail_version),
                        cache_only=True,
                    )
                )
                html_bytes = export_paloalto_audit_html(
                    config,
                    entry.analysis.derived,
                    lifecycle_card=lifecycle,
                    filename=filename,
                )
            return send_file(
                io.BytesIO(html_bytes),
                mimetype="text/html; charset=utf-8",
                as_attachment=True,
                download_name=f"{_safe_vendor_filename(vendor)}_security_audit_report.html",
            )
        except ConfigurationDecodeError:
            return jsonify({"success": False, "error": "Configuration file is not valid UTF-8."}), 400
        except SourceSizeError:
            raise
        except ValueError as exc:
            return jsonify({"success": False, "error": safe_validation_message(exc, "Invalid audit report request")}), 400
        except HTTPException:
            raise
        except Exception:
            _LOGGER.exception("Audit report export failed")
            return jsonify({"success": False, "error": "Security audit report export failed"}), 500

    @app.route("/api/source/pm-lookup", methods=["POST"])
    def source_pm_lookup():
        """Run backup-config Preventive Maintenance (PM) Lookup for FortiGate or Palo Alto."""
        try:
            vendor, entry = _parse_audit_request()
            if vendor == "fortigate":
                result = evaluate_fortigate_pm_checklist(
                    entry.analysis.extracted.config,
                    entry.analysis.derived,
                    metadata=entry.analysis.extracted.source_metadata,
                )
            else:
                result = evaluate_paloalto_pm_checklist(
                    entry.analysis.config,
                    entry.analysis.derived,
                )
            return jsonify({"success": True, **result})
        except ConfigurationDecodeError:
            return jsonify({"success": False, "error": "Configuration file is not valid UTF-8."}), 400
        except SourceSizeError:
            raise
        except ValueError as exc:
            return jsonify({"success": False, "error": safe_validation_message(exc, "Invalid PM Lookup request")}), 400
        except HTTPException:
            raise
        except Exception:
            _LOGGER.exception("PM Lookup failed")
            return jsonify({"success": False, "error": "PM Lookup failed"}), 500

    @app.route("/api/source/pm-lookup/export", methods=["POST"])
    @limit_export_response
    def source_pm_lookup_export():
        """Export PM Lookup checklist evaluation to a formatted single-sheet Excel workbook."""
        try:
            vendor, entry = _parse_audit_request()
            if vendor == "fortigate":
                result = evaluate_fortigate_pm_checklist(
                    entry.analysis.extracted.config,
                    entry.analysis.derived,
                    metadata=entry.analysis.extracted.source_metadata,
                )
            else:
                result = evaluate_paloalto_pm_checklist(
                    entry.analysis.config,
                    entry.analysis.derived,
                )
            xlsx_bytes = export_pm_checklist_excel(result)
            return send_file(
                io.BytesIO(xlsx_bytes),
                mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                as_attachment=True,
                download_name=f"{_safe_vendor_filename(vendor)}_pm_lookup.xlsx",
            )
        except ConfigurationDecodeError:
            return jsonify({"success": False, "error": "Configuration file is not valid UTF-8."}), 400
        except SourceSizeError:
            raise
        except ValueError as exc:
            return jsonify({"success": False, "error": safe_validation_message(exc, "Invalid PM Lookup export request")}), 400
        except HTTPException:
            raise
        except Exception:
            _LOGGER.exception("PM Lookup Excel export failed")
            return jsonify({"success": False, "error": "PM Lookup Excel export failed"}), 500
