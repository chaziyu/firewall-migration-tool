"""HTTP endpoints for Phase 3 Traffic Simulators & Structural Config Diff."""

from __future__ import annotations

import hashlib
import json
import logging
import os

from flask import current_app, has_app_context, jsonify, request
from werkzeug.exceptions import HTTPException

from fwmigrate.collection.snapshot import MAX_BYTES, sanitize_source
from fwmigrate.source_reporting import source_reporters
from fwmigrate.source_reporting.config_diff import diff_fortigate_configs, diff_paloalto_configs
from fwmigrate.source_reporting.packet_trace import trace_fortigate_packet, trace_paloalto_packet
from fwmigrate.source_reporting.policy_lookup import (
    evaluate_fortigate_policy_lookup,
    evaluate_paloalto_policy_lookup,
)
from fwmigrate.source_reporting.route_lookup import lookup_fortigate_route, lookup_paloalto_route
from fwmigrate.web_support.public_errors import safe_validation_message
from fwmigrate.web_support.reporting import ConfigurationDecodeError, SourceSizeError
from fwmigrate.web_support.request_source import SourceCacheExpiredError, _read_uploaded_source, analyze_request_source

_LOGGER = logging.getLogger(__name__)
_SUPPORTED_VENDORS = frozenset({"fortigate", "palo_alto"})


def _parse_simulator_json():
    payload = request.get_json(silent=True, cache=False)
    if not isinstance(payload, dict):
        raise ValueError("Simulator request must be a JSON object")
    vendor = str(payload.get("source_vendor") or "").strip().lower()
    if vendor not in _SUPPORTED_VENDORS:
        raise ValueError("Simulators support fortigate and palo_alto only")
    entry = analyze_request_source(payload, vendor, use_cache=True)
    return vendor, entry, payload


def _extract_config(vendor: str, entry):
    if vendor == "fortigate":
        return entry.analysis.extracted.config
    return entry.analysis.config


def _validate_same_vendor_text(vendor: str, text: str) -> None:
    stripped = text.lstrip()
    looks_xml = stripped.startswith("<")
    if vendor == "palo_alto" and (not looks_xml or "<config" not in stripped[:4096]):
        raise ValueError("Comparison file does not appear to be a Palo Alto PAN-OS XML configuration.")
    if vendor == "fortigate" and (stripped.startswith("<?xml") or stripped.startswith("<config")):
        raise ValueError("Comparison file appears to be XML, expected a FortiGate CLI configuration.")


def _analyze_comparison_source(vendor: str):
    uploaded = request.files.get("compare_file")
    if uploaded and uploaded.filename:
        raw_text = _read_uploaded_source(uploaded)
        _validate_same_vendor_text(vendor, raw_text)
        sanitized = sanitize_source(vendor, raw_text)
        name = os.path.basename(uploaded.filename)
    else:
        payload = request.get_json(silent=True, cache=False)
        compare_src = payload.get("compare_source") if isinstance(payload, dict) else None
        if isinstance(compare_src, str):
            try:
                compare_src = json.loads(compare_src)
            except json.JSONDecodeError as exc:
                raise ValueError("Invalid comparison source payload") from exc
        if not isinstance(compare_src, dict) or not isinstance(compare_src.get("source_text"), str):
            raise ValueError("A comparison configuration file is required")
        src_vendor = compare_src.get("vendor")
        if src_vendor and str(src_vendor).strip().lower() != vendor:
            raise ValueError("Comparison configuration vendor does not match active configuration vendor")
        raw_text = compare_src["source_text"]
        if len(raw_text) > MAX_BYTES or len(raw_text.encode("utf-8")) > MAX_BYTES:
            raise SourceSizeError("Comparison configuration exceeds the size limit.")
        _validate_same_vendor_text(vendor, raw_text)
        sanitized = sanitize_source(vendor, raw_text)
        name = str(compare_src.get("source_name") or "Comparison")[:255]

    hasher = hashlib.sha256()
    hasher.update(sanitized.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(vendor.encode("utf-8"))
    digest = hasher.hexdigest()

    cache = current_app.extensions.get("analysis_cache") if has_app_context() else None
    if cache is not None:
        analysis = cache.get_or_load(vendor, digest, lambda: source_reporters.get(vendor).analyze_source(sanitized))
    else:
        analysis = source_reporters.get(vendor).analyze_source(sanitized)
    return analysis, name


def register_simulator_routes(app) -> None:
    """Register Phase 3 simulator and config-diff endpoints."""

    @app.route("/api/source/policy-lookup", methods=["POST"])
    def source_policy_lookup():
        try:
            vendor, entry, payload = _parse_simulator_json()
            cfg = _extract_config(vendor, entry)
            if vendor == "fortigate":
                result = evaluate_fortigate_policy_lookup(
                    cfg,
                    vdom=payload.get("vdom"),
                    src_iface=str(payload.get("src_iface") or "any"),
                    dst_iface=str(payload.get("dst_iface") or "any"),
                    src_addr=str(payload.get("src_addr") or ""),
                    dst_addr=str(payload.get("dst_addr") or ""),
                    protocol=str(payload.get("protocol") or "any"),
                )
            else:
                result = evaluate_paloalto_policy_lookup(
                    cfg,
                    scope=payload.get("scope"),
                    policy_type=str(payload.get("policy_type") or "security"),
                    src_zone=str(payload.get("src_zone") or "any"),
                    dst_zone=str(payload.get("dst_zone") or "any"),
                    src_addr=str(payload.get("src_addr") or ""),
                    dst_addr=str(payload.get("dst_addr") or ""),
                    src_user=str(payload.get("src_user") or "any"),
                    dst_port=str(payload.get("dst_port") or ""),
                    protocol=str(payload.get("protocol") or "any"),
                )
            return jsonify({"success": True, **result})
        except ConfigurationDecodeError:
            return jsonify({"success": False, "error": "Configuration file is not valid UTF-8."}), 400
        except (SourceSizeError, SourceCacheExpiredError):
            raise
        except ValueError as exc:
            return jsonify({"success": False, "error": safe_validation_message(exc, "Invalid policy lookup request")}), 400
        except HTTPException:
            raise
        except Exception:
            _LOGGER.exception("Policy lookup failed")
            return jsonify({"success": False, "error": "Policy lookup failed"}), 500

    @app.route("/api/source/route-lookup", methods=["POST"])
    def source_route_lookup():
        try:
            vendor, entry, payload = _parse_simulator_json()
            cfg = _extract_config(vendor, entry)
            dest_ip = str(payload.get("dest_ip") or "")
            if vendor == "fortigate":
                result = lookup_fortigate_route(cfg, dest_ip, vdom=payload.get("vdom"))
            else:
                result = lookup_paloalto_route(
                    cfg,
                    dest_ip,
                    virtual_router=str(payload.get("virtual_router") or "all"),
                )
            return jsonify({"success": True, **result})
        except ConfigurationDecodeError:
            return jsonify({"success": False, "error": "Configuration file is not valid UTF-8."}), 400
        except (SourceSizeError, SourceCacheExpiredError):
            raise
        except ValueError as exc:
            return jsonify({"success": False, "error": safe_validation_message(exc, "Invalid route lookup request")}), 400
        except HTTPException:
            raise
        except Exception:
            _LOGGER.exception("Route lookup failed")
            return jsonify({"success": False, "error": "Route lookup failed"}), 500

    @app.route("/api/source/packet-trace", methods=["POST"])
    def source_packet_trace():
        try:
            vendor, entry, payload = _parse_simulator_json()
            cfg = _extract_config(vendor, entry)
            check_return = payload.get("check_return")
            check_return_flag = True if check_return is None else bool(check_return)
            if vendor == "fortigate":
                result = trace_fortigate_packet(
                    cfg,
                    src_ip=str(payload.get("src_ip") or ""),
                    dst_ip=str(payload.get("dst_ip") or ""),
                    dst_port=str(payload.get("dst_port") or "443"),
                    protocol=str(payload.get("protocol") or "tcp"),
                    vdom=payload.get("vdom"),
                    check_return=check_return_flag,
                )
            else:
                result = trace_paloalto_packet(
                    cfg,
                    src_ip=str(payload.get("src_ip") or ""),
                    dst_ip=str(payload.get("dst_ip") or ""),
                    dst_port=str(payload.get("dst_port") or "443"),
                    protocol=str(payload.get("protocol") or "tcp"),
                    virtual_router=str(payload.get("virtual_router") or "all"),
                    scope=payload.get("scope"),
                    check_return=check_return_flag,
                )
            return jsonify({"success": True, **result})
        except ConfigurationDecodeError:
            return jsonify({"success": False, "error": "Configuration file is not valid UTF-8."}), 400
        except (SourceSizeError, SourceCacheExpiredError):
            raise
        except ValueError as exc:
            return jsonify({"success": False, "error": safe_validation_message(exc, "Invalid packet trace request")}), 400
        except HTTPException:
            raise
        except Exception:
            _LOGGER.exception("Packet trace failed")
            return jsonify({"success": False, "error": "Packet trace failed"}), 500

    @app.route("/api/source/config-diff", methods=["POST"])
    def source_config_diff():
        try:
            if request.files or request.form:
                payload = {
                    "source_vendor": request.form.get("source_vendor", ""),
                    "source": request.form.get("source") or None,
                    "source_digest": request.form.get("source_digest") or None,
                    "source_name": request.form.get("source_name") or None,
                }
            else:
                payload = request.get_json(silent=True, cache=False)
                if not isinstance(payload, dict):
                    raise ValueError("Config diff request must be multipart form data or JSON")

            vendor = str(payload.get("source_vendor") or "").strip().lower()
            if vendor not in _SUPPORTED_VENDORS:
                raise ValueError("Config diff supports fortigate and palo_alto only")

            before_entry = analyze_request_source(payload, vendor, use_cache=True)
            after_analysis, after_name = _analyze_comparison_source(vendor)

            before_name = before_entry.source_name or "Current"
            if vendor == "fortigate":
                result = diff_fortigate_configs(
                    before_entry.analysis.extracted.config,
                    after_analysis.extracted.config,
                    before_name=before_name,
                    after_name=after_name,
                )
            else:
                result = diff_paloalto_configs(
                    before_entry.analysis.config,
                    after_analysis.config,
                    before_name=before_name,
                    after_name=after_name,
                )
            return jsonify({"success": True, **result})
        except ConfigurationDecodeError:
            return jsonify({"success": False, "error": "Configuration file is not valid UTF-8."}), 400
        except (SourceSizeError, SourceCacheExpiredError):
            raise
        except ValueError as exc:
            return jsonify({"success": False, "error": safe_validation_message(exc, "Invalid config diff request")}), 400
        except HTTPException:
            raise
        except Exception:
            _LOGGER.exception("Config diff failed")
            return jsonify({"success": False, "error": "Config diff failed"}), 500
