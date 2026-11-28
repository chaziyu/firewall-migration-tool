"""HTTP endpoints for desktop/local update checking and automatic installation."""

from __future__ import annotations

import logging

from flask import jsonify

from fwmigrate.web_support.request_controls import live_device_access_allowed
from fwmigrate.web_support.update_service import check_for_updates, download_and_trigger_install

_LOGGER = logging.getLogger(__name__)
_SAFE_UPDATE_PREFIXES = (
    "Already on the latest version",
    "Unable to reach GitHub Releases",
    "GitHub API returned HTTP",
    "Running from unpacked source without git",
    "No Windows executable asset found",
    "Downloaded executable is invalid or corrupted",
    "Release is missing required SHA256SUMS.txt",
    "SHA-256 checksum verification failed",
    "Update executable failed Authenticode signature check",
    "Local directory is not a git repository",
    "git pull failed",
    "Refusing to download update from untrusted host",
)


def _safe_update_error(exc: Exception) -> str:
    msg = str(exc).strip()
    if any(msg.startswith(prefix) for prefix in _SAFE_UPDATE_PREFIXES):
        return msg
    return "Update installation failed."


def register_update_routes(app) -> None:
    @app.route("/api/update/check", methods=["GET"])
    def check_update():
        is_loopback = live_device_access_allowed(app)
        return jsonify(check_for_updates(is_loopback=is_loopback))

    @app.route("/api/update/install", methods=["POST"])
    def install_update():
        if not live_device_access_allowed(app):
            return jsonify({
                "success": False,
                "error": "Self-update is only allowed from local loopback desktop or source sessions.",
            }), 403
        try:
            return jsonify(download_and_trigger_install())
        except (ValueError, RuntimeError) as exc:
            return jsonify({"success": False, "error": _safe_update_error(exc)}), 400
        except Exception:
            _LOGGER.exception("Update installation failed")
            return jsonify({"success": False, "error": "Update installation failed."}), 500
