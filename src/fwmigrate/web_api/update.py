"""HTTP endpoints for desktop/local update checking and automatic installation."""

from __future__ import annotations

from flask import jsonify

from fwmigrate.web_support.request_controls import live_device_access_allowed
from fwmigrate.web_support.update_service import check_for_updates, download_and_trigger_install


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
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
