"""Static React frontend routes.

Presentation serving stays separate from API orchestration so web.py remains the
composition root rather than owning frontend file-serving details.
"""

from __future__ import annotations

import os

from flask import jsonify, send_file, send_from_directory


def register_frontend_routes(app) -> None:
    @app.route("/")
    def index():
        frontend_index = os.path.join(app.config["FRONTEND_DIST_DIR"], "index.html")
        if os.path.isfile(frontend_index):
            return send_from_directory(app.config["FRONTEND_DIST_DIR"], "index.html")
        return jsonify({"error": "Frontend build is unavailable"}), 503

    @app.route("/assets/<path:filename>")
    def frontend_asset(filename):
        return send_from_directory(os.path.join(app.config["FRONTEND_DIST_DIR"], "assets"), filename)

    @app.route("/favicon.svg")
    def frontend_favicon():
        frontend_icon = os.path.join(app.config["FRONTEND_DIST_DIR"], "favicon.svg")
        if os.path.isfile(frontend_icon):
            return send_from_directory(app.config["FRONTEND_DIST_DIR"], "favicon.svg")
        return send_from_directory(app.static_folder, "app_icon.svg")

    @app.route("/favicon.ico")
    def favicon():
        return send_file(os.path.join(app.static_folder, "app_icon.ico"), mimetype="image/vnd.microsoft.icon")
