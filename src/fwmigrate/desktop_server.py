"""Loopback-only Flask sidecar used by the Tauri desktop shell."""

from __future__ import annotations

import argparse
import secrets
from collections.abc import Mapping

from flask import Flask, jsonify, request
from werkzeug.serving import make_server

from fwmigrate.web import create_app

DESKTOP_TOKEN_HEADER = "X-FWMigrate-Desktop-Token"
READY_PREFIX = "FWMIGRATE_DESKTOP_READY "
_ALLOWED_ORIGINS = {
    "http://tauri.localhost",
    "https://tauri.localhost",
    "tauri://localhost",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
}


def create_desktop_app(token: str, test_config: Mapping[str, object] | None = None) -> Flask:
    """Wrap the existing Flask composition root with desktop-only transport controls."""
    if not token:
        raise ValueError("desktop token must not be empty")

    app = create_app(dict(test_config) if test_config is not None else None)

    @app.before_request
    def authenticate_desktop_api():
        if not request.path.startswith("/api/"):
            return None
        if request.method == "OPTIONS":
            return ("", 204)

        supplied = request.headers.get(DESKTOP_TOKEN_HEADER, "")
        if not secrets.compare_digest(supplied, token):
            return jsonify({"error": "Unauthorized desktop request"}), 401
        return None

    @app.after_request
    def add_desktop_cors(response):
        origin = request.headers.get("Origin")
        if origin in _ALLOWED_ORIGINS:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Headers"] = (
                f"Content-Type, {DESKTOP_TOKEN_HEADER}"
            )
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Vary"] = "Origin"
        return response

    return app


def run_desktop_server(*, port: int, token: str) -> None:
    """Serve the shared Flask API on loopback and report the selected port to Tauri."""
    app = create_desktop_app(token)
    server = make_server("127.0.0.1", port, app, threaded=True)
    print(f"{READY_PREFIX}{server.server_port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description="Firewall Migration Tool desktop sidecar")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    run_desktop_server(port=args.port, token=args.token)


if __name__ == "__main__":
    main()
