"""Desktop launcher for bundling the frontend and Flask backend into a standalone app."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import webbrowser
from pathlib import Path

from werkzeug.serving import make_server

from fwmigrate.web import create_app


def _resolve_frontend_dist() -> Path:
    """Return the built frontend directory for frozen and source runs."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "frontend_dist"
    return Path(__file__).resolve().parent.parent / "src" / "frontend" / "dist"


def _configure_environment() -> None:
    """Configure local-only mode and bundled frontend path before creating the Flask app."""
    os.environ.setdefault("FWMIGRATE_WEB_MODE", "local")
    os.environ["FWMIGRATE_FRONTEND_DIST_DIR"] = str(_resolve_frontend_dist())


def main(argv: list[str] | None = None) -> int:
    """Start the local Flask server and open the desktop UI."""
    parser = argparse.ArgumentParser(description="Launch Firewall Migration Tool desktop app.")
    parser.add_argument("--browser", action="store_true", help="Open in the default web browser instead of a desktop window.")
    args = parser.parse_args(argv)

    _configure_environment()
    app = create_app()
    server = make_server("127.0.0.1", 0, app, threaded=True)
    url = f"http://127.0.0.1:{server.server_port}/"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        if args.browser:
            webbrowser.open(url)
            server_thread.join()
            return 0

        try:
            import webview
        except ImportError:
            webbrowser.open(url)
            server_thread.join()
            return 0

        webview.settings["ALLOW_DOWNLOADS"] = True
        webview.create_window(
            "Firewall Migration Tool",
            url,
            width=1440,
            height=900,
            min_size=(960, 640),
        )
        webview.start()
        return 0
    finally:
        server.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
