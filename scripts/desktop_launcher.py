"""Desktop launcher for bundling the frontend and Flask backend into a standalone app."""

from __future__ import annotations

import argparse
import base64
import os
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any


class DesktopApi:
    """JS-callable bridge exposed to the desktop UI via pywebview."""

    def __init__(self, webview_module: Any = None) -> None:
        self._webview = webview_module
        self._window: Any = None

    def attach_window(self, window: Any) -> None:
        """Bind the created pywebview Window instance after window creation."""
        self._window = window

    def save_file(self, filename: str, content_base64: str) -> dict[str, object]:
        """Open a native Save dialog with a preserved extension and write the file."""
        if self._window is None:
            return {"saved": False, "cancelled": False, "error": "Window is not ready"}
        safe_name = Path(filename or "export.xlsx").name or "export.xlsx"
        expected_ext = Path(safe_name).suffix
        file_types: tuple[str, ...]
        if expected_ext.lower() == ".xlsx":
            file_types = ("Excel Workbook (*.xlsx)", "All files (*.*)")
        elif expected_ext:
            file_types = (f"{expected_ext.lstrip('.').upper()} File (*{expected_ext})", "All files (*.*)")
        else:
            file_types = ("All files (*.*)",)

        file_dialog = getattr(self._webview, "FileDialog", None)
        save_dialog_type = getattr(file_dialog, "SAVE", getattr(self._webview, "SAVE_DIALOG", 30))
        selection = self._window.create_file_dialog(
            save_dialog_type,
            save_filename=safe_name,
            file_types=file_types,
        )
        if not selection:
            return {"saved": False, "cancelled": True}

        chosen = selection[0] if isinstance(selection, (list, tuple)) else str(selection)
        target = Path(chosen)
        if expected_ext and target.suffix.lower() != expected_ext.lower():
            target = target.with_name(f"{target.name}{expected_ext}")

        raw = base64.b64decode(content_base64)
        target.write_bytes(raw)
        return {"saved": True, "cancelled": False, "path": str(target), "filename": target.name}

    def download_file(self, filename: str, content_base64: str) -> dict[str, object]:
        """Save file directly into native Windows Downloads with a unique filename (no manual prompt)."""
        from fwmigrate.web_support.desktop_downloads import get_downloads_dir, unique_export_path

        safe_name = Path(filename or "export.xlsx").name or "export.xlsx"
        stem = Path(safe_name).stem or "export"
        ext = Path(safe_name).suffix or ".xlsx"
        downloads_dir = get_downloads_dir()
        target = unique_export_path(downloads_dir, stem, ext)
        raw = base64.b64decode(content_base64)
        target.write_bytes(raw)
        return {"saved": True, "cancelled": False, "path": str(target), "filename": target.name}


def _resolve_frontend_dist() -> Path:
    """Return the built frontend directory for frozen and source runs."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "frontend_dist"
    return Path(__file__).resolve().parent.parent / "src" / "frontend" / "dist"


def _configure_environment() -> None:
    """Configure local-only mode and bundled frontend path before creating the Flask app."""
    os.environ.setdefault("FWMIGRATE_WEB_MODE", "local")
    os.environ["FWMIGRATE_FRONTEND_DIST_DIR"] = str(_resolve_frontend_dist())


def _compute_window_geometry(webview_module: Any) -> dict[str, Any]:
    """Compute a centered initial window size and position fitted to the primary screen."""
    screens = getattr(webview_module, "screens", None) or []
    if not screens:
        return {"width": 1200, "height": 760, "min_size": (800, 600)}

    primary = screens[0]
    screen_w = int(getattr(primary, "width", 1440))
    screen_h = int(getattr(primary, "height", 900))
    screen_x = int(getattr(primary, "x", 0))
    screen_y = int(getattr(primary, "y", 0))

    width = max(1, min(1440, int(screen_w * 0.88)))
    height = max(1, min(900, int(screen_h * 0.85)))
    x = screen_x + max(0, (screen_w - width) // 2)
    y = screen_y + max(0, (screen_h - height) // 2)
    return {
        "width": width,
        "height": height,
        "x": x,
        "y": y,
        "screen": primary,
        "min_size": (min(800, width), min(600, height)),
    }


def _close_splash() -> None:
    """Close the PyInstaller splash screen if running in a frozen build."""
    try:
        import pyi_splash  # type: ignore[import-not-found]
    except ImportError:
        return
    try:
        pyi_splash.close()
    except Exception:
        pass


def _start_backend_async() -> tuple[threading.Event, dict[str, object]]:
    """Initialize Flask and bind the loopback HTTP server on a background thread."""
    ready = threading.Event()
    state: dict[str, object] = {}

    def _boot() -> None:
        try:
            from werkzeug.serving import make_server

            from fwmigrate.web import create_app

            app = create_app()
            try:
                server = make_server("127.0.0.1", 5000, app, threaded=True)
            except OSError:
                server = make_server("127.0.0.1", 0, app, threaded=True)
            state["server"] = server
            state["url"] = f"http://127.0.0.1:{server.server_port}/"
        except BaseException as exc:  # pragma: no cover - surfaced on main thread
            state["error"] = exc
        finally:
            ready.set()

    threading.Thread(target=_boot, daemon=True).start()
    return ready, state


def main(argv: list[str] | None = None) -> int:
    """Start the local Flask server and open the desktop UI."""
    parser = argparse.ArgumentParser(description="Launch Firewall Migration Tool desktop app.")
    parser.add_argument("--browser", action="store_true", help="Open in the default web browser instead of a desktop window.")
    args = parser.parse_args(argv)

    _configure_environment()
    backend_ready, backend_state = _start_backend_async()

    webview = None
    if not args.browser:
        try:
            import webview as _webview

            webview = _webview
        except ImportError:
            webview = None

    backend_ready.wait()
    if "error" in backend_state:
        _close_splash()
        raise backend_state["error"]  # type: ignore[misc]

    server = backend_state["server"]
    url = str(backend_state["url"])

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)  # type: ignore[attr-defined]
    server_thread.start()

    try:
        if args.browser or webview is None:
            _close_splash()
            webbrowser.open(url)
            server_thread.join()
            return 0

        webview.settings["ALLOW_DOWNLOADS"] = True
        api = DesktopApi(webview)
        geometry = _compute_window_geometry(webview)
        window = webview.create_window(
            "Firewall Migration Tool",
            url,
            js_api=api,
            resizable=True,
            zoomable=True,
            **geometry,
        )
        api.attach_window(window)
        events = getattr(window, "events", None)
        if events is not None and hasattr(events, "shown"):
            events.shown += _close_splash
            webview.start()
        else:
            webview.start(func=_close_splash)
        return 0
    finally:
        _close_splash()
        server.shutdown()  # type: ignore[attr-defined]


if __name__ == "__main__":
    raise SystemExit(main())
