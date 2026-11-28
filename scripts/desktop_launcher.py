"""Desktop launcher for bundling the frontend and Flask backend into a standalone app."""

from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any


MAX_DESKTOP_SAVE_BYTES = 100 * 1024 * 1024


class DesktopApi:
    """JS-callable bridge exposed to the desktop UI via pywebview."""

    def __init__(self, webview_module: Any = None) -> None:
        self._webview = webview_module
        self._window: Any = None

    def attach_window(self, window: Any) -> None:
        """Bind the created pywebview Window instance after window creation."""
        self._window = window

    def _decode_bounded_base64(self, content_base64: str) -> bytes:
        if not isinstance(content_base64, str):
            raise ValueError("Invalid export payload")
        # Base64 expands 3 bytes to 4 chars; reject oversized payloads before decoding.
        if len(content_base64) > (MAX_DESKTOP_SAVE_BYTES * 4 // 3) + 8:
            raise ValueError("Export exceeds desktop save size limit")
        raw = base64.b64decode(content_base64)
        if len(raw) > MAX_DESKTOP_SAVE_BYTES:
            raise ValueError("Export exceeds desktop save size limit")
        return raw

    def save_file(self, filename: str, content_base64: str) -> dict[str, object]:
        """Open a native Save dialog with a preserved extension and write the file."""
        if self._window is None:
            return {"saved": False, "cancelled": False, "error": "Window is not ready"}
        try:
            raw = self._decode_bounded_base64(content_base64)
        except ValueError as exc:
            return {"saved": False, "cancelled": False, "error": str(exc)}
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

        target.write_bytes(raw)
        return {"saved": True, "cancelled": False, "path": str(target), "filename": target.name}

    def download_file(self, filename: str, content_base64: str) -> dict[str, object]:
        """Save file directly into native Windows Downloads with a unique filename (no manual prompt)."""
        from fwmigrate.web_support.desktop_downloads import get_downloads_dir, unique_export_path

        try:
            raw = self._decode_bounded_base64(content_base64)
        except ValueError as exc:
            return {"saved": False, "cancelled": False, "error": str(exc)}
        safe_name = Path(filename or "export.xlsx").name or "export.xlsx"
        stem = Path(safe_name).stem or "export"
        ext = Path(safe_name).suffix or ".xlsx"
        downloads_dir = get_downloads_dir()
        target = unique_export_path(downloads_dir, stem, ext)
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


def _get_primary_dpi_scale(primary_screen: Any) -> float:
    """Return the primary display DPI scale factor (>= 1.0)."""
    if sys.platform == "win32":
        try:
            dpi = int(ctypes.windll.user32.GetDpiForSystem())
            if dpi > 0:
                return max(1.0, dpi / 96.0)
        except Exception:
            pass
    try:
        scale = float(getattr(primary_screen, "scale", 1.0) or 1.0)
    except (TypeError, ValueError):
        scale = 1.0
    return max(1.0, scale)


def _window_state_path() -> Path:
    """Return the local JSON path used to persist desktop window size and maximized state."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
    else:
        base = Path.home() / ".config"
    return base / "FirewallMigrationTool" / "window_state.json"


def _load_window_state(path: Path | None = None) -> dict[str, Any]:
    """Load persisted desktop window state, returning an empty dict if missing or invalid."""
    target = path or _window_state_path()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    result: dict[str, Any] = {}
    if isinstance(raw.get("maximized"), bool):
        result["maximized"] = raw["maximized"]
    for key in ("width", "height"):
        val = raw.get(key)
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            result[key] = val
    return result


def _save_window_state(state: dict[str, Any], path: Path | None = None) -> None:
    """Persist desktop window state cleanly to local storage."""
    target = path or _window_state_path()
    payload = {
        "maximized": bool(state.get("maximized", False)),
        "width": int(state.get("width", 1200)),
        "height": int(state.get("height", 760)),
    }
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        pass


def _compute_window_geometry(
    webview_module: Any,
    saved_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute a logical-pixel window size fitted to the primary screen so pywebview centers it."""
    saved = saved_state or {}
    screens = getattr(webview_module, "screens", None) or []
    if not screens:
        default_w, default_h = 1200, 760
        max_w, max_h = 3840, 2160
    else:
        primary = screens[0]
        screen_w = int(getattr(primary, "width", 1440))
        screen_h = int(getattr(primary, "height", 900))
        dpi_scale = _get_primary_dpi_scale(primary)
        logical_w = max(1, int(round(screen_w / dpi_scale)))
        logical_h = max(1, int(round(screen_h / dpi_scale)))
        default_w = max(1, min(1440, int(logical_w * 0.88)))
        default_h = max(1, min(900, int(logical_h * 0.85)))
        max_w, max_h = logical_w, logical_h

    saved_w = saved.get("width")
    saved_h = saved.get("height")
    if isinstance(saved_w, int) and isinstance(saved_h, int) and saved_w > 0 and saved_h > 0:
        min_w = min(800, max_w)
        min_h = min(600, max_h)
        width = max(min_w, min(max_w, saved_w))
        height = max(min_h, min(max_h, saved_h))
    else:
        width = default_w
        height = default_h

    # Omit x, y, and screen so WinForms uses CenterScreen on the primary monitor's WorkingArea.
    geometry: dict[str, Any] = {
        "width": width,
        "height": height,
        "min_size": (min(800, width), min(600, height)),
    }
    if saved.get("maximized") is True:
        geometry["maximized"] = True
    return geometry


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
            from fwmigrate.web_support.local_server import KeepAliveWSGIRequestHandler

            app = create_app()
            server = None
            for candidate_port in (5000, 5001, 5002, 5003, 5004, 5005, 0):
                try:
                    server = make_server(
                        "127.0.0.1",
                        candidate_port,
                        app,
                        threaded=True,
                        request_handler=KeepAliveWSGIRequestHandler,
                    )
                    break
                except OSError:
                    continue
            assert server is not None
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            state["server"] = server
            state["server_thread"] = server_thread
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
    server_thread = backend_state.get("server_thread")
    if server_thread is None:
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)  # type: ignore[attr-defined]
        server_thread.start()
    url = str(backend_state["url"])

    try:
        if args.browser or webview is None:
            _close_splash()
            webbrowser.open(url)
            server_thread.join()
            return 0

        webview.settings["ALLOW_DOWNLOADS"] = True
        api = DesktopApi(webview)
        saved_state = _load_window_state()
        geometry = _compute_window_geometry(webview, saved_state=saved_state)
        window = webview.create_window(
            "Firewall Migration Tool",
            url,
            js_api=api,
            resizable=True,
            text_select=True,
            zoomable=True,
            **geometry,
        )
        api.attach_window(window)
        window_state: dict[str, Any] = {
            "maximized": bool(geometry.get("maximized", False)),
            "width": int(geometry["width"]),
            "height": int(geometry["height"]),
        }
        is_minimized = False

        def _on_maximized(*_args: Any) -> None:
            nonlocal is_minimized
            is_minimized = False
            window_state["maximized"] = True

        def _on_minimized(*_args: Any) -> None:
            nonlocal is_minimized
            is_minimized = True

        def _on_restored(*_args: Any) -> None:
            nonlocal is_minimized
            is_minimized = False
            window_state["maximized"] = False

        def _on_resized(*args: Any) -> None:
            if window_state["maximized"] or is_minimized:
                return
            if len(args) >= 2 and isinstance(args[0], (int, float)) and isinstance(args[1], (int, float)):
                w, h = int(args[0]), int(args[1])
            else:
                w = int(getattr(window, "width", 0) or 0)
                h = int(getattr(window, "height", 0) or 0)
            if w >= 400 and h >= 300:
                window_state["width"] = w
                window_state["height"] = h

        def _on_closing(*_args: Any) -> None:
            _save_window_state(window_state)

        events = getattr(window, "events", None)
        if events is not None:
            if hasattr(events, "maximized"):
                events.maximized += _on_maximized
            if hasattr(events, "minimized"):
                events.minimized += _on_minimized
            if hasattr(events, "restored"):
                events.restored += _on_restored
            if hasattr(events, "resized"):
                events.resized += _on_resized
            if hasattr(events, "closing"):
                events.closing += _on_closing

        if events is not None and hasattr(events, "shown"):
            events.shown += _close_splash
            webview.start(private_mode=True)
        else:
            webview.start(func=_close_splash, private_mode=True)
        return 0
    finally:
        _close_splash()
        try:
            from fwmigrate.web_support.chat_service import chat_store

            chat_store.clear_all()
        except Exception:
            pass
        server.shutdown()  # type: ignore[attr-defined]


if __name__ == "__main__":
    raise SystemExit(main())
