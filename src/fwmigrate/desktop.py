"""Desktop-shell integration for the Flask application."""

from __future__ import annotations


class DesktopAPI:
    """JS bridge API exposed to the pywebview desktop frontend."""

    def __init__(self, window=None):
        self._window = window

    def set_window(self, window):
        self._window = window

    def save_file_dialog(self, filename: str, base64_data: str) -> dict:
        """Prompt with a native Save File dialog and write the selected file."""
        import base64
        import os
        from pathlib import Path

        try:
            import webview

            raw_bytes = base64.b64decode(base64_data)
            ext = Path(filename).suffix.lower()
            if ext == ".zip":
                file_types = ("Zip Archive (*.zip)", "All files (*.*)")
            elif ext == ".xlsx":
                file_types = ("Excel Workbook (*.xlsx)", "All files (*.*)")
            elif ext == ".json":
                file_types = ("JSON (*.json)", "All files (*.*)")
            elif ext == ".md":
                file_types = ("Markdown (*.md)", "All files (*.*)")
            else:
                file_types = ("All files (*.*)",)

            default_dir = str(Path.home() / "Downloads")
            if not os.path.exists(default_dir):
                default_dir = str(Path.home() / "Desktop")

            save_path = None
            if self._window:
                dialog_type = getattr(webview, "FileDialog", None)
                save_enum = (
                    webview.FileDialog.SAVE
                    if dialog_type and hasattr(dialog_type, "SAVE")
                    else getattr(webview, "SAVE_DIALOG", 30)
                )
                result = self._window.create_file_dialog(
                    dialog_type=save_enum,
                    directory=default_dir,
                    save_filename=filename,
                    file_types=file_types,
                )
                if result:
                    save_path = result[0] if isinstance(result, (list, tuple)) else result

            if not save_path:
                return {"success": False, "cancelled": True}

            with open(save_path, "wb") as output:
                output.write(raw_bytes)

            return {"success": True, "path": str(save_path)}
        except Exception as exc:
            return {"success": False, "error": str(exc)}


def run_desktop(port: int = 5000):
    """Launch the app inside a dedicated native desktop window via pywebview."""
    from fwmigrate.web import create_app

    app = create_app()
    try:
        import webview

        api = DesktopAPI()
        window = webview.create_window(
            title="Firewall Migration Tool",
            url=app,
            width=1360,
            height=880,
            min_size=(960, 640),
            text_select=True,
            js_api=api,
        )
        api.set_window(window)
        webview.start(gui="edgechromium")
    except ImportError:
        import webbrowser

        print(f"pywebview is not installed. Opening in default browser at http://localhost:{port}")
        webbrowser.open(f"http://localhost:{port}")
        app.run(host="127.0.0.1", port=port, debug=False)
