"""Tests for the desktop launcher pywebview bridge."""

from __future__ import annotations

import base64
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from fwmigrate.web_support.chat_service import chat_store
from scripts import desktop_launcher
from scripts.desktop_launcher import DesktopApi


class _FakeWindow:
    def __init__(self, dialog_result: object = None) -> None:
        self.resized: list[tuple[int, int]] = []
        self.maximized_calls = 0
        self.restored_calls = 0
        self.dialog_calls: list[dict[str, object]] = []
        self._dialog_result = dialog_result

    def resize(self, width: int, height: int) -> None:
        self.resized.append((width, height))

    def maximize(self) -> None:
        self.maximized_calls += 1

    def restore(self) -> None:
        self.restored_calls += 1

    def create_file_dialog(
        self,
        dialog_type: int,
        *,
        save_filename: str = "",
        file_types: tuple[str, ...] = (),
    ) -> object:
        self.dialog_calls.append(
            {
                "dialog_type": dialog_type,
                "save_filename": save_filename,
                "file_types": file_types,
            }
        )
        return self._dialog_result


def _fake_webview() -> SimpleNamespace:
    return SimpleNamespace(FileDialog=SimpleNamespace(SAVE=30), SAVE_DIALOG=30)


def test_desktop_api_save_file_appends_xlsx_when_missing(tmp_path: Path) -> None:
    chosen_without_ext = tmp_path / "my-report"
    window = _FakeWindow(dialog_result=[str(chosen_without_ext)])
    api = DesktopApi(_fake_webview())
    api.attach_window(window)

    payload = b"PK\x03\x04fake-xlsx-bytes"
    encoded = base64.b64encode(payload).decode("ascii")
    result = api.save_file("fortigate-source-report.xlsx", encoded)

    expected_path = tmp_path / "my-report.xlsx"
    assert result["saved"] is True
    assert result["cancelled"] is False
    assert result["filename"] == "my-report.xlsx"
    assert Path(str(result["path"])) == expected_path
    assert expected_path.read_bytes() == payload
    assert window.dialog_calls[0]["save_filename"] == "fortigate-source-report.xlsx"
    assert window.dialog_calls[0]["file_types"] == ("Excel Workbook (*.xlsx)", "All files (*.*)")


def test_desktop_api_save_file_cancelled(tmp_path: Path) -> None:
    window = _FakeWindow(dialog_result=None)
    api = DesktopApi(_fake_webview())
    api.attach_window(window)

    result = api.save_file("fortigate-source-report.xlsx", base64.b64encode(b"abc").decode("ascii"))
    assert result == {"saved": False, "cancelled": True}
    assert list(tmp_path.iterdir()) == []


class _FakeEvent:
    def __init__(self) -> None:
        self.handlers: list[object] = []

    def __iadd__(self, handler: object) -> _FakeEvent:
        self.handlers.append(handler)
        return self

    def emit(self, *args: object) -> None:
        for handler in self.handlers:
            handler(*args)  # type: ignore[operator]


@pytest.mark.parametrize("with_events", [True, False])
def test_desktop_launcher_uses_private_mode_and_clears_chat_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, with_events: bool
) -> None:
    create_calls: list[dict[str, object]] = []
    start_calls: list[dict[str, object]] = []
    shutdown_calls: list[bool] = []

    class _FakeServer:
        def serve_forever(self) -> None:
            return None

        def shutdown(self) -> None:
            shutdown_calls.append(True)

    def _fake_start_backend() -> tuple[threading.Event, dict[str, object]]:
        ready = threading.Event()
        ready.set()
        return ready, {"server": _FakeServer(), "url": "http://127.0.0.1:5000/"}

    def _create_window(*_args: object, **kwargs: object) -> object:
        create_calls.append(kwargs)
        if with_events:
            return SimpleNamespace(events=SimpleNamespace(shown=_FakeEvent()))
        return SimpleNamespace()

    def _start(*_args: object, **kwargs: object) -> None:
        start_calls.append(kwargs)

    fake_webview = SimpleNamespace(
        settings={},
        screens=[],
        create_window=_create_window,
        start=_start,
    )

    chat_store.clear_all()
    sess, _ = chat_store.get_or_create(None)
    sess.gemini_api_key = "synthetic-key"
    assert chat_store.get(sess.session_id) is not None

    monkeypatch.setenv("FWMIGRATE_WEB_MODE", "local")
    monkeypatch.setenv("FWMIGRATE_FRONTEND_DIST_DIR", str(desktop_launcher._resolve_frontend_dist()))
    monkeypatch.setitem(sys.modules, "webview", fake_webview)
    monkeypatch.setattr(desktop_launcher, "_start_backend_async", _fake_start_backend)
    monkeypatch.setattr(desktop_launcher, "_window_state_path", lambda: tmp_path / "window_state.json")

    try:
        assert desktop_launcher.main([]) == 0
        assert len(create_calls) == 1
        assert create_calls[0]["text_select"] is True
        assert len(start_calls) == 1
        assert start_calls[0]["private_mode"] is True
        if not with_events:
            assert start_calls[0]["func"] is desktop_launcher._close_splash
        assert shutdown_calls == [True]
        assert chat_store.get(sess.session_id) is None
    finally:
        chat_store.clear_all()


def test_compute_window_geometry_scales_for_high_dpi_and_uses_center_screen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scale = 130 / 96.0
    monkeypatch.setattr(desktop_launcher, "_get_primary_dpi_scale", lambda _screen: scale)
    fake_webview = SimpleNamespace(
        screens=[SimpleNamespace(x=0, y=0, width=1920, height=1080, scale=1.0)]
    )

    geometry = desktop_launcher._compute_window_geometry(fake_webview)

    assert "x" not in geometry
    assert "y" not in geometry
    assert "screen" not in geometry
    assert geometry["width"] * scale <= 1920
    assert geometry["height"] * scale <= 1080
    assert geometry["min_size"] == (min(800, geometry["width"]), min(600, geometry["height"]))


def test_compute_window_geometry_at_96_dpi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(desktop_launcher, "_get_primary_dpi_scale", lambda _screen: 1.0)
    fake_webview = SimpleNamespace(
        screens=[SimpleNamespace(x=0, y=0, width=1920, height=1080, scale=1.0)]
    )

    geometry = desktop_launcher._compute_window_geometry(fake_webview)

    assert geometry == {
        "width": 1440,
        "height": 900,
        "min_size": (800, 600),
    }


def test_window_state_round_trip_and_invalid_files(tmp_path: Path) -> None:
    state_file = tmp_path / "nested" / "window_state.json"
    assert desktop_launcher._load_window_state(state_file) == {}

    desktop_launcher._save_window_state({"maximized": True, "width": 1320, "height": 840}, state_file)
    assert desktop_launcher._load_window_state(state_file) == {
        "maximized": True,
        "width": 1320,
        "height": 840,
    }

    state_file.write_text("{not-valid-json", encoding="utf-8")
    assert desktop_launcher._load_window_state(state_file) == {}


def test_compute_window_geometry_restores_maximized_and_clamps_saved_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(desktop_launcher, "_get_primary_dpi_scale", lambda _screen: 130 / 96.0)
    fake_webview = SimpleNamespace(
        screens=[SimpleNamespace(x=0, y=0, width=1920, height=1080, scale=1.0)]
    )

    geometry = desktop_launcher._compute_window_geometry(
        fake_webview,
        saved_state={"maximized": True, "width": 2400, "height": 1500},
    )

    assert geometry["maximized"] is True
    assert geometry["width"] == 1418
    assert geometry["height"] == 798


def test_desktop_launcher_restores_and_saves_window_state_events(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state_file = tmp_path / "window_state.json"
    desktop_launcher._save_window_state({"maximized": True, "width": 1100, "height": 700}, state_file)

    create_calls: list[dict[str, object]] = []
    window_events = SimpleNamespace(
        shown=_FakeEvent(),
        maximized=_FakeEvent(),
        minimized=_FakeEvent(),
        restored=_FakeEvent(),
        resized=_FakeEvent(),
        closing=_FakeEvent(),
    )

    class _FakeServer:
        def serve_forever(self) -> None:
            return None

        def shutdown(self) -> None:
            return None

    def _fake_start_backend() -> tuple[threading.Event, dict[str, object]]:
        ready = threading.Event()
        ready.set()
        return ready, {"server": _FakeServer(), "url": "http://127.0.0.1:5000/"}

    def _create_window(*_args: object, **kwargs: object) -> object:
        create_calls.append(kwargs)
        return SimpleNamespace(events=window_events)

    def _start(*_args: object, **_kwargs: object) -> None:
        window_events.restored.emit()
        window_events.resized.emit(1024, 720)
        window_events.maximized.emit()
        window_events.resized.emit(1920, 1080)
        window_events.closing.emit()

    fake_webview = SimpleNamespace(settings={}, screens=[], create_window=_create_window, start=_start)

    monkeypatch.setenv("FWMIGRATE_WEB_MODE", "local")
    monkeypatch.setenv("FWMIGRATE_FRONTEND_DIST_DIR", str(desktop_launcher._resolve_frontend_dist()))
    monkeypatch.setitem(sys.modules, "webview", fake_webview)
    monkeypatch.setattr(desktop_launcher, "_start_backend_async", _fake_start_backend)
    monkeypatch.setattr(desktop_launcher, "_window_state_path", lambda: state_file)

    assert desktop_launcher.main([]) == 0
    assert create_calls[0]["maximized"] is True
    assert create_calls[0]["width"] == 1100
    assert create_calls[0]["height"] == 700
    assert desktop_launcher._load_window_state(state_file) == {
        "maximized": True,
        "width": 1024,
        "height": 720,
    }
