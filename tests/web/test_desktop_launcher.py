"""Tests for the desktop launcher pywebview bridge."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

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
