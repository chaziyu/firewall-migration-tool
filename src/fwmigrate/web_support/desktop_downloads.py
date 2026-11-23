"""Native Windows Downloads resolution and non-colliding filename helpers."""

from __future__ import annotations

import sys
from pathlib import Path


def get_downloads_dir() -> Path:
    """Return the user's Downloads directory (Windows Known Folder with Path.home fallback)."""
    if sys.platform == "win32":
        try:
            import ctypes
            from ctypes import wintypes

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            # FOLDERID_Downloads = {374DE290-123F-4565-9164-39C4925E467B}
            downloads_guid = GUID(
                0x374DE290,
                0x123F,
                0x4565,
                (ctypes.c_ubyte * 8)(0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B),
            )
            path_ptr = ctypes.c_wchar_p()
            hr = ctypes.windll.shell32.SHGetKnownFolderPath(
                ctypes.byref(downloads_guid), 0, None, ctypes.byref(path_ptr)
            )
            if hr == 0 and path_ptr.value:
                result = Path(path_ptr.value)
                ctypes.windll.ole32.CoTaskMemFree(path_ptr)
                result.mkdir(parents=True, exist_ok=True)
                return result
        except Exception:
            pass
    fallback = Path.home() / "Downloads"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def unique_export_path(directory: Path, stem: str, ext: str = ".xlsx") -> Path:
    """Return a non-colliding path in *directory*, appending -1, -2, ... if needed."""
    normalized_ext = ext if not ext or ext.startswith(".") else f".{ext}"
    candidate = directory / f"{stem}{normalized_ext}"
    if not candidate.exists():
        return candidate
    idx = 1
    while True:
        candidate = directory / f"{stem}-{idx}{normalized_ext}"
        if not candidate.exists():
            return candidate
        idx += 1
