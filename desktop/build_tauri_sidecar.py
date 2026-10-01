"""Build the PyInstaller backend using Tauri's target-triple sidecar naming."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "desktop" / "fwmigrate-backend.spec"
BINARIES = ROOT / "src" / "frontend" / "src-tauri" / "binaries"


def main() -> None:
    subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", str(SPEC)],
        cwd=ROOT,
        check=True,
    )
    target = subprocess.check_output(
        ["rustc", "--print", "host-tuple"],
        cwd=ROOT,
        text=True,
    ).strip()
    if not target:
        raise RuntimeError("rustc did not report a host target triple")

    extension = ".exe" if os.name == "nt" else ""
    source = ROOT / "dist" / f"fwmigrate-backend{extension}"
    if not source.is_file():
        raise FileNotFoundError(source)

    BINARIES.mkdir(parents=True, exist_ok=True)
    destination = BINARIES / f"fwmigrate-backend-{target}{extension}"
    shutil.copy2(source, destination)
    print(destination)


if __name__ == "__main__":
    main()
