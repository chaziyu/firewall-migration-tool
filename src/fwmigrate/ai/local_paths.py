"""User data and packaged paths for local inference assets."""

import os
import sys
from pathlib import Path


def local_ai_data_dir() -> Path:
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or Path.home() / "AppData" / "Local"
        return Path(root) / "FirewallMigrationTool" / "ai"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "FirewallMigrationTool" / "ai"
    root = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(root) / "firewall-migration-tool" / "ai"


def bundled_runtime_dir() -> Path:
    root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))
    return root / "fwmigrate" / "ai_runtime" / "windows-x64"
