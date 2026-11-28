"""GitHub Releases update checker, SHA-256 verified downloader, and silent self-updater."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import tomllib
import urllib.error
import urllib.request
from importlib import metadata
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT_DIR = Path(__file__).resolve().parents[3]
GITHUB_REPO = os.environ.get("FWMIGRATE_GITHUB_REPO", "chaziyu/firewall-migration-tool")
ALLOWED_DOWNLOAD_HOSTS = frozenset({
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
})


def get_app_version() -> str:
    """Resolve current application version from pyproject.toml or installed package metadata."""
    pyproject = ROOT_DIR / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            ver = str(data.get("project", {}).get("version") or "").strip()
            if ver:
                return ver
        except Exception:
            pass
    try:
        return metadata.version("firewall-migration-tool")
    except Exception:
        return "0.2.6"


APP_VERSION = get_app_version()


def parse_version_tuple(ver_str: str) -> tuple[int, ...]:
    """Parse 'v0.2.3' or '0.2.3' into a tuple of ints for comparison."""
    cleaned = ver_str.strip().lstrip("vV").split("-")[0]
    parts = []
    for segment in cleaned.split("."):
        match = re.match(r"^(\d+)", segment)
        parts.append(int(match.group(1)) if match else 0)
    return tuple(parts) or (0,)


def is_newer_version(latest: str, current: str | None = None) -> bool:
    return parse_version_tuple(latest) > parse_version_tuple(current or APP_VERSION)


def is_frozen_desktop_exe() -> bool:
    """Return True only when running inside a packaged PyInstaller Windows .exe."""
    return sys.platform == "win32" and bool(getattr(sys, "frozen", False))


def is_local_git_checkout() -> bool:
    """Return True when running from a local git clone with git available on PATH."""
    return not is_frozen_desktop_exe() and (ROOT_DIR / ".git").exists() and shutil.which("git") is not None


def get_runtime_mode(is_loopback: bool) -> str:
    """Return 'cloud' | 'desktop' | 'source'."""
    if not is_loopback:
        return "cloud"
    if is_frozen_desktop_exe():
        return "desktop"
    return "source"


def check_for_updates(timeout: float = 4.0, *, is_loopback: bool = True) -> dict[str, Any]:
    """Query GitHub Releases API for the latest release."""
    mode = get_runtime_mode(is_loopback)
    current_version = APP_VERSION
    if mode == "cloud":
        return {
            "mode": "cloud",
            "checked": True,
            "current_version": current_version,
            "latest_version": current_version,
            "update_available": False,
            "can_auto_install": False,
        }

    api_url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    req = urllib.request.Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"FirewallMigrationTool/{current_version}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "mode": mode,
                "checked": True,
                "current_version": current_version,
                "latest_version": current_version,
                "update_available": False,
                "can_auto_install": False,
            }
        return {
            "mode": mode,
            "checked": False,
            "current_version": current_version,
            "update_available": False,
            "can_auto_install": False,
            "error": f"GitHub API returned HTTP {exc.code}",
        }
    except Exception as exc:
        return {
            "mode": mode,
            "checked": False,
            "current_version": current_version,
            "update_available": False,
            "can_auto_install": False,
            "error": str(exc),
        }

    tag = str(data.get("tag_name") or "").strip()
    latest_ver = tag.lstrip("vV") or current_version
    html_url = str(data.get("html_url") or f"https://github.com/{GITHUB_REPO}/releases")
    body = str(data.get("body") or "").strip()

    installer_asset = None
    portable_asset = None
    sums_asset = None
    for asset in data.get("assets") or []:
        name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        lowered = name.lower()
        if lowered.startswith("firewallmigrationtool-setup-") and lowered.endswith(".exe"):
            installer_asset = {"name": name, "url": url, "size": int(asset.get("size") or 0)}
        elif lowered == "firewallmigrationtool.exe":
            portable_asset = {"name": name, "url": url, "size": int(asset.get("size") or 0)}
        elif name == "SHA256SUMS.txt":
            sums_asset = {"name": name, "url": url}

    selected_asset = installer_asset or portable_asset
    newer = is_newer_version(latest_ver, current_version)
    can_install = False
    install_method = None
    if newer:
        if mode == "desktop" and selected_asset:
            can_install = True
            install_method = "installer" if installer_asset else "portable_replace"
        elif mode == "source" and is_local_git_checkout():
            can_install = True
            install_method = "git_pull"

    return {
        "mode": mode,
        "checked": True,
        "current_version": current_version,
        "latest_version": latest_ver,
        "update_available": newer,
        "release_url": html_url,
        "release_notes": body[:1000],
        "installer_asset": installer_asset,
        "portable_asset": portable_asset,
        "sums_asset": sums_asset,
        "can_auto_install": can_install,
        "install_method": install_method,
    }


def _validate_github_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError(f"Refusing to download update from untrusted host: {parsed.hostname}")


def _download_bytes(url: str, timeout: float = 60.0) -> bytes:
    _validate_github_url(url)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"FirewallMigrationTool/{APP_VERSION}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _verify_sha256(file_bytes: bytes, filename: str, sums_text: str) -> bool:
    actual = hashlib.sha256(file_bytes).hexdigest().lower()
    for line in sums_text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1].strip("*") == filename:
            expected = parts[0].strip().lower()
            return actual == expected
    return False


def _verify_authenticode_if_required(exe_path: Path) -> None:
    """Optionally verify Windows Authenticode signature when FWMIGRATE_REQUIRE_SIGNED_UPDATES=1."""
    require_signed = str(os.environ.get("FWMIGRATE_REQUIRE_SIGNED_UPDATES", "")).strip().lower() in {
        "1", "true", "yes", "on",
    }
    if not require_signed:
        return
    if sys.platform != "win32":
        raise RuntimeError("Signed update verification is only supported on Windows.")
    escaped = str(exe_path).replace("'", "''")
    res = subprocess.run(
        [
            "powershell", "-NoProfile", "-Command",
            f"(Get-AuthenticodeSignature -LiteralPath '{escaped}').Status",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    status = (res.stdout or "").strip()
    if res.returncode != 0 or status != "Valid":
        raise RuntimeError(f"Update executable failed Authenticode signature check (status: {status or 'unknown'}).")


def _run_git_pull_update(latest_version: str) -> dict[str, Any]:
    """Pull latest changes via git fast-forward when running from a local git repository."""
    if not is_local_git_checkout():
        raise RuntimeError("Local directory is not a git repository.")
    res = subprocess.run(
        ["git", "pull", "--ff-only"],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=30,
    )
    if res.returncode != 0:
        err = (res.stderr or res.stdout or "git pull failed").strip()
        raise RuntimeError(f"git pull failed: {err}")
    return {
        "ok": True,
        "method": "git_pull",
        "latest_version": latest_version,
        "message": f"Updated local repository to v{latest_version} via git pull. Restart the local server to apply.",
    }


def download_and_trigger_install() -> dict[str, Any]:
    """Execute the appropriate update mechanism for the current runtime mode (desktop .exe vs local git source)."""
    info = check_for_updates(timeout=8.0, is_loopback=True)
    if not info.get("checked"):
        raise RuntimeError(info.get("error") or "Unable to reach GitHub Releases.")
    if not info.get("update_available"):
        raise RuntimeError(f"Already on the latest version (v{APP_VERSION}).")

    if not is_frozen_desktop_exe():
        if is_local_git_checkout():
            return _run_git_pull_update(info["latest_version"])
        raise RuntimeError(
            "Running from unpacked source without git. Download the latest release from GitHub Releases."
        )

    installer = info.get("installer_asset")
    portable = info.get("portable_asset")
    target_asset = installer or portable
    if not target_asset or not target_asset.get("url"):
        raise RuntimeError("No Windows executable asset found on the latest GitHub Release.")

    update_dir = Path(tempfile.gettempdir()) / "fw_migration_tool_update"
    update_dir.mkdir(parents=True, exist_ok=True)
    exe_name = Path(target_asset["name"]).name
    exe_path = update_dir / exe_name

    exe_bytes = _download_bytes(target_asset["url"], timeout=120.0)
    if len(exe_bytes) < 1024 or not exe_bytes.startswith(b"MZ"):
        raise RuntimeError("Downloaded executable is invalid or corrupted.")

    sums_asset = info.get("sums_asset")
    if not (sums_asset and sums_asset.get("url")):
        raise RuntimeError("Release is missing required SHA256SUMS.txt checksum manifest.")
    sums_bytes = _download_bytes(sums_asset["url"], timeout=15.0)
    sums_text = sums_bytes.decode("utf-8", errors="replace")
    if not _verify_sha256(exe_bytes, exe_name, sums_text):
        raise RuntimeError("SHA-256 checksum verification failed for downloaded update.")

    exe_path.write_bytes(exe_bytes)
    try:
        _verify_authenticode_if_required(exe_path)
    except Exception:
        exe_path.unlink(missing_ok=True)
        raise
    current_exe = sys.executable
    batch_path = update_dir / "run_update.cmd"
    if installer:
        batch_contents = (
            "@echo off\r\n"
            "ping 127.0.0.1 -n 3 > nul\r\n"
            f'"{exe_path}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS\r\n'
            f'start "" "{current_exe}"\r\n'
        )
    else:
        batch_contents = (
            "@echo off\r\n"
            "ping 127.0.0.1 -n 3 > nul\r\n"
            f'move /Y "{exe_path}" "{current_exe}"\r\n'
            f'start "" "{current_exe}"\r\n'
        )
    batch_path.write_text(batch_contents, encoding="utf-8")

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
        subprocess, "DETACHED_PROCESS", 0
    )
    subprocess.Popen(
        ["cmd.exe", "/c", str(batch_path)],
        creationflags=creationflags,
        close_fds=True,
    )

    threading.Timer(0.6, lambda: os._exit(0)).start()

    return {
        "ok": True,
        "method": "installer" if installer else "portable_replace",
        "latest_version": info["latest_version"],
        "installer_path": str(exe_path),
        "message": f"Update v{info['latest_version']} verified and launched. Restarting automatically…",
    }
