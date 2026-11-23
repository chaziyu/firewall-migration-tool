"""Tests for native Windows download helper, auto-updater endpoints, and AI chatbox API."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from fwmigrate.web import create_app
from fwmigrate.web_support import chat_service, desktop_downloads, update_service


def test_unique_export_path_avoids_collisions(tmp_path: Path):
    first = desktop_downloads.unique_export_path(tmp_path, "edge_report", ".xlsx")
    assert first == tmp_path / "edge_report.xlsx"
    first.write_bytes(b"1")
    second = desktop_downloads.unique_export_path(tmp_path, "edge_report", ".xlsx")
    assert second == tmp_path / "edge_report-1.xlsx"
    second.write_bytes(b"2")
    third = desktop_downloads.unique_export_path(tmp_path, "edge_report", ".xlsx")
    assert third == tmp_path / "edge_report-2.xlsx"


def test_desktop_api_download_file_saves_directly_without_dialog(tmp_path: Path, monkeypatch):
    scripts_dir = Path(__file__).resolve().parents[2] / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import desktop_launcher

    monkeypatch.setattr(desktop_downloads, "get_downloads_dir", lambda: tmp_path)

    class NeverDialogWindow:
        def create_file_dialog(self, *_args, **_kwargs):
            raise AssertionError("Manual Save dialog must not be opened by download_file")

    api = desktop_launcher.DesktopApi()
    api.attach_window(NeverDialogWindow())
    payload = base64.b64encode(b"PK\x03\x04workbook").decode("ascii")

    res1 = api.download_file("edge-fortigate-report.xlsx", payload)
    res2 = api.download_file("edge-fortigate-report.xlsx", payload)
    assert res1["saved"] is True
    assert res1["filename"] == "edge-fortigate-report.xlsx"
    assert Path(str(res1["path"])).read_bytes() == b"PK\x03\x04workbook"
    assert res2["filename"] == "edge-fortigate-report-1.xlsx"
    assert Path(str(res2["path"])).exists()


def test_update_endpoints_enforce_cloud_guard_and_parse_release(monkeypatch):
    public_client = create_app({"TESTING": True, "WEB_MODE": "public"}).test_client()
    cloud_check = public_client.get("/api/update/check")
    assert cloud_check.status_code == 200
    assert cloud_check.get_json()["mode"] == "cloud"
    assert cloud_check.get_json()["update_available"] is False
    assert public_client.post("/api/update/install").status_code == 403

    release_json = {
        "tag_name": "v9.9.9",
        "html_url": "https://github.com/chaziyu/firewall-migration-tool/releases/tag/v9.9.9",
        "body": "Bug fixes and improvements",
        "assets": [
            {
                "name": "FirewallMigrationTool-Setup-9.9.9.exe",
                "browser_download_url": "https://github.com/chaziyu/firewall-migration-tool/releases/download/v9.9.9/FirewallMigrationTool-Setup-9.9.9.exe",
                "size": 4096,
            },
            {
                "name": "SHA256SUMS.txt",
                "browser_download_url": "https://github.com/chaziyu/firewall-migration-tool/releases/download/v9.9.9/SHA256SUMS.txt",
            },
        ],
    }

    class FakeResp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(
        update_service.urllib.request,
        "urlopen",
        lambda req, timeout=4.0: FakeResp(json.dumps(release_json).encode("utf-8")),
    )
    monkeypatch.setattr(update_service, "is_frozen_desktop_exe", lambda: True)
    info = update_service.check_for_updates(is_loopback=True)
    assert info["mode"] == "desktop"
    assert info["update_available"] is True
    assert info["can_auto_install"] is True
    assert info["install_method"] == "installer"

    raw_exe = b"MZ" + (b"\x90" * 2048)
    digest = hashlib.sha256(raw_exe).hexdigest()
    assert update_service._verify_sha256(raw_exe, "FirewallMigrationTool-Setup-9.9.9.exe", f"{digest}  FirewallMigrationTool-Setup-9.9.9.exe\n")
    assert not update_service._verify_sha256(raw_exe, "FirewallMigrationTool-Setup-9.9.9.exe", f"{'0' * 64}  FirewallMigrationTool-Setup-9.9.9.exe\n")

    local_client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    monkeypatch.setattr(update_service, "is_frozen_desktop_exe", lambda: False)
    monkeypatch.setattr(update_service, "is_local_git_checkout", lambda: True)
    monkeypatch.setattr(
        update_service.subprocess,
        "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout="Already up to date.\n", stderr=""),
    )
    res = local_client.post("/api/update/install", base_url="http://127.0.0.1:5000")
    assert res.status_code == 200
    assert res.get_json()["method"] == "git_pull"


def test_chat_endpoints_key_isolation_summary_and_history(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaENV_KEY_LOCAL_ONLY_123456")

    public_client = create_app({"TESTING": True, "WEB_MODE": "public"}).test_client()
    state_pub = public_client.get("/api/chat").get_json()
    assert state_pub["key_status"]["configured"] is False

    local_client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    state_loc = local_client.get("/api/chat", base_url="http://127.0.0.1:5000").get_json()
    assert state_loc["key_status"]["configured"] is True
    assert state_loc["key_status"]["source"] == "local-env"

    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    set_res = public_client.post("/api/chat/key", json={"api_key": "AIzaSessionKey_999999"})
    assert set_res.status_code == 200
    assert set_res.get_json()["key_status"]["configured"] is True
    assert set_res.get_json()["key_status"]["source"] == "session"

    monkeypatch.setattr(chat_service, "_call_gemini", lambda **_kwargs: "**ALLOW** via `port1`.")
    ask_res = public_client.post(
        "/api/chat",
        json={
            "question": "Which policy matches?",
            "vendor": "palo_alto",
            "filename": "fortigate.conf",
            "source_text": "config firewall policy\n  edit 1\n  next\nend\n",
            "preview": {
                "summary": {"hostname": "fg-branch", "objects": {"policies": 1}},
                "sections": {"policies": [{"policy_id": 1, "srcintf": ["port1"], "action": "accept"}]},
            },
        },
    )
    assert ask_res.status_code == 200
    data = ask_res.get_json()
    assert data["ok"] is True
    assert data["reply"] == "**ALLOW** via `port1`."
    assert len(data["history"]) == 2
    assert "Looks like fortigate" in (data["vendor_mismatch"] or "").replace("looks like fortigate", "Looks like fortigate")

    del_res = public_client.delete("/api/chat")
    assert del_res.status_code == 200
    assert public_client.get("/api/chat").get_json()["history"] == []
