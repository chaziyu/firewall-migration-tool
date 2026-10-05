"""Desktop distribution checks do not touch application or Flask semantics."""

import base64
import json
import runpy
from pathlib import Path

import pytest

check_version = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/check_desktop_release_version.py"))["check_version"]


def test_release_version_and_public_key_fail_closed(tmp_path):
    desktop = tmp_path / "src/frontend/src-tauri"
    desktop.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.1"')
    (desktop / "Cargo.toml").write_text('[package]\nversion = "0.2.1"')
    packet = base64.b64encode(b"Ed" + bytes(40)).decode()
    key = base64.b64encode(f"untrusted comment: public key\n{packet}\n".encode()).decode()
    config = {"version": "0.2.1", "plugins": {"updater": {"pubkey": key}}}
    path = desktop / "tauri.conf.json"
    path.write_text(json.dumps(config))
    assert check_version(tmp_path) == "0.2.1"
    assert check_version(tmp_path, "desktop-v0.2.1") == "0.2.1"
    with pytest.raises(ValueError, match="tag"):
        check_version(tmp_path, "desktop-v0.2.2")
    for invalid_key in ["", "not a key", base64.b64encode(b"private key").decode()]:
        config["plugins"]["updater"]["pubkey"] = invalid_key
        path.write_text(json.dumps(config))
        with pytest.raises(ValueError, match="public key"):
            check_version(tmp_path, "desktop-v0.2.1")
    config["version"] = "0.2.2"
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError, match="versions must match"):
        check_version(tmp_path)
