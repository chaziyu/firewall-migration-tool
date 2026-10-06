"""Desktop distribution checks do not touch application or Flask semantics."""

import base64
import json
import runpy
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

check_version = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/check_desktop_release_version.py"))["check_version"]


def test_release_tag_automation(tmp_path):
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/desktop-release.yml").read_text())
    step = workflow["jobs"]["prepare"]["steps"][-1]
    bash = shutil.which("bash")
    if os.name == "nt":
        bash = "C:/Program Files/Git/bin/bash.exe"
    if not bash or not Path(bash).exists():
        pytest.skip("Bash is required for the GitHub runner script")
    mocks = '''
python() { echo 0.2.1; }
git() {
  if [ "$1" = show-ref ]; then return "$TAG_MISSING"; fi
  echo "git $*"
}
gh() { echo "gh $*"; }
'''
    for event, missing, push_tag, expected in [
        ("workflow_run", "1", "main", "gh workflow run desktop-release.yml --ref desktop-v0.2.1"),
        ("workflow_run", "0", "main", "skipping release"),
        ("push", "0", "desktop-v0.2.1", ""),
        ("workflow_dispatch", "0", "desktop-v0.2.1", ""),
    ]:
        output = tmp_path / "output"
        output.write_text("")
        result = subprocess.run([bash, "-c", mocks + step["run"]], text=True, capture_output=True,
                                env={**os.environ, "EVENT_NAME": event, "TAG_MISSING": missing,
                                     "PUSH_TAG": push_tag, "GITHUB_OUTPUT": output.as_posix()})
        assert result.returncode == 0, result.stderr
        assert expected in result.stdout
        assert ("tag=desktop-v0.2.1" in output.read_text()) == (event != "workflow_run")
        if missing == "0":
            assert "git push" not in result.stdout
        if event == "workflow_run" and missing == "1":
            assert "git push origin refs/tags/desktop-v0.2.1" in result.stdout


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
