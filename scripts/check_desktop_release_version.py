"""Fail closed before producing a signed desktop release (stdlib only)."""

from __future__ import annotations

import argparse
import base64
import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check_version(root: Path, tag: str | None = None) -> str:
    desktop = root / "src/frontend/src-tauri"
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    cargo = tomllib.loads((desktop / "Cargo.toml").read_text(encoding="utf-8"))
    config = json.loads((desktop / "tauri.conf.json").read_text(encoding="utf-8"))
    version = project["project"]["version"]
    if version != cargo["package"]["version"] or version != config["version"]:
        raise ValueError("Python, Cargo and Tauri versions must match")
    if tag is not None:
        if not re.fullmatch(r"\d+\.\d+\.\d+", version) or tag != f"desktop-v{version}":
            raise ValueError("Stable desktop release tag must equal the application version")
        # This is the pinned trust anchor, never a private key or a CI-selected replacement.
        public_key = config["plugins"]["updater"]["pubkey"]
        try:
            text = base64.b64decode(public_key, validate=True).decode("utf-8")
            packet = base64.b64decode(text.splitlines()[-1], validate=True)
        except (ValueError, IndexError, UnicodeError) as error:
            raise ValueError("Configure a valid updater public key before releasing") from error
        if len(packet) != 42 or packet[:2] != b"Ed":
            raise ValueError("Invalid updater public key")
    return version


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag")
    print(check_version(ROOT, parser.parse_args().tag))
