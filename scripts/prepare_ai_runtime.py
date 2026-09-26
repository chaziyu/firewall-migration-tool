"""Fetch the pinned llama.cpp Windows CPU build for PyInstaller."""

import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from fwmigrate.ai.manifests import LOCAL_MODEL, WINDOWS_X64_CPU_RUNTIME


ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "src" / "fwmigrate" / "ai_runtime" / "windows-x64"
LLAMA_LICENSE_URL = "https://raw.githubusercontent.com/ggml-org/llama.cpp/b11200/LICENSE"
LLAMA_LICENSE_SHA256 = "94f29bb ed6a22c35b992c5c6ebf0e7c92f13b836b90f36f461c9cf2f0f1d010d".replace(" ", "")


def main():
    manifest = WINDOWS_X64_CPU_RUNTIME
    digest = hashlib.sha256()
    DEST.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp_dir:
        archive_path = Path(temp_dir) / "llama-runtime.zip"
        size = 0
        with urlopen(manifest.archive_url, timeout=30) as response, archive_path.open("wb") as output:
            while block := response.read(1024 * 1024):
                output.write(block)
                digest.update(block)
                size += len(block)
        if size != manifest.archive_size_bytes or digest.hexdigest() != manifest.archive_sha256:
            raise SystemExit("Pinned llama.cpp runtime archive failed its integrity check")
        stage = Path(temp_dir) / "runtime"
        stage.mkdir()
        with zipfile.ZipFile(archive_path) as archive:
            for entry in archive.infolist():
                path = PurePosixPath(entry.filename)
                if entry.is_dir() or len(path.parts) != 1 or path.name != entry.filename:
                    continue
                if (path.suffix.casefold() not in {".dll"}
                        and path.name != "llama-server.exe" and not path.name.startswith("LICENSE")):
                    continue
                with archive.open(entry) as source, (stage / path.name).open("wb") as output:
                    shutil.copyfileobj(source, output)
        with urlopen(LLAMA_LICENSE_URL, timeout=30) as response:
            license_text = response.read()
        if hashlib.sha256(license_text).hexdigest() != LLAMA_LICENSE_SHA256:
            raise SystemExit("Pinned llama.cpp license failed its integrity check")
        (stage / "LICENSE-llama.cpp-MIT.txt").write_bytes(license_text)
        if not (stage / "llama-server.exe").is_file():
            raise SystemExit("Pinned runtime archive does not contain llama-server.exe")
        for old in DEST.iterdir():
            if old.is_file() and (old.suffix.casefold() in {".exe", ".dll"}
                                  or old.name.startswith("LICENSE") or old.name == "runtime-manifest.json"):
                old.unlink()
        for path in stage.iterdir():
            shutil.copy2(path, DEST / path.name)
    runtime_info = {
        "version": manifest.version,
        "platform": manifest.platform,
        "architecture": manifest.architecture,
        "archive_sha256": manifest.archive_sha256,
        "model_id": LOCAL_MODEL.model_id,
        "model_revision": LOCAL_MODEL.revision,
        "model_sha256": LOCAL_MODEL.sha256,
    }
    (DEST / "runtime-manifest.json").write_text(json.dumps(runtime_info, indent=2) + "\n", encoding="utf-8")
    print(f"Prepared llama.cpp {manifest.version} at {DEST}")


if __name__ == "__main__":
    main()
