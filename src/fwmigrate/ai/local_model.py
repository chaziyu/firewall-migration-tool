"""Verified, atomic installation of the pinned local model."""

import hashlib
import os
import platform
import shutil
import threading
from pathlib import Path
from urllib.request import urlopen

from .local_paths import local_ai_data_dir
from .manifests import LOCAL_MODEL, LocalModelManifest


class LocalModelManager:
    def __init__(self, manifest: LocalModelManifest = LOCAL_MODEL, *, model_dir: Path | None = None):
        self.manifest = manifest
        self.model_dir = Path(model_dir) if model_dir else local_ai_data_dir() / "models"
        self.path = self.model_dir / manifest.filename
        self.part_path = self.path.with_suffix(self.path.suffix + ".part")
        self._lock = threading.Lock()
        self._install_lock = threading.Lock()
        self._state = "READY" if self.path.exists() else "NOT_INSTALLED"
        self._downloaded = 0
        self._error = None
        self._verified_stat = None

    def status(self) -> dict:
        with self._lock:
            state = self._state
            downloaded = self._downloaded
            error = self._error
        exists = self.path.is_file()
        if state not in {"DOWNLOADING", "VERIFYING", "FAILED"}:
            valid = self.verify() if exists else False
            state = "READY" if valid else "CORRUPT" if exists else "NOT_INSTALLED"
        return {"state": state, "installed": state == "READY", "downloaded_bytes": downloaded,
                "download_bytes": self.manifest.size_bytes, "error": error}

    def mark_downloading(self) -> None:
        with self._lock:
            self._state, self._downloaded, self._error = "DOWNLOADING", 0, None

    def verify(self) -> bool:
        try:
            stat = self.path.stat()
        except OSError:
            return False
        signature = (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, getattr(stat, "st_ino", None))
        if signature == self._verified_stat:
            return True
        if stat.st_size != self.manifest.size_bytes:
            return False
        digest = hashlib.sha256()
        with self.path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        valid = digest.hexdigest() == self.manifest.sha256
        self._verified_stat = signature if valid else None
        return valid

    def ensure_installed(self, progress=None) -> Path:
        with self._install_lock:
            return self._ensure_installed(progress)

    def _ensure_installed(self, progress=None) -> Path:
        if self.verify():
            with self._lock:
                self._state, self._error = "READY", None
            return self.path
        if platform.architecture()[0] != "64bit":
            raise RuntimeError("Local AI requires a 64-bit operating system")
        if shutil.disk_usage(self.model_dir.parent if self.model_dir.parent.exists() else Path.home()).free < self.manifest.size_bytes + 256 * 1024 * 1024:
            raise RuntimeError("There is not enough free disk space to install the local AI model")
        self.model_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        downloaded = 0
        with self._lock:
            self._state, self._downloaded, self._error = "DOWNLOADING", 0, None
        try:
            with urlopen(self.manifest.download_url, timeout=30) as response, self.part_path.open("wb") as output:
                while block := response.read(1024 * 1024):
                    output.write(block)
                    digest.update(block)
                    downloaded += len(block)
                    with self._lock:
                        self._downloaded = downloaded
                    if progress:
                        progress(downloaded, self.manifest.size_bytes)
                output.flush()
                os.fsync(output.fileno())
            with self._lock:
                self._state = "VERIFYING"
            if downloaded != self.manifest.size_bytes or digest.hexdigest() != self.manifest.sha256:
                raise RuntimeError("The downloaded model failed its integrity check")
            os.replace(self.part_path, self.path)
            stat = self.path.stat()
            self._verified_stat = (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns,
                                   getattr(stat, "st_ino", None))
            with self._lock:
                self._state, self._error = "READY", None
            return self.path
        except Exception as exc:
            self.part_path.unlink(missing_ok=True)
            with self._lock:
                self._state = "CORRUPT" if self.path.exists() else "FAILED"
                self._error = str(exc) if isinstance(exc, RuntimeError) else "Local AI model download failed"
            raise

    def remove(self) -> None:
        with self._lock:
            if self._state == "DOWNLOADING":
                raise RuntimeError("The local AI model is currently downloading")
        self.path.unlink(missing_ok=True)
        self.part_path.unlink(missing_ok=True)
        self._verified_stat = None
        with self._lock:
            self._state, self._downloaded, self._error = "NOT_INSTALLED", 0, None
