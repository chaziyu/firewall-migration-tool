"""Validates and safely extracts TSF ZIP archives to isolated session directories.

Security hardening:
  - Session ID validation: strict 32-character lowercase hex UUID check.
  - Path traversal: every member path is resolved and confirmed to stay
    inside the session root before extraction.
  - Symlinks inside ZIPs: symlink entries and any member resolving outside
    the session root are skipped.
  - Depth limit: paths deeper than MAX_DEPTH directories are skipped.
  - Executable signatures & extensions: members matching known PE/ELF/script
    signatures or blocked extensions are skipped.
  - Max total extracted size: aborts member extraction beyond MAX_EXTRACT_BYTES.
  - Password-protected ZIPs: detected and rejected with a clear message.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import stat
import tempfile
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

DEFAULT_SESSIONS_ROOT = Path(
    os.environ.get("TSF_SESSIONS_DIR") or Path(tempfile.gettempdir()) / "fwmigrate_tsf_sessions"
)

MAX_DEPTH = 20
MAX_EXTRACT_BYTES = 5 * 1024**3  # 5 GB total extracted size guard
MAX_ZIP_MB = 500  # default maximum accepted ZIP upload in MB
MAX_SINGLE_FILE_MB = 200  # skip individual members larger than this

_SESSION_ID_RE = re.compile(r"^[0-9a-f]{32}$")

_SKIP_SIGS: tuple[bytes, ...] = (
    b"\x4d\x5a",  # PE Windows exe/dll
    b"\x7felf",  # ELF Linux binary (lowercased compare)
    b"#!/",  # shell shebang
    b"<?php",  # PHP
)

_SKIP_EXTS: frozenset[str] = frozenset({
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".jar",
    ".class",
    ".pyc",
})


@dataclass
class ExtractionResult:
    """Outcome of TSF ZIP validation and extraction."""

    success: bool
    session_id: str = ""
    session_path: Path | None = None
    total_files: int = 0
    total_bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    error: str = ""


def is_valid_session_id(session_id: str) -> bool:
    """Return True if session_id is a strict 32-char lowercase hex UUID."""
    return isinstance(session_id, str) and bool(_SESSION_ID_RE.fullmatch(session_id))


def _resolve_sessions_root(sessions_root: Path | None) -> Path:
    return sessions_root if sessions_root is not None else DEFAULT_SESSIONS_ROOT


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode) if mode else False


def validate_and_extract(
    zip_source: bytes | Path,
    progress_cb: Callable[[float, str], None] | None = None,
    *,
    max_zip_mb: int = MAX_ZIP_MB,
    sessions_root: Path | None = None,
) -> ExtractionResult:
    """Validate zip_source as a safe TSF archive and extract it to a session directory."""

    def _p(frac: float, msg: str) -> None:
        if progress_cb:
            progress_cb(frac, msg)

    _p(0.0, "Checking file size…")
    if isinstance(zip_source, Path):
        try:
            byte_len = zip_source.stat().st_size
        except OSError as exc:
            return ExtractionResult(success=False, error=f"Cannot read uploaded archive: {exc}")
        open_target: io.BytesIO | Path = zip_source
    else:
        byte_len = len(zip_source)
        open_target = io.BytesIO(zip_source)

    size_mb = byte_len / (1024**2)
    if size_mb > max_zip_mb:
        return ExtractionResult(
            success=False,
            error=f"ZIP is {size_mb:.1f} MB — exceeds the {max_zip_mb} MB limit.",
        )

    _p(0.05, "Validating archive structure…")
    try:
        zf_ctx = zipfile.ZipFile(open_target, "r")
    except zipfile.BadZipFile:
        return ExtractionResult(
            success=False, error="The file is not a valid ZIP archive."
        )
    except Exception as exc:
        return ExtractionResult(success=False, error=f"Cannot open archive: {exc}")

    with zf_ctx as zf:
        members = zf.infolist()
        if not members:
            return ExtractionResult(success=False, error="The ZIP archive is empty.")

        # Probe first non-directory member (or first member) for encryption
        probe_member = next((m for m in members if not m.is_dir()), members[0])
        if probe_member.flag_bits & 0x1:
            return ExtractionResult(
                success=False, error="Password-protected ZIP files are not supported."
            )
        try:
            if not probe_member.is_dir():
                with zf.open(probe_member, "r") as probe_stream:
                    probe_stream.read(1)
        except RuntimeError as exc:
            if "encrypt" in str(exc).lower() or "password" in str(exc).lower():
                return ExtractionResult(
                    success=False, error="Password-protected ZIP files are not supported."
                )
        except Exception:
            pass

        root_base = _resolve_sessions_root(sessions_root)
        _p(0.10, f"Scanning {len(members):,} archive members…")
        session_id = uuid.uuid4().hex
        root_base.mkdir(parents=True, exist_ok=True)
        session_path = root_base / session_id
        session_path.mkdir(parents=True, exist_ok=True)
        session_root = session_path.resolve()

        safe_members: list[zipfile.ZipInfo] = []
        skipped: list[str] = []
        projected_size = 0

        for info in members:
            name = info.filename

            if name.endswith("/") or info.is_dir():
                continue

            if _is_zip_symlink(info):
                skipped.append(f"[symlink] {name}")
                continue

            # Path traversal guard
            try:
                dest = (session_root / name).resolve()
                dest.relative_to(session_root)
            except ValueError:
                skipped.append(f"[traversal] {name}")
                continue

            if len(Path(name).parts) - 1 > MAX_DEPTH:
                skipped.append(f"[depth-exceeded] {name}")
                continue

            if Path(name).suffix.lower() in _SKIP_EXTS:
                skipped.append(f"[blocked-ext] {name}")
                continue

            if info.file_size > MAX_SINGLE_FILE_MB * 1024**2:
                skipped.append(f"[file-too-large] {name}")
                continue

            projected_size += info.file_size
            if projected_size > MAX_EXTRACT_BYTES:
                skipped.append(f"[total-size-exceeded] {name}")
                continue

            safe_members.append(info)

        if not safe_members:
            shutil.rmtree(session_path, ignore_errors=True)
            return ExtractionResult(
                success=False,
                error="No extractable files found after security screening.",
                skipped=skipped,
            )

        total = len(safe_members)
        extracted_count = 0
        extracted_bytes = 0

        for idx, info in enumerate(safe_members):
            _p(
                0.15 + 0.80 * (idx / total),
                f"Extracting {idx + 1:,}/{total:,}: {Path(info.filename).name}",
            )

            dest = (session_root / info.filename).resolve()
            try:
                dest.relative_to(session_root)
            except ValueError:
                skipped.append(f"[traversal] {info.filename}")
                continue

            dest.parent.mkdir(parents=True, exist_ok=True)

            max_single_bytes = MAX_SINGLE_FILE_MB * 1024**2
            try:
                buf = bytearray()
                too_large_single = False
                too_large_total = False
                with zf.open(info, "r") as member_stream:
                    while True:
                        chunk = member_stream.read(65536)
                        if not chunk:
                            break
                        if len(buf) + len(chunk) > max_single_bytes:
                            too_large_single = True
                            break
                        if extracted_bytes + len(buf) + len(chunk) > MAX_EXTRACT_BYTES:
                            too_large_total = True
                            break
                        buf.extend(chunk)
            except RuntimeError:
                skipped.append(f"[encrypted] {info.filename}")
                continue
            except Exception as exc:
                skipped.append(f"[read-error] {info.filename}: {exc}")
                continue

            if too_large_single:
                skipped.append(f"[file-too-large] {info.filename}")
                continue
            if too_large_total:
                skipped.append(f"[total-size-exceeded] {info.filename}")
                continue
            data = bytes(buf)

            sig_sample = data[:16].lower()
            if any(sig_sample.startswith(sig) for sig in _SKIP_SIGS):
                skipped.append(f"[exec-sig] {info.filename}")
                continue

            try:
                dest.write_bytes(data)
                extracted_count += 1
                extracted_bytes += len(data)
            except OSError as exc:
                skipped.append(f"[write-error] {info.filename}: {exc}")

    if extracted_count == 0:
        shutil.rmtree(session_path, ignore_errors=True)
        return ExtractionResult(
            success=False,
            error="No extractable files found after security screening.",
            skipped=skipped,
        )

    _p(1.0, f"Done — {extracted_count:,} files extracted.")

    return ExtractionResult(
        success=True,
        session_id=session_id,
        session_path=session_path,
        total_files=extracted_count,
        total_bytes=extracted_bytes,
        skipped=skipped,
    )


def cleanup_session(session_id: str, *, sessions_root: Path | None = None) -> None:
    """Remove a validated session directory and all its contents."""
    if not is_valid_session_id(session_id):
        return
    root_base = _resolve_sessions_root(sessions_root)
    path = root_base / session_id
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def cleanup_old_sessions(
    max_age_hours: float = 6.0,
    *,
    sessions_root: Path | None = None,
) -> int:
    """Delete session directories older than max_age_hours. Returns count removed."""
    root_base = _resolve_sessions_root(sessions_root)
    if not root_base.exists():
        return 0
    removed = 0
    now = time.time()
    for child in root_base.iterdir():
        if not child.is_dir():
            continue
        try:
            age_hours = (now - child.stat().st_mtime) / 3600
        except OSError:
            continue
        if age_hours > max_age_hours:
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
    return removed


def get_session_path(session_id: str, *, sessions_root: Path | None = None) -> Path | None:
    """Return the Path for a validated session if it still exists, else None."""
    if not is_valid_session_id(session_id):
        return None
    root_base = _resolve_sessions_root(sessions_root)
    path = root_base / session_id
    return path if path.is_dir() else None
