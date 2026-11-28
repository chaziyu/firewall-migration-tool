import io
import stat
import time
import zipfile
from pathlib import Path

from fwmigrate.tsf.extractor import (
    cleanup_old_sessions,
    cleanup_session,
    get_session_path,
    is_valid_session_id,
    validate_and_extract,
)
from fwmigrate.tsf.file_preview import MAX_READ_BYTES, page_containing_line, preview_file
from fwmigrate.tsf.indexer import (
    build_file_index,
    drop_index,
    get_index,
    list_dir,
    start_content_indexing,
)
from fwmigrate.tsf.search import content_index_status, search_by_content, search_by_filename


def _make_zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_validate_and_extract_security_screening_and_cleanup(tmp_path: Path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("opt/pancfg/mgmt/saved-configs/running-config.xml", b"<config><devices/></config>")
        zf.writestr("var/log/pan/mp-log.log", b"2026-01-01 INFO failover ready\nline2\n")
        zf.writestr("../escape.txt", b"should not escape")
        zf.writestr("bin/payload.exe", b"not actually exe but blocked ext")
        zf.writestr("scripts/run.txt", b"#!/bin/sh\necho hi\n")
        zf.writestr("deep/" + "/".join(["d"] * 22) + "/file.txt", b"too deep")

        sym = zipfile.ZipInfo("var/log/sym.txt")
        sym.create_system = 3
        sym.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(sym, b"/etc/passwd")

    res = validate_and_extract(buf.getvalue(), sessions_root=tmp_path)
    assert res.success is True
    assert is_valid_session_id(res.session_id)
    assert res.total_files == 2
    assert res.session_path is not None
    assert (res.session_path / "var/log/pan/mp-log.log").is_file()
    assert not (tmp_path / "escape.txt").exists()
    assert any(item.startswith("[traversal]") for item in res.skipped)
    assert any(item.startswith("[blocked-ext]") for item in res.skipped)
    assert any(item.startswith("[exec-sig]") for item in res.skipped)
    assert any(item.startswith("[depth-exceeded]") for item in res.skipped)
    assert any(item.startswith("[symlink]") for item in res.skipped)

    assert get_session_path(res.session_id, sessions_root=tmp_path) == res.session_path
    cleanup_session(res.session_id, sessions_root=tmp_path)
    assert get_session_path(res.session_id, sessions_root=tmp_path) is None


def test_validate_and_extract_rejects_bad_archives_and_invalid_ids(tmp_path: Path):
    assert not is_valid_session_id("../etc")
    assert not is_valid_session_id("not-a-uuid")
    assert get_session_path("../etc", sessions_root=tmp_path) is None
    cleanup_session("../etc", sessions_root=tmp_path)

    bad = validate_and_extract(b"not a zip", sessions_root=tmp_path)
    assert bad.success is False
    assert "not a valid ZIP" in bad.error

    empty = validate_and_extract(_make_zip_bytes({}), sessions_root=tmp_path)
    assert empty.success is False
    assert "empty" in empty.error.lower()

    oversized = validate_and_extract(
        _make_zip_bytes({"a.txt": b"x" * 2048}),
        max_zip_mb=0,
        sessions_root=tmp_path,
    )
    assert oversized.success is False
    assert "exceeds" in oversized.error.lower()


def test_cleanup_old_sessions_removes_expired_dirs(tmp_path: Path):
    old_dir = tmp_path / ("a" * 32)
    fresh_dir = tmp_path / ("b" * 32)
    old_dir.mkdir()
    fresh_dir.mkdir()
    old_time = time.time() - 10 * 3600
    import os
    os.utime(old_dir, (old_time, old_time))

    removed = cleanup_old_sessions(max_age_hours=6, sessions_root=tmp_path)
    assert removed == 1
    assert not old_dir.exists()
    assert fresh_dir.exists()


def test_indexer_search_and_preview_pagination(tmp_path: Path):
    lines = "\n".join(f"log-entry-{i} 10.20.30.40" if i == 505 else f"log-entry-{i}" for i in range(1, 520))
    zip_bytes = _make_zip_bytes({
        "var/log/mp-log.log": lines.encode("utf-8"),
        "var/log/other-mp-log.txt": b"secondary match\n",
        "opt/running-config.xml": b"<config>10.20.30.40</config>\n",
        "bin/blob.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    })
    res = validate_and_extract(zip_bytes, sessions_root=tmp_path)
    assert res.success and res.session_path is not None

    state = build_file_index(res.session_id, res.session_path)
    assert get_index(res.session_id) is state

    root_dirs, root_files = list_dir(state, "")
    assert root_dirs == ["bin", "opt", "var"]
    assert root_files == []

    fn_hits = search_by_filename(state, "mp-log.log")
    assert [h.name for h in fn_hits] == ["mp-log.log"]

    fn_prefix = search_by_filename(state, "mp-log")
    assert [h.name for h in fn_prefix] == ["mp-log.log", "other-mp-log.txt"]

    start_content_indexing(res.session_id)
    deadline = time.time() + 5.0
    while not state.content_ready and time.time() < deadline:
        time.sleep(0.02)
    assert state.content_ready is True
    ready, pct, msg = content_index_status(state)
    assert ready is True and pct == 1.0 and "3 files indexed" in msg

    groups = search_by_content(state, "10.20.30.40")
    assert len(groups) == 2

    preview = preview_file(res.session_path / "var/log/mp-log.log", lines_per_page=500)
    assert preview.success is True
    assert preview.total_pages == 2
    assert page_containing_line(preview, 505) == 1

    bin_preview = preview_file(res.session_path / "bin/blob.png")
    assert bin_preview.success is False
    assert bin_preview.is_binary is True

    drop_index(res.session_id)
    assert get_index(res.session_id) is None
    cleanup_session(res.session_id, sessions_root=tmp_path)


def test_preview_file_caps_reads_at_max_bytes(tmp_path: Path):
    big = tmp_path / "huge.log"
    big.write_bytes(b"a\n" * ((MAX_READ_BYTES // 2) + 500))
    preview = preview_file(big)
    assert preview.success is True
    assert preview.truncated is True


def test_validate_and_extract_enforces_streaming_size_cap(tmp_path: Path, monkeypatch):
    import fwmigrate.tsf.extractor as extractor_mod

    monkeypatch.setattr(extractor_mod, "MAX_SINGLE_FILE_MB", 0)
    zip_bytes = _make_zip_bytes({
        "opt/running-config.xml": b"<config/>",
        "var/log/small.log": b"ok\n",
    })
    # Force info.file_size to 0 in zip central directory? Even without spoofing, 0 MB cap checks actual stream bytes.
    res = validate_and_extract(zip_bytes, sessions_root=tmp_path)
    assert res.success is False
    assert any(item.startswith("[file-too-large]") for item in res.skipped)
