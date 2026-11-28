"""Flask routes for Palo Alto Technical Support File (TSF) archive exploration."""

from __future__ import annotations

import atexit
import shutil
import threading
import uuid
from pathlib import Path
from typing import Any

from flask import current_app, jsonify, request, send_file

from fwmigrate.tsf.extractor import (
    DEFAULT_SESSIONS_ROOT,
    cleanup_old_sessions,
    cleanup_session,
    is_valid_session_id,
    validate_and_extract,
)
from fwmigrate.tsf.file_preview import human_size, page_containing_line, preview_file
from fwmigrate.tsf.indexer import (
    IndexState,
    build_file_index,
    drop_index,
    get_index,
    list_dir,
    search_content,
    start_content_indexing,
)
from fwmigrate.tsf.search import search_by_filename

_MAX_TRACKED_JOBS = 64
_SEARCH_LIMIT = 300


def _sessions_root(app=None) -> Path:
    target = app if app is not None else current_app
    configured = target.config.get("TSF_SESSIONS_DIR")
    if configured:
        return Path(configured)
    return DEFAULT_SESSIONS_ROOT


def _resolve_session_dir(session_id: str) -> Path | None:
    if not is_valid_session_id(session_id):
        return None
    root = _sessions_root().resolve()
    candidate = (root / session_id).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_dir() else None


def _require_tsf_index(session_id: str) -> tuple[IndexState | None, tuple[Any, int] | None]:
    if not is_valid_session_id(session_id):
        return None, (jsonify({"success": False, "error": "Invalid TSF session ID."}), 400)
    idx = get_index(session_id)
    if idx is None:
        return None, (jsonify({"success": False, "error": "TSF session expired or not found."}), 404)
    return idx, None


def register_tsf_routes(app) -> None:
    """Register /api/tsf/* endpoints and app-owned job state on app."""
    jobs: dict[str, dict[str, Any]] = {}
    jobs_lock = threading.Lock()
    active_sessions: set[str] = set()
    app.extensions["tsf_jobs"] = jobs
    app.extensions["tsf_jobs_lock"] = jobs_lock
    app.extensions["tsf_active_sessions"] = active_sessions

    sessions_root = _sessions_root(app)

    def _cleanup_on_exit() -> None:
        with jobs_lock:
            session_ids = list(active_sessions)
            active_sessions.clear()
        for sid in session_ids:
            drop_index(sid)
            cleanup_session(sid, sessions_root=sessions_root)

    atexit.register(_cleanup_on_exit)

    def _prune_jobs_locked() -> None:
        if len(jobs) <= _MAX_TRACKED_JOBS:
            return
        finished = [jid for jid, info in jobs.items() if info.get("status") != "running"]
        for jid in finished[: max(0, len(jobs) - _MAX_TRACKED_JOBS)]:
            jobs.pop(jid, None)

    @app.route("/api/tsf/upload", methods=["POST"])
    def tsf_upload():
        if "file" not in request.files:
            return jsonify({"success": False, "error": "A TSF .zip file is required."}), 400
        uploaded = request.files["file"]
        raw_name = Path(uploaded.filename or "").name
        if not raw_name or not raw_name.lower().endswith(".zip"):
            return jsonify({"success": False, "error": "Upload must be a .zip TSF archive."}), 400

        max_zip_mb = int(app.config.get("TSF_MAX_ZIP_MB", 500))
        max_zip_bytes = max_zip_mb * 1024 * 1024
        ttl_hours = float(app.config.get("TSF_SESSION_TTL_HOURS", 6))

        cleanup_old_sessions(max_age_hours=ttl_hours, sessions_root=sessions_root)
        sessions_root.mkdir(parents=True, exist_ok=True)

        job_id = uuid.uuid4().hex
        tmp_zip = sessions_root / f"_upload_{job_id}.zip"
        total_written = 0
        try:
            with tmp_zip.open("wb") as out_fh:
                while True:
                    chunk = uploaded.stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total_written += len(chunk)
                    if total_written > max_zip_bytes:
                        raise ValueError("oversized_tsf")
                    out_fh.write(chunk)
        except ValueError:
            tmp_zip.unlink(missing_ok=True)
            return (
                jsonify({
                    "success": False,
                    "error": f"TSF archive exceeds the {max_zip_mb} MB upload limit.",
                }),
                413,
            )
        except OSError:
            tmp_zip.unlink(missing_ok=True)
            return jsonify({"success": False, "error": "Failed to stage uploaded TSF archive."}), 500

        if total_written == 0:
            tmp_zip.unlink(missing_ok=True)
            return jsonify({"success": False, "error": "The uploaded ZIP archive is empty."}), 400

        with jobs_lock:
            _prune_jobs_locked()
            jobs[job_id] = {
                "status": "running",
                "progress": 0.0,
                "message": "Queued for extraction…",
                "filename": raw_name,
                "session_id": "",
                "total_files": 0,
                "skipped_count": 0,
                "error": "",
            }

        def _worker() -> None:
            def _on_progress(frac: float, msg: str) -> None:
                with jobs_lock:
                    job = jobs.get(job_id)
                    if job is not None:
                        job["progress"] = max(0.0, min(0.92, frac * 0.92))
                        job["message"] = msg

            try:
                result = validate_and_extract(
                    tmp_zip,
                    progress_cb=_on_progress,
                    max_zip_mb=max_zip_mb,
                    sessions_root=sessions_root,
                )
            except Exception as exc:
                with jobs_lock:
                    job = jobs.get(job_id)
                    if job is not None:
                        job["status"] = "error"
                        job["progress"] = 1.0
                        job["error"] = str(exc) or "TSF extraction failed."
                return
            finally:
                try:
                    tmp_zip.unlink(missing_ok=True)
                except OSError:
                    pass

            if not result.success or result.session_path is None:
                with jobs_lock:
                    job = jobs.get(job_id)
                    if job is not None:
                        job["status"] = "error"
                        job["progress"] = 1.0
                        job["error"] = result.error or "TSF extraction failed."
                return

            with jobs_lock:
                job = jobs.get(job_id)
                if job is not None:
                    job["progress"] = 0.95
                    job["message"] = "Building file directory index…"

            try:
                build_file_index(result.session_id, result.session_path)
                start_content_indexing(result.session_id)
            except Exception as exc:
                drop_index(result.session_id)
                cleanup_session(result.session_id, sessions_root=sessions_root)
                with jobs_lock:
                    job = jobs.get(job_id)
                    if job is not None:
                        job["status"] = "error"
                        job["progress"] = 1.0
                        job["error"] = str(exc) or "Failed to index TSF archive."
                return

            with jobs_lock:
                active_sessions.add(result.session_id)
                job = jobs.get(job_id)
                if job is not None:
                    job["status"] = "done"
                    job["progress"] = 1.0
                    job["message"] = f"Extracted {result.total_files:,} files."
                    job["session_id"] = result.session_id
                    job["total_files"] = result.total_files
                    job["skipped_count"] = len(result.skipped)

        thread = threading.Thread(
            target=_worker,
            daemon=True,
            name=f"tsf-extract-{job_id[:8]}",
        )
        thread.start()

        return jsonify({"success": True, "job_id": job_id, "filename": raw_name}), 202

    @app.route("/api/tsf/progress/<job_id>", methods=["GET"])
    def tsf_progress(job_id: str):
        if not is_valid_session_id(job_id):
            return jsonify({"success": False, "error": "Invalid TSF job ID."}), 400
        with jobs_lock:
            job = jobs.get(job_id)
            snapshot = dict(job) if job is not None else None
        if snapshot is None:
            return jsonify({"success": False, "error": "TSF job not found."}), 404
        return jsonify({"success": True, **snapshot})

    @app.route("/api/tsf/status", methods=["GET"])
    def tsf_status():
        session_id = request.args.get("session_id", "")
        idx, err = _require_tsf_index(session_id)
        if err is not None:
            return err
        assert idx is not None
        return jsonify({
            "success": True,
            "total_files": len(idx.file_index),
            "content_ready": idx.content_ready,
            "content_progress": idx.content_progress,
            "content_error": idx.content_error,
        })

    @app.route("/api/tsf/tree", methods=["GET"])
    def tsf_tree():
        session_id = request.args.get("session_id", "")
        idx, err = _require_tsf_index(session_id)
        if err is not None:
            return err
        assert idx is not None
        rel_path = request.args.get("path", "")
        dirs, files = list_dir(idx, rel_path)
        return jsonify({
            "success": True,
            "path": rel_path,
            "dirs": dirs,
            "files": [
                {
                    "rel_path": f.rel_path,
                    "name": f.name,
                    "size_bytes": f.size_bytes,
                    "size_human": human_size(f.size_bytes),
                    "is_text": f.is_text,
                }
                for f in files
            ],
        })

    @app.route("/api/tsf/file", methods=["GET"])
    def tsf_file():
        session_id = request.args.get("session_id", "")
        idx, err = _require_tsf_index(session_id)
        if err is not None:
            return err
        assert idx is not None

        rel_path = request.args.get("path", "")
        entry = idx.file_index.get(rel_path)
        if entry is None:
            return jsonify({"success": False, "error": "File not found in TSF archive."}), 404

        try:
            page = max(0, int(request.args.get("page", "0")))
            jump_line = max(0, int(request.args.get("jump_line", "0")))
        except ValueError:
            return jsonify({"success": False, "error": "Invalid page or line number."}), 400

        res = preview_file(entry.abs_path)
        if not res.success:
            return jsonify({
                "success": False,
                "rel_path": entry.rel_path,
                "is_binary": res.is_binary,
                "error": res.error,
                "size_human": human_size(entry.size_bytes),
            })

        target_page = page_containing_line(res, jump_line) if jump_line > 0 else page
        target_page = max(0, min(target_page, max(0, res.total_pages - 1)))
        lines = res.pages[target_page] if res.pages else []

        return jsonify({
            "success": True,
            "rel_path": entry.rel_path,
            "size_human": human_size(res.file_size_bytes),
            "truncated": res.truncated,
            "total_lines": res.total_lines,
            "total_pages": res.total_pages,
            "page": target_page,
            "lines": [[ln, txt] for ln, txt in lines],
        })

    @app.route("/api/tsf/search", methods=["GET"])
    def tsf_search():
        session_id = request.args.get("session_id", "")
        idx, err = _require_tsf_index(session_id)
        if err is not None:
            return err
        assert idx is not None

        mode = request.args.get("mode", "filename").strip().lower()
        query = request.args.get("q", "").strip()
        if not query:
            return jsonify({"success": True, "mode": mode, "results": []})

        if mode == "content":
            matches = search_content(idx, query, max_results=_SEARCH_LIMIT)
            return jsonify({
                "success": True,
                "mode": "content",
                "results": [
                    {
                        "rel_path": m.rel_path,
                        "line_number": m.line_number,
                        "line_text": m.line_text,
                    }
                    for m in matches
                ],
            })

        files = search_by_filename(idx, query)[:_SEARCH_LIMIT]
        return jsonify({
            "success": True,
            "mode": "filename",
            "results": [
                {
                    "rel_path": f.rel_path,
                    "name": f.name,
                    "size_human": human_size(f.size_bytes),
                }
                for f in files
            ],
        })

    @app.route("/api/tsf/download", methods=["GET"])
    def tsf_download():
        session_id = request.args.get("session_id", "")
        idx, err = _require_tsf_index(session_id)
        if err is not None:
            return err
        assert idx is not None

        rel_path = request.args.get("path", "")
        entry = idx.file_index.get(rel_path)
        if entry is None:
            return jsonify({"success": False, "error": "File not found."}), 404

        try:
            resolved = entry.abs_path.resolve()
            resolved.relative_to(idx.session_root.resolve())
        except (OSError, ValueError):
            return jsonify({"success": False, "error": "File path is outside session root."}), 403

        if not resolved.is_file():
            return jsonify({"success": False, "error": "File not found."}), 404

        return send_file(
            resolved,
            as_attachment=True,
            download_name=entry.name,
            mimetype="application/octet-stream",
        )

    @app.route("/api/tsf/session/<session_id>", methods=["DELETE"])
    def tsf_delete_session(session_id: str):
        if not is_valid_session_id(session_id):
            return jsonify({"success": False, "error": "Invalid TSF session ID."}), 400
        drop_index(session_id)
        cleanup_session(session_id, sessions_root=sessions_root)
        # Fallback: remove directly if sessions_root came from os.environ
        session_dir = _resolve_session_dir(session_id)
        if session_dir is not None and session_dir.exists():
            shutil.rmtree(session_dir, ignore_errors=True)
        with jobs_lock:
            active_sessions.discard(session_id)
        return jsonify({"success": True})
