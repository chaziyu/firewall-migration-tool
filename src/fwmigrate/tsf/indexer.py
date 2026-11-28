"""Builds in-memory file and content indexes after TSF extraction."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

TEXT_EXTENSIONS: frozenset[str] = frozenset({
    ".txt",
    ".log",
    ".xml",
    ".cfg",
    ".conf",
    ".csv",
    ".json",
    ".out",
    ".html",
    ".htm",
    ".ini",
    ".yaml",
    ".yml",
    ".sh",
    ".py",
    ".md",
    ".rst",
    ".tsv",
    ".properties",
    ".env",
})

MAX_CONTENT_FILE_BYTES = 50 * 1024 * 1024  # 50 MB — skip larger files
BINARY_DETECT_BYTES = 8192  # bytes to sample for binary detection
MAX_TOTAL_INDEX_FILES = 50_000  # safety cap


@dataclass
class FileEntry:
    """Metadata for one extracted file inside a TSF session."""

    rel_path: str
    abs_path: Path
    size_bytes: int
    is_text: bool
    parent_dir: str
    name: str


@dataclass
class ContentMatch:
    """Single line hit produced by TSF content search."""

    rel_path: str
    line_number: int
    line_text: str


@dataclass
class IndexState:
    """Thread-safe file and asynchronous content index for a TSF session."""

    session_id: str
    session_root: Path
    file_index: dict[str, FileEntry] = field(default_factory=dict)
    dir_children: dict[str, list[str]] = field(default_factory=dict)

    content_ready: bool = False
    content_progress: float = 0.0
    content_error: str = ""
    cancelled: bool = False
    _content_lines: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)


_indexes: dict[str, IndexState] = {}
_index_lock = threading.Lock()


def build_file_index(session_id: str, session_root: Path) -> IndexState:
    """Synchronously walk session_root and build the file + directory index."""
    state = IndexState(session_id=session_id, session_root=session_root)
    root = session_root.resolve()
    count = 0

    for abs_path in _walk(root):
        if count >= MAX_TOTAL_INDEX_FILES:
            break

        try:
            stat_res = abs_path.stat()
        except OSError:
            continue

        rel = str(abs_path.relative_to(root)).replace("\\", "/")
        ext = abs_path.suffix.lower()
        parent = str(abs_path.parent.relative_to(root)).replace("\\", "/")
        if parent == ".":
            parent = ""

        entry = FileEntry(
            rel_path=rel,
            abs_path=abs_path,
            size_bytes=stat_res.st_size,
            is_text=(ext in TEXT_EXTENSIONS),
            parent_dir=parent,
            name=abs_path.name,
        )
        state.file_index[rel] = entry

        if parent not in state.dir_children:
            state.dir_children[parent] = []
        state.dir_children[parent].append(rel)

        _ensure_dir_ancestors(state, parent)
        count += 1

    with _index_lock:
        _indexes[session_id] = state

    return state


def start_content_indexing(session_id: str) -> None:
    """Launch a daemon thread to content-index all text files for session_id."""
    with _index_lock:
        state = _indexes.get(session_id)
    if state is None:
        return

    thread = threading.Thread(
        target=_content_index_worker,
        args=(state,),
        daemon=True,
        name=f"tsf-content-{session_id[:8]}",
    )
    thread.start()


def get_index(session_id: str) -> IndexState | None:
    """Return the IndexState for a session, or None if not found."""
    with _index_lock:
        return _indexes.get(session_id)


def drop_index(session_id: str) -> None:
    """Mark a session index cancelled and remove it from memory."""
    with _index_lock:
        state = _indexes.pop(session_id, None)
    if state is not None:
        state.cancelled = True


def search_filenames(state: IndexState, query: str) -> list[FileEntry]:
    """Case-insensitive substring search across indexed file names."""
    if not query:
        return []
    q = query.lower()
    results = [e for e in state.file_index.values() if q in e.name.lower()]
    return sorted(results, key=lambda e: e.rel_path.lower())


def search_content(
    state: IndexState,
    query: str,
    max_results: int = 500,
) -> list[ContentMatch]:
    """Case-insensitive substring search across indexed line content."""
    if not query or (not state.content_ready and not state._content_lines):
        return []

    q = query.lower()
    results: list[ContentMatch] = []

    with state._lock:
        items = list(state._content_lines.items())

    for rel_path, lines in items:
        for line_no, line_text in lines:
            if q in line_text.lower():
                results.append(
                    ContentMatch(
                        rel_path=rel_path,
                        line_number=line_no,
                        line_text=line_text,
                    )
                )
                if len(results) >= max_results:
                    return results

    return results


def list_dir(state: IndexState, dir_path: str) -> tuple[list[str], list[FileEntry]]:
    """Return sorted (subdirs, files) for dir_path within the index."""
    children_rels = state.dir_children.get(dir_path, [])

    subdirs: set[str] = set()
    files: list[FileEntry] = []

    for rel in children_rels:
        entry = state.file_index.get(rel)
        if entry:
            files.append(entry)
        else:
            subdirs.add(rel)

    prefix = (dir_path + "/") if dir_path else ""
    for key in state.dir_children:
        if key == dir_path:
            continue
        if key.startswith(prefix):
            rest = key[len(prefix):]
            if "/" not in rest and rest:
                subdirs.add(key)

    return (
        sorted(subdirs),
        sorted(files, key=lambda e: e.name.lower()),
    )


def _walk(root: Path) -> Iterator[Path]:
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        for fn in filenames:
            fp = dp / fn
            try:
                fp.resolve().relative_to(root)
                yield fp
            except ValueError:
                pass


def _ensure_dir_ancestors(state: IndexState, rel_dir: str) -> None:
    parts = rel_dir.split("/") if rel_dir else []
    for i in range(len(parts)):
        parent = "/".join(parts[:i]) if i > 0 else ""
        child = "/".join(parts[: i + 1])
        if parent not in state.dir_children:
            state.dir_children[parent] = []
        if child not in state.dir_children[parent]:
            state.dir_children[parent].append(child)


def _is_binary(data: bytes) -> bool:
    sample = data[:BINARY_DETECT_BYTES]
    if not sample:
        return False
    non_text = sum(1 for b in sample if b < 9 or (13 < b < 32 and b not in (9, 10, 13)))
    return (non_text / len(sample)) > 0.10


def _content_index_worker(state: IndexState) -> None:
    try:
        text_entries = [
            e
            for e in state.file_index.values()
            if e.is_text and e.size_bytes <= MAX_CONTENT_FILE_BYTES
        ]
        total = len(text_entries)
        if total == 0:
            state.content_progress = 1.0
            state.content_ready = True
            return

        for idx, entry in enumerate(text_entries):
            if state.cancelled:
                return
            try:
                raw = entry.abs_path.read_bytes()
                if not _is_binary(raw):
                    text = raw.decode("utf-8", errors="replace")
                    lines = []
                    for line_no, line in enumerate(text.splitlines(), 1):
                        stripped = line.strip()
                        if stripped:
                            lines.append((line_no, stripped))
                    with state._lock:
                        state._content_lines[entry.rel_path] = lines
            except OSError:
                pass

            state.content_progress = (idx + 1) / total

        state.content_ready = True
    except Exception as exc:
        state.content_error = str(exc) or "Content indexing failed"
        state.content_ready = True
