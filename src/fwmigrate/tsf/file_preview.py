"""Bounded, paginated text file preview for extracted TSF session files."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB hard read cap per file
LINES_PER_PAGE = 500
BINARY_DETECT_BYTES = 8192

VIEWABLE_EXTENSIONS: frozenset[str] = frozenset({
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
    ".text",
    ".lst",
    ".dat",
})


@dataclass
class PreviewResult:
    """Paginated line-numbered file preview."""

    success: bool
    is_binary: bool = False
    truncated: bool = False
    total_lines: int = 0
    total_pages: int = 0
    pages: list[list[tuple[int, str]]] = field(default_factory=list)
    error: str = ""
    file_size_bytes: int = 0
    encoding: str = "utf-8"


def preview_file(
    abs_path: Path,
    lines_per_page: int = LINES_PER_PAGE,
) -> PreviewResult:
    """Read up to MAX_READ_BYTES of abs_path safely and return a PreviewResult."""
    ext = abs_path.suffix.lower()
    if ext and ext not in VIEWABLE_EXTENSIONS:
        return PreviewResult(
            success=False,
            is_binary=True,
            error=f"This file type ({ext}) cannot be previewed.",
            file_size_bytes=_safe_size(abs_path),
        )

    try:
        file_size = abs_path.stat().st_size
    except OSError as exc:
        return PreviewResult(success=False, error=f"Cannot stat file: {exc}")

    try:
        with abs_path.open("rb") as fh:
            raw = fh.read(MAX_READ_BYTES + 1)
    except OSError as exc:
        return PreviewResult(
            success=False,
            error=f"Cannot read file: {exc}",
            file_size_bytes=file_size,
        )

    truncated = False
    if len(raw) > MAX_READ_BYTES:
        raw = raw[:MAX_READ_BYTES]
        truncated = True

    if _is_binary(raw):
        return PreviewResult(
            success=False,
            is_binary=True,
            error="This file type cannot be previewed.",
            file_size_bytes=file_size,
        )

    encoding = "utf-8"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
            encoding = "latin-1"
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            encoding = "utf-8 (lossy)"

    all_lines: list[tuple[int, str]] = [
        (i + 1, line) for i, line in enumerate(text.splitlines())
    ]
    total_lines = len(all_lines)

    pages: list[list[tuple[int, str]]] = []
    lpp = max(1, lines_per_page)
    for start in range(0, max(1, total_lines), lpp):
        pages.append(all_lines[start : start + lpp])

    if not pages:
        pages = [[]]

    return PreviewResult(
        success=True,
        truncated=truncated,
        total_lines=total_lines,
        total_pages=len(pages),
        pages=pages,
        file_size_bytes=file_size,
        encoding=encoding,
    )


def page_containing_line(result: PreviewResult, line_number: int) -> int:
    """Return the 0-based page index containing the given 1-based line number."""
    for page_idx, page in enumerate(result.pages):
        if any(ln == line_number for ln, _ in page):
            return page_idx
    return 0


def _is_binary(data: bytes) -> bool:
    sample = data[:BINARY_DETECT_BYTES]
    if not sample:
        return False
    non_text = sum(1 for b in sample if b < 9 or (13 < b < 32 and b not in (9, 10, 13)))
    return (non_text / len(sample)) > 0.10


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def human_size(size_bytes: int | float) -> str:
    """Convert byte count to a human-readable string."""
    value = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"
