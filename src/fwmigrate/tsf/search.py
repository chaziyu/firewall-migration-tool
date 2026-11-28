"""Convenience search and ranking layer over fwmigrate.tsf.indexer."""

from __future__ import annotations

from dataclasses import dataclass

from fwmigrate.tsf.indexer import (
    ContentMatch,
    FileEntry,
    IndexState,
    search_content,
    search_filenames,
)


@dataclass
class ContentGroup:
    """All content matches for a single file, ready for presentation."""

    entry: FileEntry
    matches: list[ContentMatch]
    total_lines: int = 0


def search_by_filename(state: IndexState, query: str) -> list[FileEntry]:
    """Case-insensitive filename search ranked exact -> prefix -> substring."""
    stripped = query.strip()
    if not stripped or not state.file_index:
        return []

    results = search_filenames(state, stripped)
    q = stripped.lower()

    def _rank(entry: FileEntry) -> tuple[int, str]:
        name = entry.name.lower()
        if name == q:
            return (0, entry.rel_path)
        if name.startswith(q):
            return (1, entry.rel_path)
        return (2, entry.rel_path)

    return sorted(results, key=_rank)


def search_by_content(
    state: IndexState,
    query: str,
    max_results: int = 500,
) -> list[ContentGroup]:
    """Case-insensitive content search grouped by file and sorted by match count."""
    stripped = query.strip()
    if not stripped:
        return []

    raw_matches = search_content(state, stripped, max_results=max_results)

    groups: dict[str, list[ContentMatch]] = {}
    for match in raw_matches:
        groups.setdefault(match.rel_path, []).append(match)

    result: list[ContentGroup] = []
    for rel_path, matches in groups.items():
        entry = state.file_index.get(rel_path)
        if not entry:
            continue
        matches.sort(key=lambda m: m.line_number)
        result.append(
            ContentGroup(
                entry=entry,
                matches=matches,
                total_lines=len(matches),
            )
        )

    result.sort(key=lambda g: -g.total_lines)
    return result


def content_index_status(state: IndexState) -> tuple[bool, float, str]:
    """Return (is_ready, progress_fraction, human_message) for the content index."""
    if state.content_ready:
        count = len(state._content_lines)
        return True, 1.0, f"Content index ready — {count:,} files indexed."

    pct = int(state.content_progress * 100)
    count = len(state._content_lines)
    return (
        False,
        state.content_progress,
        f"Content indexing in progress… {pct}%  ({count:,} files indexed so far)",
    )
