"""Palo Alto Technical Support File (TSF) archive extraction, indexing, search, and preview."""

from __future__ import annotations

from fwmigrate.tsf.extractor import (
    ExtractionResult,
    cleanup_old_sessions,
    cleanup_session,
    get_session_path,
    is_valid_session_id,
    validate_and_extract,
)
from fwmigrate.tsf.file_preview import (
    PreviewResult,
    human_size,
    page_containing_line,
    preview_file,
)
from fwmigrate.tsf.indexer import (
    ContentMatch,
    FileEntry,
    IndexState,
    build_file_index,
    drop_index,
    get_index,
    list_dir,
    start_content_indexing,
)
from fwmigrate.tsf.search import (
    ContentGroup,
    content_index_status,
    search_by_content,
    search_by_filename,
)

__all__ = [
    "ContentGroup",
    "ContentMatch",
    "ExtractionResult",
    "FileEntry",
    "IndexState",
    "PreviewResult",
    "build_file_index",
    "cleanup_old_sessions",
    "cleanup_session",
    "content_index_status",
    "drop_index",
    "get_index",
    "get_session_path",
    "human_size",
    "is_valid_session_id",
    "list_dir",
    "page_containing_line",
    "preview_file",
    "search_by_content",
    "search_by_filename",
    "start_content_indexing",
    "validate_and_extract",
]
