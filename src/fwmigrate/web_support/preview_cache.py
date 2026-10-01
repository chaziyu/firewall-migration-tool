"""In-memory cache for analyzed source previews used by the web orchestration layer."""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from copy import deepcopy
from dataclasses import dataclass

from fwmigrate.collection import CollectionStatus


@dataclass(frozen=True)
class _PreviewCacheEntry:
    preview_id: str
    source_vendor: str
    source_digest: str
    created_at: float
    analysis: object
    source_name: str | None = None
    collection_status: CollectionStatus | None = None
    collection_warnings: tuple[str, ...] = ()
    collection_method: str | None = None


_PREVIEW_CACHE: dict[str, _PreviewCacheEntry] = {}
_PREVIEW_CACHE_LOCK = threading.RLock()
_PREVIEW_CACHE_MAX_ENTRIES = 16
_PREVIEW_CACHE_TTL_SECONDS = 15 * 60


def _source_digest(source_vendor: str, raw: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(raw)
    digest.update(b"\0")
    digest.update(source_vendor.encode("utf-8"))
    return digest.hexdigest()


def _cleanup_preview_cache(now: float | None = None) -> None:
    now = time.monotonic() if now is None else now
    expired = [
        preview_id
        for preview_id, entry in _PREVIEW_CACHE.items()
        if now - entry.created_at >= _PREVIEW_CACHE_TTL_SECONDS
    ]
    for preview_id in expired:
        _PREVIEW_CACHE.pop(preview_id, None)


def _find_source_preview(
    source_vendor: str,
    source_digest: str,
    *,
    collection_status: CollectionStatus | None = None,
    collection_warnings: tuple[str, ...] = (),
    collection_method: str | None = None,
) -> _PreviewCacheEntry | None:
    return next(
        (
            entry
            for entry in _PREVIEW_CACHE.values()
            if entry.source_vendor == source_vendor
            and entry.source_digest == source_digest
            and entry.collection_status == collection_status
            and entry.collection_warnings == collection_warnings
            and entry.collection_method == collection_method
        ),
        None,
    )


def _lookup_source_preview(
    source_vendor: str,
    raw: bytes,
    *,
    collection_status: CollectionStatus | None = None,
    collection_warnings: tuple[str, ...] = (),
    collection_method: str | None = None,
) -> _PreviewCacheEntry | None:
    source_digest = _source_digest(source_vendor, raw)
    with _PREVIEW_CACHE_LOCK:
        _cleanup_preview_cache()
        return _find_source_preview(
            source_vendor,
            source_digest,
            collection_status=collection_status,
            collection_warnings=collection_warnings,
            collection_method=collection_method,
        )


def _cache_preview(
    source_vendor: str,
    raw: bytes,
    analysis,
    source_name: str | None = None,
    *,
    collection_status: CollectionStatus | None = None,
    collection_warnings: tuple[str, ...] = (),
    collection_method: str | None = None,
) -> _PreviewCacheEntry:
    now = time.monotonic()
    source_digest = _source_digest(source_vendor, raw)
    with _PREVIEW_CACHE_LOCK:
        _cleanup_preview_cache(now)
        entry = _find_source_preview(
            source_vendor,
            source_digest,
            collection_status=collection_status,
            collection_warnings=collection_warnings,
            collection_method=collection_method,
        )
        if entry is not None:
            return entry
        while len(_PREVIEW_CACHE) >= _PREVIEW_CACHE_MAX_ENTRIES:
            oldest_id = min(_PREVIEW_CACHE, key=lambda key: _PREVIEW_CACHE[key].created_at)
            _PREVIEW_CACHE.pop(oldest_id, None)
        entry = _PreviewCacheEntry(
            preview_id=uuid.uuid4().hex,
            source_vendor=source_vendor,
            source_digest=source_digest,
            created_at=now,
            analysis=analysis,
            source_name=source_name,
            collection_status=collection_status,
            collection_warnings=collection_warnings,
            collection_method=collection_method,
        )
        _PREVIEW_CACHE[entry.preview_id] = entry
        return entry


def _lookup_preview(
    preview_id: str,
    source_vendor: str,
    raw: bytes | None = None,
) -> _PreviewCacheEntry | None:
    with _PREVIEW_CACHE_LOCK:
        _cleanup_preview_cache()
        entry = _PREVIEW_CACHE.get(str(preview_id or "").strip())
        if entry is None or entry.source_vendor != source_vendor:
            return None
        if raw is not None and entry.source_digest != _source_digest(source_vendor, raw):
            return None
        return entry


def _clone_preview(entry: _PreviewCacheEntry):
    return deepcopy(entry.analysis)


def _require_complete_collection(entry: _PreviewCacheEntry) -> None:
    if entry.collection_status is not None and entry.collection_status != CollectionStatus.SUCCESS:
        raise ValueError("Migration requires a complete live collection; this source is PARTIAL or FAILED.")
