"""Bounded in-memory LRU+TTL cache and sealed RAM store for interactive source analysis."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import os
import secrets
import sys
import threading
import time
from typing import Any, Callable
import zlib


DEFAULT_CACHE_TTL_SECONDS = 30 * 60
DEFAULT_PUBLIC_CACHE_MAX_ENTRIES = 16
DEFAULT_LOCAL_CACHE_MAX_ENTRIES = 4


def default_cache_max_entries(web_mode: str = "public") -> int:
    """Return a bounded entry cap tailored to hosted vs. local/desktop memory budgets."""
    is_desktop = bool(getattr(sys, "frozen", False) or web_mode == "local")
    return DEFAULT_LOCAL_CACHE_MAX_ENTRIES if is_desktop else DEFAULT_PUBLIC_CACHE_MAX_ENTRIES


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR-obfuscate compressed bytes with an ephemeral per-entry key."""
    if not data or not key:
        return data
    klen = len(key)
    full_key = (key * ((len(data) // klen) + 1))[: len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(full_key, "little")).to_bytes(len(data), "little")


@dataclass(frozen=True, slots=True)
class SealedPayload:
    """Compressed and XOR-sealed byte buffer; never holds plaintext directly."""

    ciphertext: bytes
    key: bytes

    @classmethod
    def seal(cls, plaintext: bytes) -> SealedPayload:
        key = secrets.token_bytes(32)
        compressed = zlib.compress(plaintext, level=6)
        return cls(ciphertext=_xor_bytes(compressed, key), key=key)

    def unseal(self) -> bytes:
        compressed = _xor_bytes(self.ciphertext, self.key)
        return zlib.decompress(compressed)


@dataclass(slots=True)
class _CacheEntry:
    value: Any
    expires_at: float


class AnalysisCache:
    """Thread-safe bounded LRU+TTL cache keyed by (vendor_id, source_digest)."""

    def __init__(
        self,
        *,
        max_entries: int = DEFAULT_PUBLIC_CACHE_MAX_ENTRIES,
        ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_entries < 1 or ttl_seconds <= 0:
            raise ValueError("AnalysisCache max_entries and ttl_seconds must be positive")
        self._max_entries = int(max_entries)
        self._ttl_seconds = float(ttl_seconds)
        self._clock = clock
        self._lock = threading.RLock()
        self._entries: OrderedDict[tuple[str, str], _CacheEntry] = OrderedDict()

    def _prune_locked(self, now: float) -> None:
        expired = [key for key, entry in self._entries.items() if entry.expires_at <= now]
        for key in expired:
            self._entries.pop(key, None)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)

    def get(self, vendor_id: str, source_digest: str) -> Any | None:
        key = (vendor_id, source_digest)
        with self._lock:
            now = self._clock()
            self._prune_locked(now)
            entry = self._entries.get(key)
            if entry is None:
                return None
            entry.expires_at = now + self._ttl_seconds
            self._entries.move_to_end(key)
            return entry.value

    def put(self, vendor_id: str, source_digest: str, value: Any) -> None:
        key = (vendor_id, source_digest)
        with self._lock:
            now = self._clock()
            self._entries[key] = _CacheEntry(value=value, expires_at=now + self._ttl_seconds)
            self._entries.move_to_end(key)
            self._prune_locked(now)

    def get_or_load(self, vendor_id: str, source_digest: str, loader: Callable[[], Any]) -> Any:
        cached = self.get(vendor_id, source_digest)
        if cached is not None:
            return cached
        value = loader()
        self.put(vendor_id, source_digest, value)
        return value

    def evict(self, vendor_id: str, source_digest: str) -> bool:
        with self._lock:
            return self._entries.pop((vendor_id, source_digest), None) is not None

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            self._prune_locked(self._clock())
            return len(self._entries)


class SealedSourceStore:
    """Bounded in-memory store holding compressed, XOR-sealed UTF-8 source text."""

    def __init__(
        self,
        *,
        max_entries: int = DEFAULT_PUBLIC_CACHE_MAX_ENTRIES,
        ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._cache = AnalysisCache(
            max_entries=max_entries,
            ttl_seconds=ttl_seconds,
            clock=clock,
        )

    def put_text(self, vendor_id: str, source_digest: str, text: str) -> None:
        self._cache.put(vendor_id, source_digest, SealedPayload.seal(text.encode("utf-8")))

    def get_text(self, vendor_id: str, source_digest: str) -> str | None:
        sealed = self._cache.get(vendor_id, source_digest)
        if sealed is None:
            return None
        return sealed.unseal().decode("utf-8")

    def evict(self, vendor_id: str, source_digest: str) -> bool:
        return self._cache.evict(vendor_id, source_digest)

    def clear(self) -> None:
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


def cache_settings_from_app(app: Any) -> tuple[int, float]:
    """Resolve bounded cache limits from Flask config or environment."""
    web_mode = str(app.config.get("WEB_MODE", "public"))
    default_max = default_cache_max_entries(web_mode)
    raw_max = app.config.get("ANALYSIS_CACHE_MAX_ENTRIES", os.environ.get("FWMIGRATE_ANALYSIS_CACHE_MAX_ENTRIES", default_max))
    raw_ttl = app.config.get("ANALYSIS_CACHE_TTL_SECONDS", os.environ.get("FWMIGRATE_ANALYSIS_CACHE_TTL_SECONDS", DEFAULT_CACHE_TTL_SECONDS))
    return int(raw_max), float(raw_ttl)
