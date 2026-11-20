"""Collector lookup without vendor semantics in the web host."""

from collections.abc import Callable

from .contracts import CollectedSourceSanitizer, SourceCollector


class SourceCollectorRegistry:
    def __init__(self) -> None:
        self._collectors: dict[str, SourceCollector] = {}
        self._loaders: dict[str, Callable[[], SourceCollector]] = {}

    def register(
        self,
        collector: SourceCollector,
        *,
        loader: Callable[[], SourceCollector] | None = None,
    ) -> None:
        key = collector.vendor_id.casefold()
        if key in self._collectors and self._collectors[key] is not collector:
            raise ValueError(f"Collector already registered: {key}")
        self._collectors[key] = collector
        if loader is not None:
            self._loaders[key] = loader

    def get(self, vendor_id: str) -> SourceCollector:
        try:
            key = vendor_id.casefold()
            collector = self._collectors[key]
        except (AttributeError, KeyError) as exc:
            raise ValueError("Live collection is not supported for this vendor.") from exc
        loader = self._loaders.get(key)
        return loader() if loader is not None else collector

    def list(self) -> tuple[SourceCollector, ...]:
        return tuple(self._collectors.values())


source_collectors = SourceCollectorRegistry()


class CollectedSourceSanitizerRegistry:
    def __init__(self) -> None:
        self._sanitizers: dict[str, CollectedSourceSanitizer] = {}
        self._loaders: dict[str, Callable[[], CollectedSourceSanitizer]] = {}

    def register(
        self,
        sanitizer: CollectedSourceSanitizer,
        *,
        loader: Callable[[], CollectedSourceSanitizer] | None = None,
    ) -> None:
        key = sanitizer.vendor_id.casefold()
        if key in self._sanitizers and self._sanitizers[key] is not sanitizer:
            raise ValueError(f"Collected source sanitizer already registered: {key}")
        self._sanitizers[key] = sanitizer
        if loader is not None:
            self._loaders[key] = loader

    def get(self, vendor_id: str) -> CollectedSourceSanitizer:
        try:
            key = vendor_id.casefold()
            sanitizer = self._sanitizers[key]
        except (AttributeError, KeyError) as exc:
            raise ValueError("Snapshot vendor has no supported live source format.") from exc
        loader = self._loaders.get(key)
        return loader() if loader is not None else sanitizer


collected_source_sanitizers = CollectedSourceSanitizerRegistry()
