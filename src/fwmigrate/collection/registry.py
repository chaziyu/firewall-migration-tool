"""Collector lookup without vendor semantics in the web host."""

from .contracts import CollectedSourceSanitizer, SourceCollector


class SourceCollectorRegistry:
    def __init__(self) -> None:
        self._collectors: dict[str, SourceCollector] = {}

    def register(self, collector: SourceCollector) -> None:
        key = collector.vendor_id.casefold()
        if key in self._collectors and self._collectors[key] is not collector:
            raise ValueError(f"Collector already registered: {key}")
        self._collectors[key] = collector

    def get(self, vendor_id: str) -> SourceCollector:
        try:
            return self._collectors[vendor_id.casefold()]
        except (AttributeError, KeyError) as exc:
            raise ValueError("Live collection is not supported for this vendor.") from exc

    def list(self) -> tuple[SourceCollector, ...]:
        return tuple(self._collectors.values())


source_collectors = SourceCollectorRegistry()


class CollectedSourceSanitizerRegistry:
    def __init__(self) -> None:
        self._sanitizers: dict[str, CollectedSourceSanitizer] = {}

    def register(self, sanitizer: CollectedSourceSanitizer) -> None:
        key = sanitizer.vendor_id.casefold()
        if key in self._sanitizers and self._sanitizers[key] is not sanitizer:
            raise ValueError(f"Collected source sanitizer already registered: {key}")
        self._sanitizers[key] = sanitizer

    def get(self, vendor_id: str) -> CollectedSourceSanitizer:
        try:
            return self._sanitizers[vendor_id.casefold()]
        except (AttributeError, KeyError) as exc:
            raise ValueError("Snapshot vendor has no supported live source format.") from exc


collected_source_sanitizers = CollectedSourceSanitizerRegistry()
