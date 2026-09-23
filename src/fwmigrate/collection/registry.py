"""Collector lookup without vendor semantics in the web host."""

from .contracts import SourceCollector


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
