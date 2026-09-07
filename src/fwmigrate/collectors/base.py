from __future__ import annotations

from abc import ABC, abstractmethod

from fwmigrate.collectors.models import ConnectionResult, SourceSnapshot


class BaseSourceCollector(ABC):
    """Acquire raw source configuration without parsing or target assumptions."""

    @abstractmethod
    def test_connection(self) -> ConnectionResult:
        ...

    @abstractmethod
    def collect(self) -> SourceSnapshot:
        ...
