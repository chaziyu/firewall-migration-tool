from __future__ import annotations

from dataclasses import dataclass

from ..model.source import CheckPointConfig


@dataclass(frozen=True)
class ExtractionResult:
    config: CheckPointConfig
