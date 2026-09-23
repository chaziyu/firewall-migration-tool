from __future__ import annotations

from dataclasses import dataclass

from ..source_model import CheckPointConfig


@dataclass(frozen=True)
class ExtractionResult:
    config: CheckPointConfig
