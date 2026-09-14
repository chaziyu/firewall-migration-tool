"""Small, explicit options for Excel export trade-offs."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ExcelExportProfile(str, Enum):
    FULL = "full"
    FAST = "fast"
    DATA_ONLY = "data_only"


@dataclass(frozen=True)
class ExcelExportOptions:
    """Options that change presentation cost without changing exported data."""

    profile: ExcelExportProfile = ExcelExportProfile.FULL
    max_rows_per_sheet: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.profile, ExcelExportProfile):
            object.__setattr__(self, "profile", ExcelExportProfile(self.profile))
        if self.max_rows_per_sheet is not None and self.max_rows_per_sheet < 1:
            raise ValueError("max_rows_per_sheet must be at least 1")
