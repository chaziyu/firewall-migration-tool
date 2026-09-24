"""Presentation-only helpers shared by vendor Excel exporters."""

from __future__ import annotations

from enum import Enum
from json import dumps
from typing import Any, Mapping

from fwmigrate.extraction.sanitize import sanitize_source_value


def safe_cell_value(value: Any) -> Any:
    """Convert common Python values into values safe for an Excel cell."""
    if isinstance(value, Enum):
        return safe_cell_value(value.value)
    if isinstance(value, (list, tuple, set)):
        return "\n".join(str(safe_cell_value(item)) for item in value)
    if isinstance(value, Mapping):
        return dumps(value, ensure_ascii=False, default=str, sort_keys=True)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def safe_source_cell(key: str, value: Any) -> Any:
    """Sanitize source data, then convert it for presentation."""
    return safe_cell_value(sanitize_source_value(key, value))


def set_column_widths(sheet: Any, widths: Mapping[str, float]) -> None:
    """Apply presentation-only worksheet column widths."""
    for column, width in widths.items():
        sheet.column_dimensions[column].width = width


def configure_table_view(
    sheet: Any,
    *,
    header_row: int,
    last_row: int,
    last_column: int,
    freeze_panes: str = "A4",
) -> None:
    """Apply the common filter/freeze-pane worksheet presentation."""
    from openpyxl.utils import get_column_letter

    sheet.auto_filter.ref = (
        f"A{header_row}:{get_column_letter(last_column)}{max(header_row, last_row)}"
    )
    sheet.freeze_panes = freeze_panes
