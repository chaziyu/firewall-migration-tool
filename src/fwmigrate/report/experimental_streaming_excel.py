"""Isolated write-only worksheet experiment; never used by the production exporter."""

from __future__ import annotations

import io
import time
from typing import Iterable, Sequence

from .excel_serialization import profile_xlsx


def export_write_only_table(
    title: str,
    headers: Sequence[str],
    rows: Iterable[Sequence[object]],
) -> tuple[bytes, dict[str, object]]:
    """Write one plain table in openpyxl write-only mode for comparison."""
    from openpyxl import Workbook

    started = time.perf_counter()
    workbook = Workbook(write_only=True)
    sheet = workbook.create_sheet(title)
    sheet.append([title])
    sheet.append(["Experimental write-only export; formatting and post-write mutation are intentionally absent."])
    sheet.append(list(headers))
    for row in rows:
        sheet.append(list(row))
    output = io.BytesIO()
    workbook.save(output)
    data = output.getvalue()
    return data, {"total_seconds": round(time.perf_counter() - started, 6), **profile_xlsx(data)}
