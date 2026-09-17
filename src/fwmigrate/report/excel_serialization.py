"""Read-only XLSX structure and compression profiling helpers."""

from __future__ import annotations

import io
import time
import zipfile
from datetime import datetime, timezone
from typing import Any


def save_workbook_with_compression(workbook: Any, output, compression_level: int = 6) -> None:
    """Write an openpyxl workbook with an explicit ZIP compression level."""
    if not isinstance(compression_level, int) or not 0 <= compression_level <= 9:
        raise ValueError("compression_level must be between 0 and 9")

    from openpyxl.writer.excel import ExcelWriter

    archive = zipfile.ZipFile(
        output,
        "w",
        zipfile.ZIP_DEFLATED,
        compresslevel=compression_level,
        allowZip64=True,
    )
    workbook.properties.modified = datetime.now(timezone.utc).replace(tzinfo=None)
    ExcelWriter(workbook, archive).save()


def profile_xlsx(data: bytes) -> dict[str, Any]:
    """Return cheap, deterministic ZIP/XML measurements for an XLSX payload."""
    started = time.perf_counter()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        sizes = sorted(
            ((entry.filename, entry.file_size, entry.compress_size) for entry in entries),
            key=lambda item: item[1],
            reverse=True,
        )
        worksheet_entries = [item for item in sizes if item[0].startswith("xl/worksheets/")]
        styles = next((item for item in sizes if item[0] == "xl/styles.xml"), ("xl/styles.xml", 0, 0))
    return {
        "zip_entries": len(entries),
        "uncompressed_xml_bytes": sum(item[1] for item in sizes),
        "compressed_xml_bytes": sum(item[2] for item in sizes),
        "styles_xml_bytes": styles[1],
        "largest_worksheet": worksheet_entries[0] if worksheet_entries else None,
        "profile_seconds": round(time.perf_counter() - started, 6),
    }


def compare_compression_levels(
    data: bytes,
    levels: tuple[int, ...] = (1, 6, 9),
) -> list[dict[str, int | float]]:
    """Experiment with ZIP levels without changing openpyxl production behavior."""
    with zipfile.ZipFile(io.BytesIO(data)) as source:
        entries = [(item.filename, source.read(item.filename)) for item in source.infolist()]
    results = []
    for level in levels:
        started = time.perf_counter()
        output = io.BytesIO()
        with zipfile.ZipFile(
            output,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=level,
        ) as archive:
            for filename, content in entries:
                archive.writestr(filename, content)
        results.append({
            "level": level,
            "bytes": len(output.getvalue()),
            "seconds": round(time.perf_counter() - started, 6),
        })
    return results
