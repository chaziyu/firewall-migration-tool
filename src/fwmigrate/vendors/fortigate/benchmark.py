"""Safe, read-only performance measurements for the FortiGate pipeline."""

from __future__ import annotations

import hashlib
import statistics
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence


@dataclass(frozen=True, slots=True)
class ExcelSheetBenchmark:
    sheet: str
    row_count: int
    row_generation_ms: float
    worksheet_write_ms: float
    total_ms: float


@dataclass(frozen=True, slots=True)
class BenchmarkTimings:
    parse_ms: float
    extraction_ms: float
    derived_ms: float
    validation_ms: float
    web_report_ms: float
    excel_build_ms: float
    excel_save_ms: float
    excel_total_ms: float
    total_ms: float
    sheet_timings: Mapping[str, ExcelSheetBenchmark] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "sheet_timings", MappingProxyType(dict(self.sheet_timings)))


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    timestamp_utc: str
    scenario: str | None
    git_branch: str | None
    git_commit: str | None
    python_version: str
    input_size_bytes: int
    input_sha256: str
    runs: int
    warmup_runs: int
    timings: BenchmarkTimings
    peak_memory_bytes: int | None
    top_level_sections: int
    source_object_count: int
    validation_issue_count: int
    object_counts: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "object_counts", MappingProxyType(dict(self.object_counts)))


def median_timings(samples: Sequence[BenchmarkTimings]) -> BenchmarkTimings:
    if not samples:
        raise ValueError("At least one timing sample is required")
    fields = (
        "parse_ms", "extraction_ms", "derived_ms", "validation_ms", "web_report_ms",
        "excel_build_ms", "excel_save_ms",
    )
    sheet_names = set().union(*(sample.sheet_timings for sample in samples))
    medians = {
        name: statistics.median(getattr(sample, name) for sample in samples)
        for name in fields
    }
    medians["excel_total_ms"] = medians["excel_build_ms"] + medians["excel_save_ms"]
    medians["total_ms"] = sum(
        medians[name]
        for name in (
            "parse_ms", "extraction_ms", "derived_ms", "validation_ms", "web_report_ms",
            "excel_total_ms",
        )
    )
    return BenchmarkTimings(
        **medians,
        sheet_timings={
            name: ExcelSheetBenchmark(
                sheet=name,
                row_count=samples[0].sheet_timings[name].row_count,
                row_generation_ms=statistics.median(
                    sample.sheet_timings[name].row_generation_ms for sample in samples
                ),
                worksheet_write_ms=statistics.median(
                    sample.sheet_timings[name].worksheet_write_ms for sample in samples
                ),
                total_ms=statistics.median(
                    sample.sheet_timings[name].total_ms for sample in samples
                ),
            )
            for name in sheet_names
            if all(name in sample.sheet_timings for sample in samples)
        },
    )


def sha256_bytes(data: bytes) -> str:
    """Hash the exact input bytes without decoding or normalization."""
    return hashlib.sha256(data).hexdigest()


def git_identity(root: Path) -> tuple[str | None, str | None]:
    values = []
    for args in (("rev-parse", "--abbrev-ref", "HEAD"), ("rev-parse", "HEAD")):
        try:
            result = subprocess.run(
                ["git", *args], cwd=root, check=True, capture_output=True,
                text=True, timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            values.append(None)
        else:
            values.append(result.stdout.strip() or None)
    return values[0], values[1]
