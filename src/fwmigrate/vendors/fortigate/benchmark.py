"""Safe, read-only performance measurements for the FortiGate pipeline."""

from __future__ import annotations

import hashlib
import statistics
import subprocess
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence


@dataclass(frozen=True, slots=True)
class BenchmarkTimings:
    parse_ms: float
    extraction_ms: float
    derived_ms: float
    validation_ms: float
    web_report_ms: float
    excel_export_ms: float
    total_ms: float


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
    return BenchmarkTimings(
        **{
            field: statistics.median(getattr(sample, field) for sample in samples)
            for field in BenchmarkTimings.__dataclass_fields__
        }
    )


def sha256_bytes(data: bytes) -> str:
    """Hash the exact input bytes without decoding or normalization."""
    return hashlib.sha256(data).hexdigest()


def max_peak_memory(peaks: Sequence[int]) -> int | None:
    return max(peaks, default=None)


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
