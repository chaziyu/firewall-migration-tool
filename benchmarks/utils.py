from dataclasses import dataclass
from pathlib import Path
from statistics import median
from time import perf_counter
import tracemalloc
from typing import Callable, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class BenchmarkResult(Generic[T]):
    name: str
    iterations: int
    average_ms: float
    median_ms: float
    minimum_ms: float
    peak_memory_mib: float
    value: T


def measure(name: str, operation: Callable[[], T], iterations: int = 5) -> BenchmarkResult[T]:
    operation()
    timings = []
    tracemalloc.start()
    try:
        value = None
        for _ in range(iterations):
            started = perf_counter()
            value = operation()
            timings.append((perf_counter() - started) * 1000)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return BenchmarkResult(
        name=name,
        iterations=iterations,
        average_ms=sum(timings) / len(timings),
        median_ms=median(timings),
        minimum_ms=min(timings),
        peak_memory_mib=peak / 1024 / 1024,
        value=value,
    )


def fixture_path(name: str) -> Path:
    return Path(__file__).resolve().parents[1] / "tests" / "fixtures" / name


def print_result(result: BenchmarkResult[object]) -> None:
    print(
        f"{result.name}: avg_ms={result.average_ms:.3f} median_ms={result.median_ms:.3f} "
        f"min_ms={result.minimum_ms:.3f} peak_mib={result.peak_memory_mib:.3f} "
        f"iterations={result.iterations}"
    )
