# Performance baseline

This document records the repeatable local benchmark used for performance work. It is not a compatibility or performance guarantee: timings depend on Python, hardware, and the selected source fixture.

## Method

Run from the repository root with the development environment installed:

```text
python -m benchmarks.benchmark_pipeline --iterations 5 --optimize
python -m benchmarks.benchmark_parser --iterations 5
python -m benchmarks.benchmark_generator --iterations 5
python -m benchmarks.benchmark_validation --iterations 5
python -m benchmarks.benchmark_large_config --scale 1000 --iterations 3
```

The harness warms each operation once, reports average, median, and minimum wall time, and measures peak allocations with `tracemalloc`. Fixtures are sanitized and deterministic. No configuration content, credentials, or migration result cache is written.

## Baseline captured 2026-09-15

The baseline used `tests/fixtures/example_cisco_asa.cfg` for parser, pipeline, generator, and validation runs. The large-IR benchmark used a synthetic dependency-heavy IR at scale 1000.

| Operation | Average | Peak memory |
| :--- | ---: | ---: |
| Pipeline with optimization | 174.596 ms | 1.234 MiB |
| Cisco ASA extraction | 155.950 ms | 0.917 MiB |
| PAN-OS XML generation | 3.873 ms | 0.038 MiB |
| Validation | 0.307 ms | 0.015 MiB |
| IR index build, scale 1000 | 67.753 ms | 0.459 MiB |
| Dependency graph build, scale 1000 | 23.308 ms | 1.213 MiB |
| Unused-object analysis, scale 1000 | 2.800 ms | 0.098 MiB |

The sample pipeline is extraction-bound. Index and dependency work is only useful when it replaces repeated lookups; no absolute threshold is enforced because these measurements are machine-specific.

The Phase 4 semantic scaling run measured median 128 ms, 606 ms, and 867 ms at 1,000, 5,000, and 10,000 synthetic addresses after the family-separated sweep. The pre-optimization 10,000-address run exceeded two minutes without completing, so the production change is benchmark-justified. Worst-case all-overlap output remains quadratic by contract.

## Change record

The pipeline now exposes opt-in stage metrics with `MigrationRequest(collect_metrics=True)`. The index and dependency graph are derived runtime state, rebuilt when the working IR is replaced, and are not serialized or exposed as migration artifacts.

Unused-object analysis now consumes the shared `DependencyGraph` reachability result, including conservative retention for same-name object/group collisions. Correctness remains governed by the existing optimizer, golden, safety, and generator tests.

The source IR deepcopy remains in the pipeline because the Phase 0 working-copy stage was about 4.7 ms versus roughly 377 ms extraction in the same run; copy-on-write normalization is intentionally deferred until that ratio changes.

No parser, generator, report, cache, concurrency, streaming, or incremental-parsing change is claimed from this baseline. Those changes require a new measured hotspot and an equivalent-artifact comparison.
