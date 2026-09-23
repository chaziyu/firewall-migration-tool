#!/usr/bin/env python3
"""Benchmark the normal FortiGate analysis and Excel export pipeline."""

from __future__ import annotations

import argparse
import io
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path
from platform import python_version

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fwmigrate.vendors.fortigate.benchmark import (  # noqa: E402
    BenchmarkResult,
    BenchmarkTimings,
    git_identity,
    median_timings,
    sha256_bytes,
)
from fwmigrate.vendors.fortigate.derived import build_derived_views  # noqa: E402
from fwmigrate.vendors.fortigate.config import ExtractionConfig  # noqa: E402
from fwmigrate.vendors.fortigate.export import export_excel  # noqa: E402
from fwmigrate.vendors.fortigate.export.excel import _benchmark_excel_export  # noqa: E402
from fwmigrate.vendors.fortigate.extraction.extractor import (  # noqa: E402
    extract_fortigate_config,
)
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config  # noqa: E402
from fwmigrate.vendors.fortigate.validation.validator import (  # noqa: E402
    validate_config,
)
from fwmigrate.vendors.fortigate.web_report import build_web_report  # noqa: E402


def _timed(call):
    started = time.perf_counter()
    value = call()
    return value, (time.perf_counter() - started) * 1000


def _workload_counts(config) -> dict[str, int]:
    return {
        "Interfaces": len(config.interfaces),
        "Zones": len(config.zones),
        "Addresses": len(config.addresses),
        "Address Groups": len(config.address_groups),
        "Services": len(config.services),
        "Service Groups": len(config.service_groups),
        "Policies": len(config.policies),
        "IP Pools": len(config.ip_pools),
        "Virtual IPs": len(config.vips),
        "Routes": len(config.static_routes),
        "VPN Phase 1": len(config.ipsec_phase1),
        "VPN Phase 2": len(config.ipsec_phase2),
        "DHCP Servers": len(config.dhcp_servers),
        "SD-WAN Configurations": len(config.sdwans),
        "SSL VPN Portals": len(config.ssl_vpn_portals),
        "Local Users": len(config.local_users),
        "Administrators": len(config.administrators),
        "IPS Sensors": len(config.ips_sensors),
        "External Resources": len(config.external_resources),
    }


def _run_pipeline(source: str, source_name: str, *, measure: bool):
    def run(call):
        return _timed(call) if measure else (call(), None)

    tree, parse_ms = run(lambda: parse_fortigate_config(source))
    extracted, extraction_ms = run(
        lambda: extract_fortigate_config(tree, config=ExtractionConfig())
    )
    derived, derived_ms = run(lambda: build_derived_views(extracted.config))
    validation, validation_ms = run(
        lambda: validate_config(extracted.config, derived=derived)
    )
    _, web_report_ms = run(
        lambda: build_web_report(
            extracted.config,
            derived,
            validation,
            top_level_sections=len(tree.configs),
        )
    )

    if measure:
        excel_build_ms, excel_save_ms, excel_total_ms, sheet_timings = _benchmark_excel_export(
            extracted=extracted,
            derived=derived,
            validation=validation,
            source_name=source_name,
        )
        excel_total_ms = excel_build_ms + excel_save_ms
        timings = BenchmarkTimings(
            parse_ms=parse_ms,
            extraction_ms=extraction_ms,
            derived_ms=derived_ms,
            validation_ms=validation_ms,
            web_report_ms=web_report_ms,
            excel_build_ms=excel_build_ms,
            excel_save_ms=excel_save_ms,
            excel_total_ms=excel_total_ms,
            total_ms=sum((parse_ms, extraction_ms, derived_ms, validation_ms, web_report_ms, excel_total_ms)),
            sheet_timings=sheet_timings,
        )
    else:
        export_excel(
            extracted=extracted,
            derived=derived,
            validation=validation,
            output=io.BytesIO(),
            source_name=source_name,
            benchmark=None,
        )
        timings = None

    return tree, extracted, derived, validation, timings


def benchmark(input_path: Path, output_path: Path, runs: int, warmup: int, scenario: str | None) -> BenchmarkResult:
    source_bytes = input_path.read_bytes()
    source = source_bytes.decode("utf-8-sig")
    samples: list[BenchmarkTimings] = []
    git_branch, git_commit = git_identity(ROOT)

    if tracemalloc.is_tracing():
        tracemalloc.stop()
    for _ in range(warmup):
        _run_pipeline(source, input_path.name, measure=True)
    final_run = None
    for _ in range(runs):
        final_run = _run_pipeline(source, input_path.name, measure=True)
        samples.append(final_run[4])

    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        _run_pipeline(source, input_path.name, measure=False)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    final_tree, final_extracted, final_derived, final_validation, _ = final_run

    result = BenchmarkResult(
        timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        scenario=scenario,
        git_branch=git_branch,
        git_commit=git_commit,
        python_version=python_version(),
        input_size_bytes=len(source_bytes),
        input_sha256=sha256_bytes(source_bytes),
        runs=runs,
        warmup_runs=warmup,
        timings=median_timings(samples),
        peak_memory_bytes=peak,
        top_level_sections=len(final_tree.configs),
        source_object_count=len(final_extracted.source_objects),
        validation_issue_count=len(final_validation.issues),
        object_counts=_workload_counts(final_extracted.config),
    )
    export_excel(
        extracted=final_extracted,
        derived=final_derived,
        validation=final_validation,
        output=output_path,
        source_name=input_path.name,
        benchmark=result,
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="FortiGate configuration file")
    parser.add_argument("--output", type=Path, default=Path("benchmark.xlsx"))
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--scenario")
    args = parser.parse_args()
    if args.runs < 1 or args.warmup < 0:
        parser.error("--runs must be at least 1 and --warmup cannot be negative")

    result = benchmark(args.input, args.output, args.runs, args.warmup, args.scenario)
    timings = result.timings
    print("FortiGate benchmark complete")
    print(f"Input:           {args.input.name}")
    print(f"Runs:            {result.runs} (+{result.warmup_runs} warm-up)")
    for label, value in (
        ("Parse", timings.parse_ms),
        ("Extraction", timings.extraction_ms),
        ("Derived", timings.derived_ms),
        ("Validation", timings.validation_ms),
        ("Web report", timings.web_report_ms),
        ("Excel build", timings.excel_build_ms),
        ("Excel save", timings.excel_save_ms),
        ("Excel total", timings.excel_total_ms),
        ("Total", timings.total_ms),
    ):
        print(f"{label + ':':16}{value:9.1f} ms")
    print(f"Peak memory:     {result.peak_memory_bytes / (1024 * 1024):.1f} MiB")
    print(f"\nReference workbook:\n{args.output}")


if __name__ == "__main__":
    main()
