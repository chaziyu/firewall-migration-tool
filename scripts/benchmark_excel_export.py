"""Run deterministic developer-only Excel export benchmarks.

This script intentionally generates IR directly. It is not part of the normal
test suite and writes no workbook files.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
import tracemalloc

from fwmigrate.ir.core import (
    AddressType,
    IRAddress,
    IRAddressGroup,
    IRConfig,
    IRMetadata,
    IRPolicy,
)
from fwmigrate.report import (
    ExcelExportOptions,
    ExcelExportProfile,
    IRExcelExporter,
    StreamingFastExcelExporter,
)
from fwmigrate.report.excel_serialization import (
    compare_compression_levels,
    profile_xlsx,
)


SCENARIOS = {
    "small": (25, 0, 0),
    "addresses-100k": (100_000, 0, 0),
    "policies-10k": (10_000, 0, 10_000),
    "policies-25k": (25_000, 0, 25_000),
    "policies-50k": (50_000, 0, 50_000),
    "mixed": (10_000, 2_000, 10_000),
    "review-heavy": (2_000, 500, 0),
    "group-heavy": (10_000, 10_000, 0),
    "very-wide-policies": (1_000, 0, 1_000),
}


def build_ir(scenario: str) -> IRConfig:
    address_count, group_count, policy_count = SCENARIOS[scenario]
    review_heavy = scenario == "review-heavy"
    addresses = [
        IRAddress(
            name=f"benchmark-address-{index:05d}",
            type=AddressType.HOST,
            value=f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}/32",
            migration_status="UNSUPPORTED" if review_heavy else "NORMALIZED",
            requires_manual_review=review_heavy,
            audit_note="Benchmark review finding" if review_heavy else None,
        )
        for index in range(address_count)
    ]
    groups = [
        IRAddressGroup(
            name=f"benchmark-group-{index:04d}",
            members=[addresses[index % address_count].name],
        )
        for index in range(group_count)
    ]
    policies = [
        IRPolicy(
            name=f"benchmark-policy-{index:05d}",
            source_rule_id=str(index),
            source_action="allow",
            action="allow",
            migration_status="UNSUPPORTED" if review_heavy else "NORMALIZED",
            requires_manual_review=review_heavy,
            review_reasons=["Benchmark review finding"] if review_heavy else [],
            source_extra_settings=(
                {f"wide-setting-{n}": f"value-{index}-{n}" for n in range(25)}
                if scenario == "very-wide-policies" else {}
            ),
        )
        for index in range(policy_count)
    ]
    return IRConfig(
        metadata=IRMetadata(hostname=f"benchmark-{scenario}", source_vendor="fortigate"),
        addresses=addresses,
        address_groups=groups,
        policies=policies,
    )


def run_once(
    scenario: str,
    profile: ExcelExportProfile,
    compression_profile: bool = False,
    compression_level: int | None = None,
) -> dict[str, object]:
    tracemalloc.start()
    preparation_started = time.perf_counter()
    exporter_type = (
        StreamingFastExcelExporter
        if profile is ExcelExportProfile.FAST
        else IRExcelExporter
    )
    exporter = exporter_type(
        build_ir(scenario),
        options=ExcelExportOptions(profile=profile, compression_level=compression_level),
    )
    preparation_seconds = time.perf_counter() - preparation_started
    started = time.perf_counter()
    output = exporter.generate()
    elapsed = time.perf_counter() - started
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    metrics = getattr(exporter, "_last_export_metrics", None)
    if metrics is None:
        raise RuntimeError("Excel debug metrics were not collected")
    result = {
        "scenario": scenario,
        "profile": profile.value,
        "timings": {"IR preparation": preparation_seconds, **metrics.timings},
        "total_seconds": round(elapsed, 6),
        "worksheet_count": metrics.worksheet_count,
        "total_rows": metrics.total_rows,
        "rows_written": metrics.rows_written,
        "cells_written": metrics.cells_written,
        "nonempty_cells": metrics.nonempty_cells,
        "populated_cells": metrics.populated_cells,
        "largest_worksheets": metrics.largest_worksheets,
        "worksheet_metrics": [
            {
                "name": metric.name,
                "rows": metric.rows,
                "columns": metric.columns,
                "cells": metric.cells,
                "nonempty_cells": metric.nonempty_cells,
                "build_seconds": round(metric.build_seconds, 6),
                "sizing_seconds": round(metric.sizing_seconds, 6),
            }
            for metric in metrics.worksheet_metrics
        ],
        "xlsx_bytes": len(output),
        "peak_memory_bytes": peak_memory,
    }
    result["top_sheets"] = {
        field: [
            {
                "name": metric.name,
                "value": getattr(metric, field),
                "rows": metric.rows,
                "columns": metric.columns,
                "cells": metric.cells,
            }
            for metric in sorted(
                metrics.worksheet_metrics,
                key=lambda item: getattr(item, field),
                reverse=True,
            )[:10]
        ]
        for field in ("build_seconds", "sizing_seconds", "rows", "columns", "cells")
    }
    result["serialization_profile"] = profile_xlsx(output)
    result["serialization_percent"] = round(
        100 * metrics.timings.get("final XLSX serialization", 0.0) / max(elapsed, 1e-9),
        2,
    )
    if compression_profile:
        result["compression_profiles"] = compare_compression_levels(output)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=tuple(SCENARIOS),
        help="Scenario to run; repeat for multiple scenarios (default: all).",
    )
    parser.add_argument(
        "--profile",
        choices=tuple(profile.value for profile in ExcelExportProfile),
        default=ExcelExportProfile.FULL.value,
        help="Export profile used for the measurement.",
    )
    parser.add_argument(
        "--compression-profile",
        action="store_true",
        help="Also compare ZIP compression levels in memory.",
    )
    parser.add_argument(
        "--compression-level",
        type=int,
        choices=range(10),
        help="Explicit production ZIP compression level to benchmark.",
    )
    args = parser.parse_args()

    logging.getLogger("fwmigrate.report.excel_optimized").setLevel(logging.DEBUG)
    scenarios = args.scenario or ["small", "addresses-100k", "mixed"]
    profile = ExcelExportProfile(args.profile)
    for scenario in scenarios:
        print(
            json.dumps(
                run_once(
                    scenario,
                    profile,
                    args.compression_profile,
                    args.compression_level,
                ),
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
