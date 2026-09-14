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

from fwmigrate.ir.core import AddressType, IRAddress, IRAddressGroup, IRConfig, IRMetadata
from fwmigrate.report import IRExcelExporter


SCENARIO_COUNTS = {
    "small": (25, 0),
    "addresses": (1000, 0),
    "mixed": (250, 50),
}


def build_ir(scenario: str) -> IRConfig:
    address_count, group_count = SCENARIO_COUNTS[scenario]
    addresses = [
        IRAddress(
            name=f"benchmark-address-{index:05d}",
            type=AddressType.HOST,
            value=f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}/32",
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
    return IRConfig(
        metadata=IRMetadata(hostname=f"benchmark-{scenario}", source_vendor="fortigate"),
        addresses=addresses,
        address_groups=groups,
    )


def run_once(scenario: str) -> dict[str, object]:
    exporter = IRExcelExporter(build_ir(scenario))
    tracemalloc.start()
    started = time.perf_counter()
    output = exporter.generate()
    elapsed = time.perf_counter() - started
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    metrics = getattr(exporter, "_last_export_metrics", None)
    if metrics is None:
        raise RuntimeError("Excel debug metrics were not collected")
    return {
        "scenario": scenario,
        "timings": metrics.timings,
        "total_seconds": round(elapsed, 6),
        "worksheet_count": metrics.worksheet_count,
        "total_rows": metrics.total_rows,
        "populated_cells": metrics.populated_cells,
        "largest_worksheets": metrics.largest_worksheets,
        "xlsx_bytes": len(output),
        "peak_memory_bytes": peak_memory,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=tuple(SCENARIO_COUNTS),
        help="Scenario to run; repeat for multiple scenarios (default: all).",
    )
    args = parser.parse_args()

    logging.getLogger("fwmigrate.report.excel_optimized").setLevel(logging.DEBUG)
    scenarios = args.scenario or list(SCENARIO_COUNTS)
    for scenario in scenarios:
        print(json.dumps(run_once(scenario), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
