from __future__ import annotations

import hashlib
import io
import unittest
from unittest.mock import patch

from openpyxl import load_workbook

from fwmigrate.vendors.fortigate.benchmark import BenchmarkResult, BenchmarkTimings, ExcelSheetBenchmark
from fwmigrate.vendors.fortigate.config import ExtractionConfig
from fwmigrate.vendors.fortigate.derived import build_derived_views
from fwmigrate.vendors.fortigate.export import export_excel
from fwmigrate.vendors.fortigate.export import excel as excel_module
from fwmigrate.vendors.fortigate.export.excel_schema import SHEET_ORDER
from fwmigrate.vendors.fortigate.extraction.extractor import extract_fortigate_config
from fwmigrate.vendors.fortigate.parser import parse_fortigate_config
from fwmigrate.vendors.fortigate.validation.validator import validate_config


_SOURCE = '''
config system admin
    edit "benchmark-admin"
        set password "BENCHMARK_SECRET_MARKER"
    next
end
config firewall policy
    edit 7
        set name "BENCHMARK_RAW_CLI_MARKER"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
end
config vpn ipsec phase1-interface
    edit "benchmark-phase1"
        set psksecret "BENCHMARK_PSK_MARKER"
    next
end
config system api-user
    edit "benchmark-api-user"
        set api-key "BENCHMARK_API_TOKEN_MARKER"
    next
end
'''


def _result(source: bytes) -> BenchmarkResult:
    return BenchmarkResult(
        timestamp_utc="2026-09-23 01:02:03",
        scenario="test",
        git_branch="codex/test",
        git_commit="abc123",
        python_version="3.14.0",
        input_size_bytes=len(source),
        input_sha256=hashlib.sha256(source).hexdigest(),
        runs=3,
        warmup_runs=1,
        timings=BenchmarkTimings(
            1, 2, 3, 4, 5, 2, 4, 6, 21,
            {
                "Summary": ExcelSheetBenchmark("Summary", 0, 0, 0.5, 0.5),
                "Policies": ExcelSheetBenchmark("Policies", 1, 0.2, 0.5, 0.7),
            },
        ),
        peak_memory_bytes=2 * 1024 * 1024,
        top_level_sections=2,
        source_object_count=5,
        validation_issue_count=1,
        object_counts={"Policies": 1, "Interfaces": 2},
    )


def _workbook(benchmark: BenchmarkResult | None):
    extracted = extract_fortigate_config(
        parse_fortigate_config(_SOURCE), config=ExtractionConfig()
    )
    derived = build_derived_views(extracted.config)
    validation = validate_config(extracted.config, derived=derived)
    output = io.BytesIO()
    export_excel(
        extracted=extracted,
        derived=derived,
        validation=validation,
        output=output,
        source_name="sanitized.conf",
        benchmark=benchmark,
    )
    output.seek(0)
    return load_workbook(output, data_only=True)


class ExcelBenchmarkTest(unittest.TestCase):
    def test_timed_rows_stays_lazy_and_counts_consumed_rows(self):
        generated = []

        def rows():
            generated.append("row")
            yield {"value": 1}
            generated.append("row")
            yield {"value": 2}

        metrics = {"elapsed_ms": 0.0, "rows": 0}
        timed = excel_module._timed_rows(rows(), metrics)
        self.assertEqual([], generated)
        self.assertEqual(2, len(list(timed)))
        self.assertEqual(["row", "row"], generated)
        self.assertEqual(2, metrics["rows"])

    def test_benchmark_sheet_is_opt_in_and_appended_once(self):
        normal = _workbook(None)
        self.assertEqual(list(SHEET_ORDER), normal.sheetnames)
        self.assertNotIn("Performance Benchmark", normal.sheetnames)

        measured = _workbook(_result(_SOURCE.encode()))
        self.assertEqual(list(SHEET_ORDER), measured.sheetnames[:-1])
        self.assertEqual("Performance Benchmark", measured.sheetnames[-1])
        self.assertEqual(1, measured.sheetnames.count("Performance Benchmark"))

    def test_benchmark_values_and_exact_input_identity_are_written(self):
        raw = _SOURCE.encode()
        workbook = _workbook(_result(raw))
        values = {
            cell.value
            for row in workbook["Performance Benchmark"].iter_rows()
            for cell in row
            if cell.value is not None
        }
        self.assertIn("Git Commit", values)
        self.assertIn("abc123", values)
        self.assertIn("Input SHA-256", values)
        self.assertIn(hashlib.sha256(raw).hexdigest(), values)
        self.assertIn(len(raw), values)
        for expected in (
            "Parse", "Extraction", "Excel Build", "Excel Save", "Excel Total", "Total",
            "Peak Traced Memory", "Excel Sheet Performance", "Policies", "Summary",
            "Source Objects", "tracemalloc disabled", "Separate full pipeline run",
            "MiB, max; separate traced run",
            "Rows", "Row Generation (ms)", "Worksheet Writing (ms)", "Total (ms)",
        ):
            self.assertIn(expected, values)

    def test_excel_build_and_save_are_measured_separately_and_sheet_collection_is_opt_in(self):
        extracted = extract_fortigate_config(
            parse_fortigate_config(_SOURCE), config=ExtractionConfig()
        )
        derived = build_derived_views(extracted.config)
        validation = validate_config(extracted.config, derived=derived)

        class FakeWorkbook:
            def save(self, output):
                output.write(b"workbook")

        def build(context, *, sheet_timings):
            sheet_timings.update({"Summary": ExcelSheetBenchmark("Summary", 0, 0, 1, 1), "Policies": ExcelSheetBenchmark("Policies", 1, 1, 1, 2)})
            return FakeWorkbook()

        with (
            patch.object(excel_module, "_build_workbook", side_effect=build),
            patch.object(excel_module, "perf_counter", side_effect=(0.0, 0.003, 0.010, 0.015)),
        ):
            build_ms, save_ms, total_ms, sheet_timings = excel_module._benchmark_excel_export(
                extracted=extracted,
                derived=derived,
                validation=validation,
                source_name="sanitized.conf",
            )

        self.assertAlmostEqual(3.0, build_ms)
        self.assertAlmostEqual(5.0, save_ms)
        self.assertAlmostEqual(8.0, total_ms)
        self.assertEqual(build_ms + save_ms, total_ms)
        self.assertEqual(2.0, sheet_timings["Policies"].total_ms)

    def test_normal_export_does_not_collect_sheet_timings(self):
        with patch.object(
            excel_module, "_build_workbook", wraps=excel_module._build_workbook
        ) as build:
            workbook = _workbook(None)
        self.assertEqual(list(SHEET_ORDER), workbook.sheetnames)
        self.assertNotIn("sheet_timings", build.call_args.kwargs)

    def test_sheet_performance_covers_every_normal_workbook_sheet(self):
        extracted = extract_fortigate_config(
            parse_fortigate_config(_SOURCE), config=ExtractionConfig()
        )
        derived = build_derived_views(extracted.config)
        validation = validate_config(extracted.config, derived=derived)
        _, _, _, sheet_timings = excel_module._benchmark_excel_export(
            extracted=extracted,
            derived=derived,
            validation=validation,
            source_name="sanitized.conf",
        )
        self.assertEqual(set(SHEET_ORDER), set(sheet_timings))
        self.assertIn("FortiGate Source Inventory", sheet_timings)
        self.assertIn("Extraction Coverage", sheet_timings)
        for name in ("Addresses", "Services", "Policies", "FortiGate Source Inventory"):
            self.assertGreaterEqual(sheet_timings[name].row_count, 0)
            self.assertAlmostEqual(
                sheet_timings[name].total_ms,
                sheet_timings[name].row_generation_ms + sheet_timings[name].worksheet_write_ms,
                delta=0.1,
            )

    def test_benchmark_sheet_contains_no_source_configuration(self):
        workbook = _workbook(_result(_SOURCE.encode()))
        values = " ".join(
            str(cell.value)
            for row in workbook["Performance Benchmark"].iter_rows()
            for cell in row
            if cell.value is not None
        )
        self.assertNotIn("BENCHMARK_SECRET_MARKER", values)
        self.assertNotIn("BENCHMARK_PSK_MARKER", values)
        self.assertNotIn("BENCHMARK_API_TOKEN_MARKER", values)
        self.assertNotIn("BENCHMARK_RAW_CLI_MARKER", values)
        self.assertNotIn("set password", values)


if __name__ == "__main__":
    unittest.main()
