from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fwmigrate.vendors.fortigate.benchmark import (
    BenchmarkTimings,
    ExcelSheetBenchmark,
    git_identity,
    median_timings,
    sha256_bytes,
)


class BenchmarkHelpersTest(unittest.TestCase):
    @staticmethod
    def _load_harness():
        root = Path(__file__).parents[3]
        spec = importlib.util.spec_from_file_location(
            "benchmark_fortigate_harness", root / "bin" / "benchmark_fortigate.py"
        )
        harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harness)
        return harness

    def test_timing_aggregation_uses_medians(self):
        samples = [
            BenchmarkTimings(
                parse_ms=parse,
                extraction_ms=2,
                derived_ms=3,
                validation_ms=4,
                web_report_ms=5,
                excel_build_ms=build,
                excel_save_ms=save,
                excel_total_ms=build + save,
                total_ms=parse + 14 + build + save,
                sheet_timings={"Policies": ExcelSheetBenchmark("Policies", 10, sheet, sheet + 1, sheet + 2)},
            )
            for parse, build, save, sheet in ((1, 10, 20, 4), (3, 2, 10, 6), (100, 100, 12, 8))
        ]
        result = median_timings(samples)
        self.assertEqual(3, result.parse_ms)
        self.assertEqual(10, result.excel_build_ms)
        self.assertEqual(12, result.excel_save_ms)
        self.assertEqual(result.excel_build_ms + result.excel_save_ms, result.excel_total_ms)
        self.assertEqual(39, result.total_ms)
        self.assertEqual(6, result.sheet_timings["Policies"].row_generation_ms)

    def test_sha256_uses_exact_input_bytes(self):
        self.assertEqual(
            "5b42e502734aa4e4364647dd69684bcf86329f63c5d2de6ecff252e87d8a8b06",
            sha256_bytes(b"config system global\r\nend\r\n"),
        )

    def test_git_metadata_failure_is_nonfatal(self):
        with patch("fwmigrate.vendors.fortigate.benchmark.subprocess.run", side_effect=subprocess.CalledProcessError(1, "git")):
            self.assertEqual((None, None), git_identity(Path.cwd()))

    def test_pipeline_gates_excel_timing_and_export_by_measurement_mode(self):
        harness = self._load_harness()
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        tree = SimpleNamespace(configs=[])
        extracted = SimpleNamespace(config=object())
        derived = object()
        validation = SimpleNamespace(issues=[])

        def checked(value):
            def call(*args, **kwargs):
                self.assertFalse(tracemalloc.is_tracing())
                return value
            return call

        with (
            patch.object(harness, "parse_fortigate_config", checked(tree)),
            patch.object(harness, "extract_fortigate_config", checked(extracted)),
            patch.object(harness, "build_derived_views", checked(derived)),
            patch.object(harness, "validate_config", checked(validation)),
            patch.object(harness, "build_web_report", checked({})),
            patch.object(harness, "_benchmark_excel_export", checked((2.0, 3.0, 5.0, {}))),
        ):
            measured = harness._run_pipeline("source", "source.conf", measure=True)
        self.assertEqual(5.0, measured[4].excel_total_ms)

        tracemalloc.start()
        try:
            def checked_traced(value):
                def call(*args, **kwargs):
                    self.assertTrue(tracemalloc.is_tracing())
                    return value
                return call

            with (
                patch.object(harness, "parse_fortigate_config", checked_traced(tree)),
                patch.object(harness, "extract_fortigate_config", checked_traced(extracted)),
                patch.object(harness, "build_derived_views", checked_traced(derived)),
                patch.object(harness, "validate_config", checked_traced(validation)),
                patch.object(harness, "build_web_report", checked_traced({})),
                patch.object(harness, "_benchmark_excel_export") as excel_timing,
                patch.object(harness, "export_excel") as normal_export,
                patch.object(harness, "_timed", side_effect=AssertionError("timing during memory run")),
            ):
                memory_run = harness._run_pipeline("source", "source.conf", measure=False)
        finally:
            tracemalloc.stop()
        self.assertIsNone(memory_run[4])
        excel_timing.assert_not_called()
        normal_export.assert_called_once()

    def test_timing_runs_are_untraced_and_memory_run_is_separate(self):
        harness = self._load_harness()

        config = SimpleNamespace(**{
            name: [] for name in (
                "interfaces", "zones", "addresses", "address_groups", "services",
                "service_groups", "policies", "ip_pools", "vips", "static_routes",
                "ipsec_phase1", "ipsec_phase2", "dhcp_servers", "sdwans",
                "ssl_vpn_portals", "local_users", "administrators", "ips_sensors",
                "external_resources",
            )
        })
        tree = SimpleNamespace(configs=[object()])
        extracted = SimpleNamespace(config=config, source_objects=[object()])
        derived = object()
        validation = SimpleNamespace(issues=[object()])
        traced_states = []
        timing_samples = iter((999, 10, 20, 30))

        def fake_run_pipeline(source, source_name, *, measure):
            traced_states.append((measure, tracemalloc.is_tracing()))
            self.assertEqual(not measure, tracemalloc.is_tracing())
            if not measure:
                bytearray(128 * 1024)
                timings = None
            else:
                value = next(timing_samples)
                timings = BenchmarkTimings(
                    parse_ms=value,
                    extraction_ms=2,
                    derived_ms=3,
                    validation_ms=4,
                    web_report_ms=5,
                    excel_build_ms=6,
                    excel_save_ms=7,
                    excel_total_ms=13,
                    total_ms=value + 27,
                    sheet_timings={"Summary": ExcelSheetBenchmark("Summary", 0, 0, float(value), float(value))},
                )
            return tree, extracted, derived, validation, timings

        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.conf"
            input_path.write_bytes(b"synthetic config")
            with (
                patch.object(harness, "_run_pipeline", side_effect=fake_run_pipeline),
                patch.object(harness, "export_excel"),
                patch.object(harness, "git_identity", return_value=("branch", "commit")),
            ):
                result = harness.benchmark(input_path, Path(directory) / "out.xlsx", 3, 1, None)

        self.assertEqual([(True, False)] * 4 + [(False, True)], traced_states)
        self.assertEqual(20, result.timings.parse_ms)
        self.assertEqual(20, result.timings.sheet_timings["Summary"].total_ms)
        self.assertGreater(result.peak_memory_bytes, 0)
        self.assertFalse(tracemalloc.is_tracing())


if __name__ == "__main__":
    unittest.main()
