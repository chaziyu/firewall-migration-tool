from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from fwmigrate.vendors.fortigate.benchmark import (
    BenchmarkTimings,
    git_identity,
    max_peak_memory,
    median_timings,
    sha256_bytes,
)


class BenchmarkHelpersTest(unittest.TestCase):
    def test_timing_aggregation_uses_medians(self):
        samples = [
            BenchmarkTimings(*(float(value) for value in values))
            for values in ((1, 10, 4, 5, 6, 20, 46), (3, 2, 6, 7, 8, 10, 36), (100, 3, 8, 9, 10, 12, 142))
        ]
        result = median_timings(samples)
        self.assertEqual(3, result.parse_ms)
        self.assertEqual(12, result.excel_export_ms)
        self.assertEqual(46, result.total_ms)

    def test_sha256_uses_exact_input_bytes(self):
        self.assertEqual(
            "5b42e502734aa4e4364647dd69684bcf86329f63c5d2de6ecff252e87d8a8b06",
            sha256_bytes(b"config system global\r\nend\r\n"),
        )

    def test_peak_memory_uses_maximum(self):
        self.assertEqual(9, max_peak_memory([2, 9, 4]))

    def test_git_metadata_failure_is_nonfatal(self):
        with patch("fwmigrate.vendors.fortigate.benchmark.subprocess.run", side_effect=subprocess.CalledProcessError(1, "git")):
            self.assertEqual((None, None), git_identity(Path.cwd()))


if __name__ == "__main__":
    unittest.main()
