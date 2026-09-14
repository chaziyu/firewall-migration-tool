import io
from unittest.mock import patch

import pytest

from fwmigrate.ir.core import IRConfig, IRMetadata
from fwmigrate.report import IRExcelExporter


def test_excel_export_avoids_intermediate_workbook_reload():
    openpyxl = pytest.importorskip("openpyxl")
    original_load_workbook = openpyxl.load_workbook

    ir = IRConfig(
        metadata=IRMetadata(
            hostname="performance-test",
            source_vendor="fortigate",
        )
    )

    with patch.object(
        openpyxl,
        "load_workbook",
        side_effect=AssertionError("Excel export must not reload an intermediate workbook"),
    ):
        workbook_bytes = IRExcelExporter(ir).generate()

    workbook = original_load_workbook(io.BytesIO(workbook_bytes))
    assert "Summary" in workbook.sheetnames
    assert "Review Required" in workbook.sheetnames
    assert workbook_bytes.startswith(b"PK")
