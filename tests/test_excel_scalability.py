import io

from openpyxl import Workbook, load_workbook

from fwmigrate.ir.core import AddressType, IRAddress, IRConfig, IRMetadata
from fwmigrate.report import ExcelExportOptions, ExcelExportProfile, IRExcelExporter
from fwmigrate.report.excel_exporter import IRExcelExporter as BaseExporter
from fwmigrate.report.excel_serialization import profile_xlsx


def _ir() -> IRConfig:
    return IRConfig(
        metadata=IRMetadata(hostname="scalability", source_vendor="fortigate"),
        addresses=[
            IRAddress(
                name="review-address",
                type=AddressType.HOST,
                value="192.0.2.1/32",
                migration_status="UNSUPPORTED",
                requires_manual_review=True,
                audit_note="manual mapping",
            )
        ],
    )


def test_table_sheet_consumes_rows_once_and_partitions_deterministically():
    exporter = BaseExporter(
        IRConfig(metadata=IRMetadata(hostname="partition", source_vendor="fortigate")),
        options=ExcelExportOptions(max_rows_per_sheet=2),
    )
    workbook = Workbook()
    consumed = []

    def rows():
        for value in range(5):
            consumed.append(value)
            yield (value,)

    exporter._table_sheet(workbook, "Items", ("Value",), rows())

    assert consumed == [0, 1, 2, 3, 4]
    assert workbook.sheetnames == ["Sheet", "Items 1", "Items 2", "Items 3"]
    assert [workbook[name].cell(4, 1).value for name in workbook.sheetnames[1:]] == [0, 2, 4]


def test_profiles_preserve_values_and_keep_audit_sheets():
    outputs = {
        profile: load_workbook(
            io.BytesIO(
                IRExcelExporter(
                    _ir(),
                    options=ExcelExportOptions(profile=profile),
                ).generate()
            )
        )
        for profile in ExcelExportProfile
    }

    assert all("Review Required" in workbook.sheetnames for workbook in outputs.values())
    assert all("Extraction Evidence" in workbook.sheetnames for workbook in outputs.values())
    assert [outputs[profile]["Addresses"].cell(4, 1).value for profile in outputs] == [
        "review-address"
    ] * len(outputs)

    profile = profile_xlsx(
        io.BytesIO(
            IRExcelExporter(_ir()).generate()
        ).getvalue()
    )
    assert profile["zip_entries"] > 0
    assert profile["styles_xml_bytes"] > 0
