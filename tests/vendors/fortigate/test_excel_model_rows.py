from openpyxl import Workbook

from fwmigrate.vendors.fortigate.export.excel import _model_rows, _write_table_sheet


class DumpCountingModel:
    def __init__(self) -> None:
        self.dump_count = 0

    def model_dump(self, *, mode: str) -> dict[str, object]:
        assert mode == "python"
        self.dump_count += 1
        return {
            "name": "one",
            "vdom": "root",
            "raw_extra": {"unsupported": "value"},
            "explicit_fields": ["name"],
        }


class EmptyExcelContext:
    def issues_for(self, **kwargs):
        return []


def test_model_rows_dumps_each_model_once():
    item = DumpCountingModel()

    rows = list(_model_rows(
        EmptyExcelContext(),
        [item],
        ["Name", "Additional Settings", "Source Explicit Fields"],
        {"Name": "name"},
    ))

    assert item.dump_count == 1
    assert rows[0]["Name"] == "one"
    assert rows[0]["Additional Settings"] == {"unsupported": "value"}


def test_table_writer_consumes_generators_and_finalizes_note_and_filter():
    workbook = Workbook()
    workbook.remove(workbook.active)

    _write_table_sheet(
        workbook,
        "Generated",
        ["Name"],
        ({"Name": name} for name in ("one", "two")),
        context=None,
    )

    sheet = workbook["Generated"]
    assert sheet.max_row == 5
    assert sheet[2][0].value == "2 record(s). Values are explicit FortiGate source data unless the column is identified as derived or analysis output."
    assert sheet.auto_filter.ref == "A3:A5"
