from openpyxl import Workbook

from fwmigrate.vendors.fortigate.export.excel import (
    _additional_settings_from_data,
    _model_rows,
    _write_table_sheet,
)


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


def test_additional_settings_follow_model_order_and_preserve_raw_order():
    settings = _additional_settings_from_data(
        {
            "raw_extra": {"raw_z": "z", "raw_a": "a"},
            "explicit_fields": {"later", "api_key", "visible", "earlier"},
            "earlier": "one",
            "visible": "shown elsewhere",
            "api_key": "SECRET_VALUE",
            "later": "two",
        },
        visible_values=("shown elsewhere",),
    )

    assert list(settings) == ["raw_z", "raw_a", "earlier", "api_key", "later"]
    assert settings["api_key"] != "SECRET_VALUE"
