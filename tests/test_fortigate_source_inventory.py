import io

from openpyxl import load_workbook

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.report.excel_exporter import IRExcelExporter


OPERATIONAL_CONFIG = '''config system ha
    set group-name "FGT-HA"
    set mode a-p
    set hbdev "ha1" 50
end
config system physical-switch
    edit "sw0"
        set age-val 300
    next
end
config system ike
    set dh-group 14
end
config system settings
    set opmode nat
end
config firewall ssh setting
    set caname "SSH-CA"
end
config log fortianalyzer setting
    set status enable
    set server "faz.example.test"
end
config system ntp
    set ntpsync enable
    set type custom
end
config system autoupdate schedule
    set frequency daily
end
config firewall address
    edit "dedicated-address"
        set subnet 192.0.2.0 255.255.255.0
    next
end
'''


def _source_sheet(config: str):
    result = extract_fortigate_config(config)
    workbook = load_workbook(
        io.BytesIO(
            IRExcelExporter(
                result.canonical_ir,
                extraction_result=result,
            ).generate()
        )
    )
    sheet = workbook["FortiGate Source Configuration"]
    headers = {cell.value: cell.column for cell in sheet[3]}
    rows = [
        {
            name: sheet.cell(row, column).value
            for name, column in headers.items()
        }
        for row in range(4, sheet.max_row + 1)
    ]
    return result, workbook, rows


def test_unmodeled_operational_commands_are_visible_without_ir_models() -> None:
    result, workbook, rows = _source_sheet(OPERATIONAL_CONFIG)

    assert "FortiGate Source Configuration" in workbook.sheetnames
    by_path = {}
    for row in rows:
        by_path.setdefault(row["Source Path"], []).append(row)

    assert {
        row["Setting"]: row["Value"]
        for row in by_path["system ha"]
    } == {
        "group-name": "FGT-HA",
        "mode": "a-p",
        "hbdev": "ha1\n50",
    }
    physical_switch = by_path["system physical-switch"][0]
    assert physical_switch["Object"] == "sw0"
    assert physical_switch["Setting"] == "age-val"

    assert by_path["system ike"][0]["Setting"] == "dh-group"
    assert by_path["system settings"][0]["Setting"] == "opmode"
    assert by_path["firewall ssh setting"][0]["Setting"] == "caname"
    assert by_path["log fortianalyzer setting"][0]["Setting"] == "status"
    assert {row["Setting"] for row in by_path["system ntp"]} == {"ntpsync", "type"}
    assert by_path["system autoupdate schedule"][0]["Setting"] == "frequency"

    inventory_paths = {item.source_path for item in result.inventory_items}
    assert "system ha" in inventory_paths
    assert "system physical-switch" in inventory_paths


def test_dedicated_inventory_is_not_duplicated_in_generic_sheet() -> None:
    _, _, rows = _source_sheet(OPERATIONAL_CONFIG)
    assert all(row["Source Path"] != "firewall address" for row in rows)
