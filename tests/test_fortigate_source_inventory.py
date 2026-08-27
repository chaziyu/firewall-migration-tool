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

AUTOMATION_CONFIG = '''config system automation-trigger
    edit "High CPU"
        set event-type event-log
        set logid 0100037904
        unset description
        append fields "cpu=high"
    next
end
config system automation-action
    edit "Backup Config"
        set action-type cli-script
        set script "execute backup config flash backup.conf"
    next
end
config system automation-stitch
    edit "backup-config"
        set trigger "High CPU"
        config actions
            edit 1
                set action "Backup Config"
                set required enable
            next
        end
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


def test_automation_hierarchy_and_operations_survive_source_tree_and_excel() -> None:
    result, _, rows = _source_sheet(AUTOMATION_CONFIG)
    items = {item.source_path: item for item in result.inventory_items}

    trigger = items["system automation-trigger"]
    assert trigger.name == "High CPU"
    assert "structured-operational-config" in trigger.notes
    assert [(command.operation, command.key) for command in trigger.commands] == [
        ("set", "event-type"),
        ("set", "logid"),
        ("unset", "description"),
        ("append", "fields"),
    ]

    stitch = items["system automation-stitch"]
    assert stitch.name == "backup-config"
    assert stitch.children[0].name == "actions"
    assert stitch.children[0].children[0].name == "1"
    nested_commands = stitch.children[0].children[0].commands
    assert [(command.key, command.values) for command in nested_commands] == [
        ("action", ["Backup Config"]),
        ("required", ["enable"]),
    ]

    trigger_rows = [
        row for row in rows
        if row["Source Path"] == "system automation-trigger"
    ]
    assert {row["Object"] for row in trigger_rows} == {"High CPU"}
    assert {row["Operation"] for row in trigger_rows} == {"set", "unset", "append"}

    nested_rows = [
        row for row in rows
        if row["Source Path"] == "system automation-stitch"
        and row["Parent / Subsection"] == "actions / 1"
    ]
    assert {row["Setting"] for row in nested_rows} == {"action", "required"}
    assert {row["Object"] for row in nested_rows} == {"backup-config"}
