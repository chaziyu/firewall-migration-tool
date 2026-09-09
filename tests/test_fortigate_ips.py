from io import BytesIO

import pytest

from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


IPS_CONFIG = """
config ips sensor
    edit "Test_IPS"
        set comment "Test IPS sensor"
        set block-malicious-url enable
        set scan-botnet-connections block
        set unknown-sensor-setting preserve-me
        config entries
            edit 1
                set rule 43814 43815 malformed-id
                set status enable
                set action block
                set rate-count 10
                set rate-duration 60
                set quarantine attacker
                set quarantine-expiry 5m
                set unknown-entry-setting retained
            next
            edit 2
                set severity critical high
                set protocol TCP UDP
                set location server
                set rate-count unusual
            next
        end
    next
    edit "Second_IPS"
        config entries
            edit 7
                set rule 50001
            next
        end
    next
end
"""


def test_fortigate_ips_parser_preserves_nested_source_semantics():
    config = parse_fortigate_config(IPS_CONFIG)

    assert len(config.ips_sensors) == 2
    sensor = config.ips_sensors[0]
    assert sensor.name == "Test_IPS"
    assert sensor.comment == "Test IPS sensor"
    assert sensor.block_malicious_url == "enable"
    assert sensor.scan_botnet_connections == "block"
    assert sensor.extra_settings == {"unknown_sensor_setting": "preserve-me"}
    assert len(sensor.entries) == 2

    rule_entry, filter_entry = sensor.entries
    assert rule_entry.id == 1
    assert rule_entry.rules == [43814, 43815]
    assert rule_entry.status == "enable"
    assert rule_entry.action == "block"
    assert rule_entry.rate_count == 10
    assert rule_entry.rate_duration == 60
    assert rule_entry.quarantine == "attacker"
    assert rule_entry.quarantine_expiry == "5m"
    assert rule_entry.extra_settings == {
        "unparsed_rule_values": ["malformed-id"],
        "unknown_entry_setting": "retained",
    }

    assert filter_entry.id == 2
    assert filter_entry.severity == ["critical", "high"]
    assert filter_entry.protocol == ["TCP", "UDP"]
    assert filter_entry.location == "server"
    assert filter_entry.rate_count is None
    assert filter_entry.extra_settings["unparsed_rate_count"] == "unusual"

    assert [entry.id for entry in config.ips_sensors[1].entries] == [7]
    assert config.ips_sensors[1].entries[0].rules == [50001]


def test_fortigate_ips_transformer_keeps_signature_ids_source_only():
    ir = FGToIRTransformer(parse_fortigate_config(IPS_CONFIG)).transform()

    sensor = ir.ips_sensors[0]
    assert sensor.migration_status == "EXTRACT_ONLY"
    assert sensor.requires_manual_review is True
    assert sensor.block_malicious_url is True
    assert sensor.scan_botnet_connections == "block"
    assert sensor.source_attributes == {"unknown_sensor_setting": "preserve-me"}

    rule_entry, filter_entry = sensor.entries
    assert rule_entry.source_id == 1
    assert rule_entry.source_signature_ids == [43814, 43815]
    assert rule_entry.enabled is True
    assert rule_entry.action == "block"
    assert rule_entry.rate_count == 10
    assert rule_entry.rate_duration == 60
    assert rule_entry.quarantine == "attacker"
    assert rule_entry.quarantine_expiry == "5m"
    assert rule_entry.source_attributes["unparsed_rule_values"] == ["malformed-id"]

    assert filter_entry.severities == ["critical", "high"]
    assert filter_entry.protocols == ["TCP", "UDP"]
    assert filter_entry.location == "server"
    assert filter_entry.source_attributes["unparsed_rate_count"] == "unusual"


@pytest.mark.parametrize(
    "body",
    (
        'edit "Empty"\n        config entries\n        end\n    next',
        'edit "NoEntries"\n        set comment "No nested entries"\n    next',
    ),
)
def test_fortigate_ips_sensor_does_not_require_entries(body):
    config = parse_fortigate_config(f"config ips sensor\n    {body}\nend")

    assert len(config.ips_sensors) == 1
    assert config.ips_sensors[0].entries == []
    assert FGToIRTransformer(config).transform().ips_sensors[0].entries == []


def test_fortigate_ips_excel_has_parent_and_one_row_per_entry():
    openpyxl = pytest.importorskip("openpyxl")
    ir = FGToIRTransformer(parse_fortigate_config(IPS_CONFIG)).transform()
    workbook = openpyxl.load_workbook(
        BytesIO(IRExcelExporter(ir).generate())
    )

    sensors = workbook["IPS Sensors"]
    sensor_headers = {cell.value: cell.column for cell in sensors[3]}
    assert sensors.cell(4, sensor_headers["Name"]).value == "Test_IPS"
    assert sensors.cell(4, sensor_headers["Entry Count"]).value == 2
    assert sensors.cell(4, sensor_headers["Extraction Status"]).value == "EXTRACT_ONLY"
    assert sensors.cell(4, sensor_headers["Manual Review"]).value == "Yes"

    entries = workbook["IPS Sensor Entries"]
    entry_headers = {cell.value: cell.column for cell in entries[3]}
    assert entries.max_row == 6
    assert entries.cell(4, entry_headers["Sensor"]).value == "Test_IPS"
    assert entries.cell(4, entry_headers["Entry ID"]).value == 1
    assert entries.cell(4, entry_headers["Signature IDs"]).value == "43814, 43815"
    assert entries.cell(4, entry_headers["Action"]).value == "block"
    assert entries.cell(5, entry_headers["Severities"]).value == "critical, high"
    assert entries.cell(5, entry_headers["Protocols"]).value == "TCP, UDP"
    assert entries.cell(5, entry_headers["Location"]).value == "server"

    coverage = {
        workbook["Extraction Coverage"].cell(row, 1).value:
            workbook["Extraction Coverage"].cell(row, 3).value
        for row in range(4, workbook["Extraction Coverage"].max_row + 1)
    }
    assert coverage["IPS Sensors"] == 2
    assert coverage["IPS Sensor Entries"] == 3
