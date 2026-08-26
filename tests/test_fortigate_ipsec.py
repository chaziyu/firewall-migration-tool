import io

from openpyxl import load_workbook

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.parsers.fortigate.transformer import FGToIRTransformer
from fwmigrate.report.excel_exporter import IRExcelExporter


IPSEC_CONFIG = """
config vpn ipsec phase1-interface
    edit "phase1-a"
        set interface "port1"
        set remote-gw 203.0.113.10
        set proposal aes256-sha256
    next
    edit "actual-phase1"
        set interface "port2"
        set remote-gw 203.0.113.20
    next
end

config vpn ipsec phase2-interface
    edit "phase2-a"
        set phase1name "phase1-a"
        set proposal aes128-sha1 aes256-sha256
        set auto-negotiate enable
        set src-addr-type name
        set dst-addr-type name
        set src-name "local-net"
        set dst-name "remote-net"
        set src-subnet 10.0.0.0 255.255.255.0
        set dst-subnet 10.1.0.0 255.255.255.0
        set comments "Phase2 test"
        set custom-setting test-value
    next
    edit "phase2-different-name"
        set phase1name "actual-phase1"
        set proposal aes256gcm
        set dhgrp 20
        set keepalive enable
    next
    edit "orphan-phase2"
        set phase1name "missing-phase1"
        set proposal aes256-sha256
    next
end
"""


def _by_name(items):
    return {item.name: item for item in items}


def test_fortigate_phase2_parser_preserves_typed_and_unknown_settings():
    config = parse_fortigate_config(IPSEC_CONFIG)
    phase2 = _by_name(config.phase2_interfaces)

    assert len(phase2) == 3
    first = phase2["phase2-a"]
    assert first.phase1name == "phase1-a"
    assert first.proposal == ["aes128-sha1", "aes256-sha256"]
    assert first.auto_negotiate == "enable"
    assert first.src_addr_type == "name"
    assert first.dst_addr_type == "name"
    assert first.src_name == ["local-net"]
    assert first.dst_name == ["remote-net"]
    assert first.src_subnet == "10.0.0.0 255.255.255.0"
    assert first.dst_subnet == "10.1.0.0 255.255.255.0"
    assert first.comments == "Phase2 test"
    assert first.extra_settings == {"custom_setting": "test-value"}

    second = phase2["phase2-different-name"]
    assert second.phase1name == "actual-phase1"
    assert second.dhgrp == [20]
    assert second.keepalive == "enable"


def test_fortigate_phase2_transform_preserves_semantics_and_references():
    ir = FGToIRTransformer(parse_fortigate_config(IPSEC_CONFIG)).transform()
    phase2 = _by_name(ir.vpn_phase2)

    assert len(phase2) == 3
    first = phase2["phase2-a"]
    assert first.phase1_name == "phase1-a"
    assert first.proposals == ["aes128-sha1", "aes256-sha256"]
    assert first.source_address_type == "name"
    assert first.destination_address_type == "name"
    assert first.source_names == ["local-net"]
    assert first.destination_names == ["remote-net"]
    assert first.source_subnet == "10.0.0.0 255.255.255.0"
    assert first.destination_subnet == "10.1.0.0 255.255.255.0"
    assert first.auto_negotiate is True
    assert first.source_attributes == {"custom_setting": "test-value"}

    second = phase2["phase2-different-name"]
    assert second.phase1_name == "actual-phase1"
    assert second.proposals == ["aes256gcm"]
    assert second.dh_groups == [20]
    assert second.keepalive is True
    assert second.requires_manual_review is False

    orphan = phase2["orphan-phase2"]
    assert orphan.phase1_name == "missing-phase1"
    assert orphan.requires_manual_review is True
    assert any(
        entry.id == "vpn-phase2:orphan-phase2:phase1"
        and "missing-phase1" in entry.message
        for entry in ir.audit_entries
    )


def test_fortigate_phase2_coverage_reports_structured_partial_inventory():
    result = extract_fortigate_config(IPSEC_CONFIG)
    section = next(
        item
        for item in result.source_sections
        if item.path == "vpn ipsec phase2-interface"
    )

    assert section.object_count_source == 3
    assert section.object_count_parsed == 3
    assert section.object_count_normalized == 3
    assert section.status == ExtractionStatus.PARTIALLY_NORMALIZED


def test_fortigate_phase2_excel_has_dedicated_inventory_and_summary():
    result = extract_fortigate_config(IPSEC_CONFIG)
    workbook = load_workbook(
        io.BytesIO(
            IRExcelExporter(
                result.canonical_ir,
                extraction_result=result,
            ).generate()
        )
    )

    assert "VPN Tunnels" in workbook.sheetnames
    assert workbook.sheetnames.index("VPN Phase 2") == (
        workbook.sheetnames.index("VPN Tunnels") + 1
    )

    sheet = workbook["VPN Phase 2"]
    headers = {cell.value: cell.column for cell in sheet[3]}
    assert list(headers) == [
        "Name",
        "Phase 1",
        "Proposal",
        "Source Address Type",
        "Source Selector",
        "Destination Address Type",
        "Destination Selector",
        "Source Subnet",
        "Destination Subnet",
        "Auto Negotiate",
        "DH / PFS Groups",
        "Keepalive",
        "Extraction Status",
        "Manual Review",
        "Additional Settings",
        "Description",
    ]
    rows = {
        sheet.cell(row, headers["Name"]).value: row
        for row in range(4, sheet.max_row + 1)
    }

    first_row = rows["phase2-a"]
    assert sheet.cell(first_row, headers["Phase 1"]).value == "phase1-a"
    assert sheet.cell(first_row, headers["Proposal"]).value == (
        "aes128-sha1\naes256-sha256"
    )
    assert sheet.cell(first_row, headers["Source Address Type"]).value == "name"
    assert sheet.cell(first_row, headers["Source Selector"]).value == "local-net"
    assert sheet.cell(first_row, headers["Destination Address Type"]).value == "name"
    assert sheet.cell(first_row, headers["Destination Selector"]).value == "remote-net"
    assert sheet.cell(first_row, headers["Auto Negotiate"]).value == "TRUE"
    assert sheet.cell(first_row, headers["Extraction Status"]).value == (
        "PARTIALLY_NORMALIZED"
    )
    assert sheet.cell(first_row, headers["Additional Settings"]).value == (
        "custom-setting=test-value"
    )
    assert sheet.cell(first_row, headers["Description"]).value == "Phase2 test"

    second_row = rows["phase2-different-name"]
    assert sheet.cell(second_row, headers["Phase 1"]).value == "actual-phase1"
    assert sheet.cell(second_row, headers["DH / PFS Groups"]).value == "20"
    assert sheet.cell(second_row, headers["Keepalive"]).value == "TRUE"

    summary = workbook["Summary"]
    counts = {
        summary.cell(row, 1).value: summary.cell(row, 2).value
        for row in range(1, summary.max_row + 1)
    }
    assert counts["VPN Tunnels"] == 2
    assert counts["VPN Phase 2"] == 3
