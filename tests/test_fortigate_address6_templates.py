import io
import json

from openpyxl import load_workbook

from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import parse_fortigate_config
from fwmigrate.report.excel_exporter import IRExcelExporter


ADDRESS6_TEMPLATE_CONFIG = '''
config firewall address6-template
    edit "site-template"
        set ip6 2001:db8:100::/56
        set subnet-segment-count 2
        set fabric-object enable
        config subnet-segment
            edit "site"
                set bits 8
                set exclusive enable
                set name "site-id"
                config values
                    edit "branch-a"
                        set value "10"
                    next
                    edit "branch-b"
                        set value "20"
                    next
                end
            next
            edit "host"
                set bits 64
                set exclusive disable
                set name "host-id"
            next
        end
    next
end
config firewall address6
    edit "site-host"
        set type template
        set host 2001:db8:100::10
        set host-type specific
        set template "site-template"
    next
    edit "missing-template-host"
        set type template
        set host-type any
        set template "missing-template"
    next
end
'''


def test_address6_template_uses_fortios_746_typed_schema():
    parsed = parse_fortigate_config(ADDRESS6_TEMPLATE_CONFIG)

    assert len(parsed.address6_templates) == 1
    template = parsed.address6_templates[0]
    assert template.name == "site-template"
    assert template.ip6 == "2001:db8:100::/56"
    assert template.subnet_segment_count == 2
    assert template.fabric_object == "enable"
    assert len(template.subnet_segments) == 2

    site = template.subnet_segments[0]
    assert site.source_id == "site"
    assert site.bits == 8
    assert site.exclusive == "enable"
    assert site.name == "site-id"
    assert [(item.source_id, item.value) for item in site.values] == [
        ("branch-a", "10"),
        ("branch-b", "20"),
    ]

    host = template.subnet_segments[1]
    assert host.source_id == "host"
    assert host.bits == 64
    assert host.exclusive == "disable"
    assert host.name == "host-id"
    assert host.values == []

    source_addresses = {item.name: item for item in parsed.addresses}
    assert source_addresses["site-host"].type == "template"
    assert source_addresses["site-host"].host_type == "specific"
    assert source_addresses["site-host"].template == "site-template"
    assert source_addresses["site-host"].ip6 is None
    assert source_addresses["missing-template-host"].host_type == "any"


def test_address6_template_reference_is_context_scoped_and_canonical():
    result = extract_fortigate_config(ADDRESS6_TEMPLATE_CONFIG)

    resolved = [
        item
        for item in result.dependencies
        if item.source_path == "firewall address6"
        and item.source_field == "template"
        and item.reference == "site-template"
    ]
    assert resolved
    assert resolved[0].result == "RESOLVED"
    assert resolved[0].target_path == "firewall address6-template"

    unresolved = [
        item
        for item in result.dependencies
        if item.source_path == "firewall address6"
        and item.source_field == "template"
        and item.reference == "missing-template"
    ]
    assert unresolved
    assert unresolved[0].result == "UNRESOLVED"

    assert len(result.canonical_ir.address6_templates) == 1
    canonical = result.canonical_ir.address6_templates[0]
    assert canonical.name == "site-template"
    assert canonical.ip6 == "2001:db8:100::/56"
    assert canonical.subnet_segment_count == 2
    assert canonical.source_fabric_object == "enable"
    assert [segment.source_id for segment in canonical.subnet_segments] == [
        "site",
        "host",
    ]
    assert [
        (item.source_id, item.value)
        for item in canonical.subnet_segments[0].values
    ] == [("branch-a", "10"), ("branch-b", "20")]
    assert canonical.requires_manual_review is True

    addresses = {item.name: item for item in result.canonical_ir.addresses}
    template_address = addresses["site-host"]
    assert template_address.source_attributes["template"] == "site-template"
    assert template_address.source_attributes["host"] == "2001:db8:100::10"
    assert template_address.source_attributes["host_type"] == "specific"
    assert template_address.source_attributes["template_reference_resolved"] is True
    assert template_address.source_template == "site-template"
    assert template_address.source_template_reference_resolved is True
    assert template_address.subnet is None
    assert template_address.requires_manual_review is True

    missing = addresses["missing-template-host"]
    assert missing.source_template == "missing-template"
    assert missing.source_template_reference_resolved is False
    assert result.generation_safe is False


def test_address6_template_nested_source_data_reaches_excel():
    result = extract_fortigate_config(ADDRESS6_TEMPLATE_CONFIG)
    workbook = load_workbook(
        io.BytesIO(IRExcelExporter(result.canonical_ir, result).generate())
    )

    source_sheet = workbook["FortiGate Source Configuration"]
    source_headers = {cell.value: cell.column for cell in source_sheet[3]}
    source_rows = [
        row
        for row in range(4, source_sheet.max_row + 1)
        if source_sheet.cell(
            row,
            source_headers["Source Path"],
        ).value == "firewall address6-template"
        and source_sheet.cell(
            row,
            source_headers["Object"],
        ).value == "site-template"
    ]
    settings = {
        source_sheet.cell(
            row,
            source_headers["Setting"],
        ).value: source_sheet.cell(
            row,
            source_headers["Value"],
        ).value
        for row in source_rows
    }
    assert settings["ip6"] == "2001:db8:100::/56"
    assert str(settings["subnet-segment-count"]) == "2"
    assert settings["fabric-object"] == "enable"
    assert any(
        source_sheet.cell(
            row,
            source_headers["Setting"],
        ).value == "bits"
        and "subnet-segment"
        in (
            source_sheet.cell(
                row,
                source_headers["Parent / Subsection"],
            ).value
            or ""
        )
        for row in source_rows
    )

    template_sheet = workbook["IPv6 Address Templates"]
    template_headers = {
        cell.value: cell.column
        for cell in template_sheet[3]
    }
    assert template_sheet.cell(
        4,
        template_headers["Name"],
    ).value == "site-template"
    assert template_sheet.cell(
        4,
        template_headers["IPv6 Prefix"],
    ).value == "2001:db8:100::/56"
    assert template_sheet.cell(
        4,
        template_headers["Declared Segment Count"],
    ).value == 2
    assert template_sheet.cell(
        4,
        template_headers["Parsed Segment Count"],
    ).value == 2
    segments = json.loads(
        template_sheet.cell(
            4,
            template_headers["Subnet Segments"],
        ).value
    )
    assert [segment["source_id"] for segment in segments] == ["site", "host"]
    assert [
        (item["source_id"], item["value"])
        for item in segments[0]["values"]
    ] == [("branch-a", "10"), ("branch-b", "20")]

    address_sheet = workbook["Addresses"]
    address_headers = {
        cell.value: cell.column
        for cell in address_sheet[3]
    }
    address_rows = {
        address_sheet.cell(
            row,
            address_headers["Name"],
        ).value: row
        for row in range(4, address_sheet.max_row + 1)
    }
    site_row = address_rows["site-host"]
    missing_row = address_rows["missing-template-host"]
    assert address_sheet.cell(
        site_row,
        address_headers["IPv6 Template Reference"],
    ).value == "site-template"
    assert address_sheet.cell(
        site_row,
        address_headers["Template Reference Resolved"],
    ).value == "TRUE"
    assert address_sheet.cell(
        missing_row,
        address_headers["Template Reference Resolved"],
    ).value == "FALSE"
