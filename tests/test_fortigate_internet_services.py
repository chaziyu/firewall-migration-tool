from io import BytesIO

from openpyxl import load_workbook

from fwmigrate.parsers.fortigate.parser import (
    parse_fortigate_config,
)
from fwmigrate.parsers.fortigate.transformer import (
    FGToIRTransformer,
)
from fwmigrate.report.excel_exporter import (
    IRExcelExporter,
)


FORTIGATE_CONFIG = """
config system global
    set hostname "FG-TEST"
end

config firewall internet-service-name
    edit "Google-Other"
        set internet-service-id 65536
    next
    edit "Microsoft-Office365"
        set internet-service-id 327782
    next
end
"""


def test_fortigate_internet_service_source_id_is_parsed():
    fg = parse_fortigate_config(
        FORTIGATE_CONFIG
    )

    assert len(fg.internet_services) == 2

    google = fg.internet_services[0]

    assert google.name == "Google-Other"
    assert google.id == 65536

    microsoft = fg.internet_services[1]

    assert (
        microsoft.name
        == "Microsoft-Office365"
    )
    assert microsoft.id == 327782


def test_fortigate_internet_service_source_id_reaches_ir():
    fg = parse_fortigate_config(
        FORTIGATE_CONFIG
    )

    ir = FGToIRTransformer(
        fg
    ).transform()

    assert len(ir.internet_services) == 2

    google = ir.internet_services[0]

    assert google.name == "Google-Other"
    assert google.source_id == 65536

    microsoft = ir.internet_services[1]

    assert (
        microsoft.name
        == "Microsoft-Office365"
    )
    assert microsoft.source_id == 327782


def test_fortigate_internet_service_source_id_is_exported_to_excel():
    fg = parse_fortigate_config(
        FORTIGATE_CONFIG
    )

    ir = FGToIRTransformer(
        fg
    ).transform()

    workbook_bytes = IRExcelExporter(
        ir
    ).generate()

    workbook = load_workbook(
        BytesIO(workbook_bytes)
    )

    assert "Internet Services" in workbook.sheetnames

    sheet = workbook["Internet Services"]

    headers = [
        cell.value
        for cell in sheet[3]
    ]

    assert "Name" in headers
    assert "Source Vendor" in headers
    assert "Source ID" in headers
    assert "Description" in headers

    header_index = {
        name: index + 1
        for index, name in enumerate(
            headers
        )
    }

    rows = {}

    for row_number in range(
        4,
        sheet.max_row + 1,
    ):
        name = sheet.cell(
            row=row_number,
            column=header_index["Name"],
        ).value

        if name:
            rows[name] = {
                "vendor": sheet.cell(
                    row=row_number,
                    column=header_index[
                        "Source Vendor"
                    ],
                ).value,
                "source_id": sheet.cell(
                    row=row_number,
                    column=header_index[
                        "Source ID"
                    ],
                ).value,
            }

    assert "Google-Other" in rows

    assert (
        rows["Google-Other"]["vendor"]
        == "fortigate"
    )

    assert (
        rows["Google-Other"]["source_id"]
        == 65536
    )

    assert "Microsoft-Office365" in rows

    assert (
        rows["Microsoft-Office365"][
            "source_id"
        ]
        == 327782
    )
