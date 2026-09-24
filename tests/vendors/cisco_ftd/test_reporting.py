from io import BytesIO
from pathlib import Path

from openpyxl import load_workbook

from fwmigrate.vendors.cisco_ftd.source_report import CiscoFTDSourceReporter
from fwmigrate.vendors.cisco_ftd.web_report import build_ftd_preview


FIXTURE = Path(__file__).parents[2] / "fixtures" / "cisco_ftd" / "fmc_selected_domains.json"


def test_native_collections_are_visible_in_preview_and_excel():
    result = CiscoFTDSourceReporter().analyze_source(FIXTURE.read_text(encoding="utf-8"))
    preview = build_ftd_preview(result)
    assert preview["summary"]["s2s_vpn_topologies"] == 1
    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)
    workbook = load_workbook(output, read_only=True)
    assert "Native Sources" in workbook.sheetnames
    assert workbook["Native Sources"].max_row > 1
