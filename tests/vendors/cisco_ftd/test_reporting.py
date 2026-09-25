import json
from io import BytesIO
from pathlib import Path

from openpyxl import load_workbook

from fwmigrate.vendors.cisco_ftd.source_report import CiscoFTDSourceReporter, extract_cisco_ftd_source
from fwmigrate.vendors.cisco_ftd.web_report import build_ftd_preview


FIXTURE = Path(__file__).parents[2] / "fixtures" / "cisco_ftd" / "fmc_selected_domains.json"


def test_native_collections_are_visible_in_preview_and_excel():
    result = CiscoFTDSourceReporter().analyze_source(FIXTURE.read_text(encoding="utf-8"))
    preview = build_ftd_preview(result)
    assert preview["summary"]["s2s_vpn_topologies"] == 1
    assert preview["summary"]["objects"]["policies"] > 0
    assert preview["source_plane"] == "fmc-rest-bundle"
    assert {"interfaces", "addresses", "address_groups", "services", "service_groups", "schedules",
            "policies", "nat", "routes", "vpn_tunnels", "vpn_phase2", "validation",
            "unresolved_references"} <= set(preview["sections"])
    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)
    workbook = load_workbook(output, read_only=True)
    assert "Native Sources" in workbook.sheetnames
    assert workbook["Native Sources"].max_row > 1


def test_report_preserves_ftd_source_plane_and_partial_coverage():
    fdm = CiscoFTDSourceReporter().build_preview(extract_cisco_ftd_source(
        (FIXTURE.parent / "fdm_object_pipeline_conformance.json").read_text(encoding="utf-8")))
    cli = CiscoFTDSourceReporter().build_preview(extract_cisco_ftd_source(
        "interface outside\n ip address 203.0.113.1 255.255.255.0\n"))
    partial = CiscoFTDSourceReporter().build_preview(extract_cisco_ftd_source(
        '{"format":"cisco-fmc-rest-export-v1","source":"fmc-rest-api","access_policies":[{"id":"p1","name":"Policy A","rules":[{"id":"r1","name":"Rule"}]},{"id":"p2","name":"Policy B"}]}'))
    assert fdm["source_plane"] == "fdm-rest-bundle"
    assert cli["source_plane"] == "ftd-text-evidence" and cli["sections"]["policies"] == []
    assert partial["source_plane_completeness"]["acp"] == "partial"
    assert partial["sections"]["policies"][0]["source_plane"] == "fmc-rest-bundle"


def test_excel_formula_like_source_text_is_literal():
    result = extract_cisco_ftd_source(json.dumps({"source": "fmc-rest-api", "objects": {
        "networkaddresses": [{"id": "net-1", "name": "=1+1", "type": "Host", "value": "192.0.2.1"}]}}))
    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)
    workbook = load_workbook(output, read_only=True)
    sheet = workbook["Managed Objects"]
    row = next(sheet.iter_rows(min_row=2, max_row=2))
    assert row[0].value == "'=1+1"
    assert row[0].data_type != "f"
