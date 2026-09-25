import io
from copy import deepcopy
from pathlib import Path
from openpyxl import load_workbook
from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source
from fwmigrate.vendors.checkpoint.export.excel import export_checkpoint_excel
from fwmigrate.vendors.checkpoint.export.excel_schema import SHEET_ORDER
from fwmigrate.vendors.checkpoint.web_report import build_checkpoint_preview

def test_excel_report_uses_typed_source_and_derived_sheets():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "multidomain_full.json").read_text()
    result = extract_checkpoint_source(source)
    before = (result.config.model_dump(), deepcopy(result.derived), deepcopy(result.validation))
    output = io.BytesIO(); export_checkpoint_excel(result, output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True)
    assert {"Hosts", "Networks", "Access Sections", "Access Rules", "NAT Rules", "Gaia Interfaces",
            "NAT Migration Views", "Policy Traversal", "Interface Views", "VPN Views",
            "Check Point Source Inventory", "Review Required"} <= set(workbook.sheetnames)
    assert "Network Objects" not in workbook.sheetnames and "Gaia" not in workbook.sheetnames
    assert "IP Pools" not in SHEET_ORDER and "VIPs" not in SHEET_ORDER and "SD-WAN" not in SHEET_ORDER
    assert (result.config.model_dump(), result.derived, result.validation) == before

def test_excel_formula_like_source_text_is_safe():
    result = extract_checkpoint_source('{"objects":[{"type":"host","name":"=1+1"}]}')
    output = io.BytesIO(); export_checkpoint_excel(result, output)
    workbook = load_workbook(io.BytesIO(output.getvalue()), read_only=True)
    sheet = workbook["Hosts"]
    headers = [cell.value for cell in next(sheet.iter_rows())]
    name_col = headers.index("name")
    assert list(sheet.iter_rows(min_row=2, values_only=True))[0][name_col] == "'=1+1"

def test_web_report_has_typed_source_derived_validation_and_traceability():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "multidomain_full.json").read_text()
    result = extract_checkpoint_source(source)
    before = (result.config.model_dump(), deepcopy(result.derived), deepcopy(result.validation))
    preview = build_checkpoint_preview(result)
    assert preview["vendor"] == "checkpoint"
    assert "access_rules" in preview["source"]
    assert {"nat", "policy_traversal", "interfaces", "vpn"} <= set(preview["derived"])
    assert {"scope", "collection", "source_inventory", "unsupported", "validation"} <= set(preview)
    assert "No direct R81.00 equivalent" == preview["summary"]["capabilities"]["SD-WAN"]
    assert preview["summary"]["scopes"]
    assert {"interfaces", "addresses", "address_groups", "services", "service_groups", "schedules",
            "policies", "nat", "routes", "vpn_tunnels", "vpn_phase2", "validation",
            "unresolved_references"} <= set(preview["sections"])
    assert all("package" in row and "layer" in row and "section" in row
               for row in preview["sections"]["policies"])
    if preview["source"]["nat_rules"]:
        assert "original_source" in preview["source"]["nat_rules"][0]
    assert (result.config.model_dump(), result.derived, result.validation) == before

def test_nat_transform_is_exposed_in_preview_and_excel():
    result = extract_checkpoint_source(
        '{"responses":[{"command":"show-hosts","data":{"objects":[{"type":"host","uid":"h","name":"Web","nat-settings":{"auto-rule":true}}]}}]}'
    )

    assert result.config.hosts[0].nat_settings == {"auto-rule": True}
    preview = build_checkpoint_preview(result)
    assert preview["derived"]["nat"][0]["source_kind"] == "automatic_object_settings"

    output = io.BytesIO()
    export_checkpoint_excel(result, output)
    output.seek(0)
    sheet = load_workbook(output, read_only=True)["NAT Migration Views"]
    headers = next(sheet.iter_rows(values_only=True))
    row = next(sheet.iter_rows(min_row=2, values_only=True))
    assert row[headers.index("Source Kind")] == "automatic_object_settings"
    assert row[headers.index("Resolved Translation")] in (None, "")
