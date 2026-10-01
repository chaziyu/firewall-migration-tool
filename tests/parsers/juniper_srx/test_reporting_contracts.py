from copy import deepcopy
from io import BytesIO
from pathlib import Path

from openpyxl import load_workbook

from fwmigrate.extraction.models import ExtractionStatus
from fwmigrate.vendors.juniper_srx.source_accounting import _account
from fwmigrate.vendors.juniper_srx.source_report import extract_juniper_source
from fwmigrate.vendors.juniper_srx.tokenizer import JunosCommand, JunosOperation
from fwmigrate.vendors.juniper_srx.validation import validate_juniper_config
from fwmigrate.vendors.juniper_srx.web_report import build_juniper_preview
from fwmigrate.vendors.juniper_srx.export.excel import export_juniper_excel


def test_source_accounting_preserves_source_only_and_does_not_call_commands_objects():
    commands = [
        JunosCommand(operation=JunosOperation.SET, tokens=["set", "security", "native"],
                     raw_sanitized="set security native", line_number=1,
                     extraction_status=ExtractionStatus.SOURCE_ONLY),
    ]
    sections, inventory, _ = _account(commands)
    assert sections[0].status == ExtractionStatus.SOURCE_ONLY
    assert sections[0].object_count_source is None
    assert sections[0].source_commands == ["set security native"]
    assert len(inventory[0].commands) == 1


def test_structured_validation_preview_and_excel_preserve_boundaries():
    result = extract_juniper_source("""set security ike gateway GW ike-policy MISSING
set security ipsec vpn VPN ike gateway GW
""")
    source_before = deepcopy(result.config.model_dump(mode="python"))
    derived_before = deepcopy(result.derived)
    issue = next(issue for issue in result.validation.issues if issue.reference == "MISSING")
    assert issue.code == "UNRESOLVED_REFERENCE"
    assert issue.source_path == "security ike gateway"
    assert issue.field == "ike-policy"
    assert issue.expected_type == "ike-policy"
    validate_juniper_config(result.config, result.derived)

    preview = build_juniper_preview(result)
    assert "extraction_coverage" in preview
    assert "review_required" in preview
    assert preview["validation_summary"]["errors"] >= 1
    assert preview["summary"]["scopes"] == ["root"]
    assert {"interfaces", "addresses", "address_groups", "services", "service_groups", "schedules",
            "policies", "nat", "routes", "vpn_tunnels", "vpn_phase2", "validation",
            "unresolved_references"} <= set(preview["sections"])
    assert preview["sections"]["unresolved_references"][0]["reference"] == "MISSING"

    output = BytesIO()
    export_juniper_excel(result, output)
    output.seek(0)
    workbook = load_workbook(output, read_only=True)
    assert {"Review Required", "Extraction Coverage", "Unresolved References", "Additional Settings"} <= set(workbook.sheetnames)
    references = workbook["Unresolved References"]
    assert any(row[5].value == "MISSING" for row in references.iter_rows(min_row=2))
    assert result.config.model_dump(mode="python") == source_before
    assert result.derived == derived_before


def test_report_projection_keeps_logical_system_and_address_book_scope():
    source = (Path(__file__).parents[2] / "fixtures" / "juniper" / "logical_systems.set").read_text()
    preview = build_juniper_preview(extract_juniper_source(source))
    scope = "logical-system LS_TENANT_A"
    assert scope in preview["summary"]["scopes"]
    assert any(row["scope"] == scope and row["address_book"] == "global" for row in preview["sections"]["addresses"])
    assert any(row["scope"] == scope and row["name"] == "LS_P1" for row in preview["sections"]["policies"])
    assert all("provenance" in row for row in preview["sections"]["policies"])



def test_mixed_section_coverage_is_partial_not_unsupported():
    commands = [
        JunosCommand(
            operation=JunosOperation.SET,
            tokens=["set", "security", "policies", "known"],
            raw_sanitized="set security policies known",
            line_number=1,
            consumed=True,
            extraction_status=ExtractionStatus.EXTRACTED,
        ),
        JunosCommand(
            operation=JunosOperation.SET,
            tokens=["set", "security", "policies", "unknown"],
            raw_sanitized="set security policies unknown",
            line_number=2,
            extraction_status=ExtractionStatus.UNSUPPORTED,
        ),
    ]
    sections, inventory, unsupported = _account(commands)
    assert sections[0].status == ExtractionStatus.PARTIAL
    assert inventory[0].status == ExtractionStatus.PARTIAL
    assert len(unsupported) == 1


def test_excel_exports_native_junos_detail_sheets_and_command_inventory():
    result = extract_juniper_source(
        """set security address-book global address A 192.0.2.1/32
set security address-book global address-set G address A
set applications application APP protocol tcp
set applications application APP destination-port 443
set applications application-set APPS application APP
set schedulers scheduler WORK daily start-time 09:00 stop-time 17:00
set security policies from-zone trust to-zone untrust policy P match source-address A
set security policies from-zone trust to-zone untrust policy P match destination-address any
set security policies from-zone trust to-zone untrust policy P match application APP
set security policies from-zone trust to-zone untrust policy P then permit
set security nat source pool SNAT address 198.51.100.10/32
set security nat source rule-set RS from zone trust
set security nat source rule-set RS to zone untrust
set security nat source rule-set RS rule R match source-address 192.0.2.0/24
set security nat source rule-set RS rule R then source-nat pool SNAT
set routing-options static route 203.0.113.0/24 qualified-next-hop 192.0.2.254 preference 7
set security ike proposal IKE encryption-algorithm aes-256-cbc
set security ike policy IKP proposals IKE
set security ike gateway GW ike-policy IKP
set security ipsec proposal IPSEC encryption-algorithm aes-256-gcm
set security ipsec policy IPP proposals IPSEC
set security ipsec vpn VPN bind-interface st0.0
set security ipsec vpn VPN ike gateway GW
set security ipsec vpn VPN ike ipsec-policy IPP
set security ipsec vpn VPN traffic-selector TS local-ip 10.0.0.0/24
set security ipsec vpn VPN traffic-selector TS remote-ip 10.1.0.0/24
"""
    )
    output = BytesIO()
    export_juniper_excel(result, output)
    output.seek(0)
    workbook = load_workbook(output, read_only=True)

    expected = {
        "Addresses", "Address Sets", "Application Sets", "Schedulers", "Policy Details",
        "NAT Pools", "NAT Rules", "Static Routes", "IKE Proposals", "IKE Policies",
        "IKE Gateways", "IPsec Proposals", "IPsec Policies", "IPsec VPNs", "Traffic Selectors",
    }
    assert expected <= set(workbook.sheetnames)
    assert workbook["Addresses"].max_row >= 2
    assert workbook["Static Routes"].max_row >= 2
    assert workbook["IPsec VPNs"].max_row >= 2

    inventory = workbook["Source Inventory"]
    headers = [cell.value for cell in next(inventory.iter_rows(min_row=1, max_row=1))]
    assert headers == [
        "Domain", "Source Path", "Context", "Line", "Operation", "Key",
        "Values", "Status", "Handler", "Review Required",
    ]
    assert inventory.max_row > len(result.inventory_items)


def test_preview_uses_junos_zone_and_nat_context_names_without_inferred_active_state():
    result = extract_juniper_source(
        """set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24
set security policies from-zone trust to-zone untrust policy P then permit
set security nat source rule-set RS from interface ge-0/0/0.0
set security nat source rule-set RS to zone untrust
set security nat source rule-set RS rule R then source-nat interface
set routing-options static route 203.0.113.0/24 next-hop 192.0.2.254
"""
    )
    preview = build_juniper_preview(result)
    policy = preview["sections"]["policies"][0]
    nat = preview["sections"]["nat"][0]
    interface = preview["sections"]["interfaces"][0]
    route = preview["sections"]["routes"][0]

    assert policy["source_zones"] == ["trust"]
    assert policy["destination_zones"] == ["untrust"]
    assert "source_interfaces" not in policy
    assert nat["from_interfaces"] == ["ge-0/0/0.0"]
    assert nat["to_zones"] == ["untrust"]
    assert "egress_interfaces" not in nat
    assert interface["status"] is None
    assert route["status"] is None



def test_unresolved_reference_counts_roll_up_to_native_section():
    result = extract_juniper_source("set security ike gateway GW ike-policy MISSING")

    section = next(item for item in result.source_sections if item.path == "security ike")
    assert section.unresolved_dependencies == 1


def test_excel_neutralizes_formula_cells_and_reports_partial_collection():
    result = extract_juniper_source(
        'set security address-book global address "=1+1" 192.0.2.1/32'
    )
    output = BytesIO()
    export_juniper_excel(
        result,
        output,
        collection_status="PARTIAL",
        collection_parts=({"name": "configuration", "status": "PERMISSION_DENIED", "complete": False},),
        collection_warnings=("Configuration incomplete",),
    )
    output.seek(0)
    workbook = load_workbook(output, read_only=True, data_only=False)

    address_sheet = workbook["Addresses"]
    headers = [cell.value for cell in next(address_sheet.iter_rows(min_row=1, max_row=1))]
    name_index = headers.index("Name")
    values = next(address_sheet.iter_rows(min_row=2, max_row=2))
    assert values[name_index].value == "'=1+1"

    summary = {
        row[0].value: row[1].value
        for row in workbook["Summary"].iter_rows(min_row=2)
        if row[0].value is not None and len(row) > 1
    }
    assert summary["Collection Status"] == "PARTIAL"
    assert summary["Incomplete Collection Parts"] == 1
    assert "Configuration incomplete" in summary["Collection Warnings"]



def test_deactivation_is_reported_as_derived_effective_state():
    result = extract_juniper_source(
        """set security address-book global address A 192.0.2.1/32
set schedulers scheduler SCH daily 12:00-13:00
set security policies from-zone trust to-zone untrust policy P then permit
set security nat source rule-set RS rule R then source-nat interface
set routing-options static route 203.0.113.0/24 next-hop 192.0.2.1
set security ipsec vpn VPN bind-interface st0.0
deactivate security address-book global address A
deactivate schedulers scheduler SCH
deactivate security policies from-zone trust to-zone untrust policy P
deactivate security nat source rule-set RS rule R
deactivate routing-options static route 203.0.113.0/24
deactivate security ipsec vpn VPN
"""
    )

    preview = build_juniper_preview(result)
    for section in ("addresses", "schedules", "policies", "nat", "routes", "vpn_tunnels"):
        assert preview["sections"][section][0]["effective_state"] == "INACTIVE"

    output = BytesIO()
    export_juniper_excel(result, output)
    output.seek(0)
    workbook = load_workbook(output, read_only=True)
    for sheet_name in ("Addresses", "Schedulers", "Policy Details", "NAT Rules", "Static Routes", "IPsec VPNs"):
        rows = list(workbook[sheet_name].values)
        state_index = rows[0].index("Effective State")
        assert rows[1][state_index] == "INACTIVE"
