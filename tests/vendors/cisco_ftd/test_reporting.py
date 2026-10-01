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
    assert "Source Inventory" in workbook.sheetnames
    assert "Collection Completeness" in workbook.sheetnames
    assert "Semantic Completeness" in workbook.sheetnames
    assert workbook["Native Sources"].max_row > 1
    assert workbook["Source Inventory"].max_row > 1
    assert result.source_sections[0].object_count_source == len(result.inventory_items)
    assert result.source_sections[0].object_count_parsed == len(result.inventory_items)
    assert result.source_sections[0].object_count_extracted == len(result.inventory_items)


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

def test_fmc_missing_name_uses_id_only_as_internal_fallback():
    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "domain": {"id": "domain-1", "name": "Global"},
        "objects": {"networkaddresses": [
            {"id": "host-without-name", "type": "Host", "value": "192.0.2.10"}
        ]},
    }))

    record = result.config.network_addresses[0]
    inventory = next(item for item in result.inventory_items if item.source_id == "host-without-name")
    assert record.name is None
    assert record.source_attributes["source_name_explicit"] is False
    assert record.source_attributes["internal_record_key"] == "id:host-without-name"
    assert inventory.name is None
    assert inventory.source_id == "host-without-name"
    assert inventory.source_record_id is not None


def test_preview_preserves_structured_fmc_scope():
    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "domain": {"id": "domain-1", "name": "Global"},
        "objects": {},
        "devices": [{"id": "device-1", "name": "FTD-A", "resources": {
            "ftd_interfaces": [{"id": "if-1", "name": "GigabitEthernet0/0"}]
        }}],
    }))

    preview = build_ftd_preview(result)
    row = preview["sections"]["interfaces"][0]
    assert row["scope_details"]["domain_id"] == "domain-1"
    assert row["scope_details"]["device_id"] == "device-1"
    assert row["scope_details"]["device_name"] == "FTD-A"


def test_fmc_missing_domain_name_is_not_inferred_as_global():
    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "domain": {"id": "domain-1"},
        "objects": {"networkaddresses": [
            {"id": "host-1", "name": "Host", "type": "Host", "value": "192.0.2.10"}
        ]},
    }))
    assert result.config.source_metadata["domain_name"] is None
    assert result.config.network_addresses[0].source_context is None
    assert result.config.network_addresses[0].domain_id == "domain-1"


def test_device_only_fmc_bundle_uses_fmc_adapter():
    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "devices": [{"id": "device-1", "name": "FTD-A", "resources": {
            "ftd_interfaces": [{"id": "if-1", "name": "GigabitEthernet0/0"}]
        }}],
    }))
    assert result.config.source_plane == "fmc-rest-bundle"
    assert result.config.source_interfaces[0].source_id == "if-1"


def test_preview_keeps_parent_policy_and_rule_identity_distinct():
    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "access_policies": [{
            "id": "acp-1", "name": "Corporate ACP",
            "rules": [{"id": "rule-1", "name": "Allow DNS", "position": 7, "action": "ALLOW"}],
        }],
        "nat_policies": [{
            "id": "nat-1", "name": "Edge NAT",
            "manual_rules_before_auto": [
                {"id": "nat-rule-1", "name": "Static NAT", "position": 3, "section": "BEFORE_AUTO"}
            ],
        }],
    }))
    preview = build_ftd_preview(result)
    policy = preview["sections"]["policies"][0]
    assert (policy["policy_id"], policy["policy_name"], policy["rule_id"], policy["position"]) == (
        "acp-1", "Corporate ACP", "rule-1", 7,
    )
    nat = preview["sections"]["nat"][0]
    assert (nat["policy_id"], nat["policy_name"], nat["rule_id"], nat["position"]) == (
        "nat-1", "Edge NAT", "nat-rule-1", 3,
    )


def test_excel_source_inventory_exposes_structured_ownership_columns():
    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "domain": {"id": "domain-1", "name": "Global"},
        "devices": [{"id": "device-1", "name": "FTD-A", "resources": {
            "virtual_routers": [{"id": "vr-1", "name": "VR-A", "resources": {}}]
        }}],
    }))
    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)
    output.seek(0)
    workbook = load_workbook(output, read_only=True)
    headers = [cell.value for cell in workbook["Source Inventory"][1]]
    assert {"Domain", "Device", "Device Name", "Virtual Router ID", "Virtual Router",
            "Parent Policy ID", "Parent Policy"} <= set(headers)


def test_preview_keeps_fmc_policy_and_rule_identity_separate():
    result = CiscoFTDSourceReporter().analyze_source(FIXTURE.read_text(encoding="utf-8"))
    policy = result.config.access_control_policies[0]
    rule = policy.rules[0]
    row = build_ftd_preview(result)["sections"]["policies"][0]

    assert row["policy_id"] == policy.source_id == "acp-1"
    assert row["policy_name"] == policy.name == "Access"
    assert row["rule_id"] == rule.source_id == "r-1"
    assert row["name"] == rule.name == "Allow updates"
    assert row["position"] == rule.position
    assert row["policy_id"] != row["position"]


def test_validation_findings_keep_stable_fmc_scope_identity():
    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "domain": {"id": "domain-1", "name": "Global"},
        "access_policies": [{
            "id": "policy-1", "name": "Policy",
            "rules": [
                {"id": "rule-1", "name": "First", "position": 4, "action": "ALLOW"},
                {"id": "rule-2", "name": "Second", "position": 4, "action": "BLOCK"},
            ],
        }],
    }))
    issue = next(item for item in result.validation.issues if item.category == "duplicate-acp-position")
    assert issue.source_id == "policy-1"
    assert issue.source_context == "fmc:Global"
    assert issue.domain_id == "domain-1"

    row = next(item for item in build_ftd_preview(result)["sections"]["validation"]
               if item["domain"] == "duplicate-acp-position")
    assert row["source_id"] == "policy-1"
    assert row["source_context"] == "fmc:Global"
    assert row["domain_id"] == "domain-1"


def test_source_inventory_exports_policy_ownership_and_native_types():
    result = CiscoFTDSourceReporter().analyze_source(FIXTURE.read_text(encoding="utf-8"))
    rule_item = next(item for item in result.inventory_items if item.source_id == "r-1")
    assert rule_item.source_attributes["policy_id"] == "acp-1"
    assert rule_item.source_record_id.startswith("fmc-rest-bundle/domain=domain-1/")
    assert "/parent=acp-1/" in rule_item.source_record_id

    address_item = next(item for item in result.inventory_items
                        if item.source_path.endswith("/network-addresses"))
    assert address_item.source_type.startswith("Network") or address_item.source_type in {
        "Host", "Network", "Range", "FQDN",
    }

    output = BytesIO()
    CiscoFTDSourceReporter().export_excel(result, output)
    workbook = load_workbook(output, read_only=True)
    headers = [cell.value for cell in workbook["Source Inventory"][1]]
    for column in ("Virtual Router ID", "Virtual Router", "Parent Policy ID", "Parent Policy"):
        assert column in headers
    rows = [dict(zip(headers, row)) for row in
            workbook["Source Inventory"].iter_rows(min_row=2, values_only=True)]
    exported_rule = next(row for row in rows if row["Source ID"] == "r-1")
    assert exported_rule["Parent Policy ID"] == "acp-1"


def test_unsupported_evidence_does_not_cross_associate_duplicate_scoped_names():
    from fwmigrate.vendors.cisco_ftd.model import CiscoFTDConfig, CiscoFTDNetworkAddress
    from fwmigrate.vendors.cisco_ftd.source_inventory import build_ftd_source_inventory

    first = CiscoFTDNetworkAddress(
        name="duplicate", source_id="id-1", source_plane="fmc-rest-bundle", domain_id="domain-1")
    second = CiscoFTDNetworkAddress(
        name="duplicate", source_id="id-2", source_plane="fmc-rest-bundle", domain_id="domain-2")
    config = CiscoFTDConfig(
        input_source_type="fmc-rest-bundle", source_plane="fmc-rest-bundle",
        network_addresses=[first, second],
        unsupported_evidence=[{"source_name": "duplicate", "reason": "ambiguous name-only evidence"}],
    )
    items = [item for item in build_ftd_source_inventory(config)
             if item.source_path.endswith("/network-addresses")]
    assert [item.requires_manual_review for item in items] == [False, False]

    config.unsupported_evidence = [{
        "source_id": "id-2", "domain_id": "domain-2", "reason": "scoped evidence",
    }]
    items = [item for item in build_ftd_source_inventory(config)
             if item.source_path.endswith("/network-addresses")]
    assert [item.requires_manual_review for item in items] == [False, True]
    assert len({item.source_record_id for item in items}) == 2


def test_fmc_unnamed_policy_does_not_manufacture_child_policy_name():
    result = extract_cisco_ftd_source(json.dumps({
        "source": "fmc-rest-api",
        "domain": {"id": "domain-1", "name": "Global"},
        "access_policies": [{
            "id": "policy-without-name",
            "rules": [{"id": "rule-1", "name": "Rule", "action": "ALLOW"}],
        }],
    }))
    policy = result.config.access_control_policies[0]
    rule = policy.rules[0]
    assert policy.name is None
    assert rule.policy_id == "policy-without-name"
    assert rule.policy_name is None
    assert rule.source_attributes["policy_name"] is None

    preview = build_ftd_preview(result)["sections"]["policies"][0]
    assert preview["policy_id"] == "policy-without-name"
    assert preview["policy_name"] is None

    inventory = next(item for item in result.inventory_items if item.source_id == "rule-1")
    assert inventory.source_attributes["policy_id"] == "policy-without-name"
    assert inventory.source_attributes["policy_name"] is None
