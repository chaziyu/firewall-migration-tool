from io import BytesIO

import ast

from openpyxl import load_workbook

from fwmigrate.vendors.cisco_asa.export.excel import export_asa_excel

from fwmigrate.vendors.cisco_asa.export.excel_schema import SHEET_HEADERS, SHEET_ORDER

from fwmigrate.vendors.cisco_asa.source_report import extract_cisco_asa_source

from fwmigrate.vendors.cisco_asa.web_report import build_asa_preview

from copy import deepcopy

from fwmigrate.vendors.cisco_asa.derived import build_asa_derived_views

from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser

from fwmigrate.vendors.cisco_asa.validation import validate_asa_config
from fwmigrate.vendors.cisco_asa.parser import CiscoASAParser


def parse(text):
    return CiscoASAParser(text).parse_raw()

from pathlib import Path

from fwmigrate.vendors.cisco_asa import CiscoASASourceReporter

from .helpers import assert_source_unchanged, snapshot_source, snapshot_value

from fwmigrate.vendors.cisco_asa import extract_cisco_asa_source

from fwmigrate.vendors.cisco_asa.model import CiscoInterface, CiscoNATRule, CiscoStaticRoute

def test_presentation_modules_do_not_import_parsers_or_calculate_semantics():
    from pathlib import Path

    root = Path(__file__).parents[3] / "src/fwmigrate/vendors/cisco_asa"
    for path in (root / "export/excel.py", root / "web_report.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        assert not any("parser" in module.casefold() for module in imports)
        calls = [node.func.id if isinstance(node.func, ast.Name) else node.func.attr
                 for node in ast.walk(tree) if isinstance(node, ast.Call)]
        assert not {"parse_raw", "resolve", "transform_nat", "transform_routes"} & set(calls)

def test_parser_does_not_attach_reference_failures_and_derived_views_do_not_mutate_source():
    config = parse("object-group network SERVERS\n network-object object MISSING")
    before = deepcopy(config)
    assert not any("relationship_issues" in item.source_attributes for item in config.network_groups)
    assert not any("reference" in reason.lower() for group in config.network_groups for reason in group.review_reasons)
    derived = build_asa_derived_views(config)
    validate_asa_config(config, derived)
    assert config == before
    assert any(not issue.resolved for issue in derived.relationship_issues)
    member_relation = derived.group_relationships.members[0]
    assert member_relation.status.value == "UNRESOLVED"
    assert member_relation.target is None
    assert "resolved" not in type(config.network_groups[0].member_entries[0]).model_fields

def test_nested_group_member_target_is_available_only_in_derived_views():
    config = parse(
        "object network SERVER\n host 192.0.2.10\n"
        "object-group network CHILD\n network-object object SERVER\n"
        "object-group network PARENT\n group-object CHILD\n"
    )
    before = deepcopy(config)

    derived = build_asa_derived_views(config)
    resolved = [edge for edge in derived.group_relationships.members if edge.target is not None]
    assert [(edge.reference_name, edge.target.name) for edge in resolved] == [
        ("SERVER", "SERVER"), ("CHILD", "CHILD"),
    ]
    assert config == before

def test_every_report_stage_leaves_authoritative_source_and_derived_state_read_only():
    result = extract_cisco_asa_source(
        "interface Ethernet0/0\n nameif outside\n"
        "object network WEB\n host 10.0.0.10\n"
        "object-group network SERVERS\n network-object object WEB\n"
        "access-list OUT extended permit ip object-group SERVERS any\n"
        "access-group OUT in interface outside\n"
        "nat (inside,outside) source static WEB interface\n"
        "route outside 192.0.2.0 255.255.255.0 192.0.2.1\n"
        "interface Ethernet0/1\n vendor-option retained\n"
    )
    source = snapshot_source(result.config)

    derived = build_asa_derived_views(result.config)
    assert_source_unchanged(result.config, source)
    derived_snapshot = snapshot_value(derived)
    validation = validate_asa_config(result.config, derived)
    assert_source_unchanged(result.config, source)

    from dataclasses import replace
    analysis = replace(result, derived=derived, validation=validation)

    output = BytesIO()
    export_asa_excel(analysis, output)
    assert output.getvalue()
    assert_source_unchanged(result.config, source)
    assert snapshot_value(derived) == derived_snapshot

def test_public_reporter_preview_and_export_leave_source_and_derived_state_unchanged():
    reporter = CiscoASASourceReporter()
    fixture = Path(__file__).parent / "fixtures" / "architecture_regression.cfg"
    analysis = reporter.analyze_source(fixture.read_text(encoding="utf-8"))
    assert {context.name for context in analysis.config.contexts} == {"customer-a", "customer-b"}
    source = snapshot_source(analysis.config)
    derived = snapshot_value(analysis.derived)

    preview = reporter.build_preview(analysis)
    assert preview["vendor"] == "cisco_asa"
    assert not hasattr(analysis, "canonical_ir")
    assert preview["derived"]["nat"]["rules"][0]["section"] == "object"
    assert preview["derived"]["nat"]["rules"][0]["effective_order"] == 2
    assert preview["derived"]["routes"][0]["effective_administrative_distance"] == 1
    assert_source_unchanged(analysis.config, source)
    assert snapshot_value(analysis.derived) == derived

    output = BytesIO()
    reporter.export_excel(analysis, output)
    assert output.getvalue()
    workbook = load_workbook(BytesIO(output.getvalue()), read_only=True)
    assert workbook["NAT Rules"]["C2"].value == 2
    assert workbook["NAT Rules"]["E2"].value == "object"
    assert workbook["Routes"]["F2"].value is None
    assert workbook["Routes"]["G2"].value == 1
    assert_source_unchanged(analysis.config, source)
    assert snapshot_value(analysis.derived) == derived

def test_removed_effective_fields_are_not_in_source_schema():
    assert not {"administrative_state_explicit", "administrative_state_effective"} & set(CiscoInterface.model_fields)
    assert not {"effective_administrative_distance"} & set(CiscoStaticRoute.model_fields)
    assert not {"effective_source_order", "object_nat_precedence", "object_nat_specificity", "effective_order_inputs"} & set(CiscoNATRule.model_fields)
