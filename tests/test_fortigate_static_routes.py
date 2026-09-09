from fwmigrate.generators.fortigate.cli_generator import FortiGateCLIGenerator
from fwmigrate.parsers.fortigate.extractor import extract_fortigate_config
from fwmigrate.parsers.fortigate.parser import FortiGateParser, parse_fortigate_config
from fwmigrate.parsers.fortigate.tokenizer import FortiGateTokenizer
from fwmigrate.report.excel_exporter import IRExcelExporter


def test_static_route_preferred_source_is_first_class_and_source_preserved():
    content = """config router static
    edit 10
        set dst 10.20.0.0 255.255.0.0
        set gateway 192.0.2.1
        set device "port1"
        set preferred-source 192.0.2.10
    next
end
"""
    parsed = parse_fortigate_config(content).static_routes[0]
    result = extract_fortigate_config(content)
    route = result.canonical_ir.routes[0]

    assert parsed.preferred_source == "192.0.2.10"
    assert (parsed.gateway, parsed.device) == ("192.0.2.1", "port1")
    assert route.source_preferred_source == "192.0.2.10"
    assert route.destination == "10.20.0.0/16"
    assert route.requires_manual_review is True
    assert route.migration_status == "PARTIALLY_NORMALIZED"
    assert route.review_reasons == [
        "Static route preferred-source requires target-specific validation."
    ]
    parser = FortiGateParser(FortiGateTokenizer(content))
    parser.parse()
    item = next(item for item in parser.source_inventory_items if item.source_id == "10")
    assert [(command.key, command.values) for command in item.commands if command.key == "preferred-source"] == [
        ("preferred-source", ["192.0.2.10"])
    ]
    assert all(item.source_field != "preferred-source" for item in result.dependencies)
    assert result.generation_safe is False
    assert "Generation BLOCKED" in FortiGateCLIGenerator().generate(result.canonical_ir)[0].content


def test_static_route_without_preferred_source_keeps_existing_behavior():
    result = extract_fortigate_config("""config router static
    edit 1
        set dst 10.0.0.0 255.255.255.0
        set gateway 192.0.2.1
        set device "port1"
    next
end
config router static
    edit 2
        set dst 10.1.0.0 255.255.255.0
        set preferred-source 10.0.0.5
    next
end
""")

    ordinary, preferred = result.canonical_ir.routes
    assert ordinary.source_preferred_source is None
    assert ordinary.requires_manual_review is False
    assert ordinary.migration_status == "NORMALIZED"
    assert preferred.source_preferred_source == "10.0.0.5"
    assert preferred.requires_manual_review is True


def test_routes_excel_exposes_preferred_source():
    result = extract_fortigate_config("""config router static
    edit 10
        set dst 10.20.0.0 255.255.0.0
        set preferred-source 192.0.2.10
    next
end
""")
    workbook = IRExcelExporter(result.canonical_ir, extraction_result=result).generate()

    from openpyxl import load_workbook
    from io import BytesIO

    sheet = load_workbook(BytesIO(workbook))["Routes"]
    headers = [cell.value for cell in sheet[3]]
    row = [cell.value for cell in sheet[4]]
    assert row[headers.index("Preferred Source")] == "192.0.2.10"
