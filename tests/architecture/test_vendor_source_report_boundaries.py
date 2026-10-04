import ast
from pathlib import Path


ROOT = Path(__file__).parents[2] / "src" / "fwmigrate" / "vendors"


def test_ftd_and_juniper_reporters_only_expose_report_entrypoints():
    for vendor, allowed in (
        ("cisco_ftd", {"extract_cisco_ftd_source"}),
        ("juniper_srx", {"extract_juniper_source"}),
    ):
        tree = ast.parse((ROOT / vendor / "source_report.py").read_text(encoding="utf-8"))
        functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
        assert functions == allowed
        assert not any(isinstance(node, (ast.For, ast.While)) for node in tree.body)


def test_fortigate_pipeline_has_no_noop_extraction_config_layer():
    fortigate = ROOT / "fortigate"

    assert not (fortigate / "config.py").exists()

    extractor = ast.parse((fortigate / "extraction" / "extractor.py").read_text(encoding="utf-8"))
    export = ast.parse((fortigate / "export" / "excel.py").read_text(encoding="utf-8"))

    extract_function = next(
        node for node in extractor.body
        if isinstance(node, ast.FunctionDef) and node.name == "extract_fortigate_config"
    )
    export_function = next(
        node for node in export.body
        if isinstance(node, ast.FunctionDef) and node.name == "export_excel"
    )

    assert "config" not in {
        argument.arg
        for argument in (*extract_function.args.args, *extract_function.args.kwonlyargs)
    }
    assert "config" not in {
        argument.arg
        for argument in (*export_function.args.args, *export_function.args.kwonlyargs)
    }
