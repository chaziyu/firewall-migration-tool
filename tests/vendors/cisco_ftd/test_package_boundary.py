import ast
from pathlib import Path


ROOT = Path(__file__).parents[3] / "src" / "fwmigrate" / "vendors" / "cisco_ftd"


def test_source_reporting_is_vendor_native_and_keeps_source_planes_separate():
    source_report = (ROOT / "source_report.py").read_text(encoding="utf-8")
    tree = ast.parse(source_report)
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]

    assert "IRConfig" not in source_report
    assert all("fwmigrate.ir" not in (node.module or "") for node in imports)
    assert (ROOT / "cli").is_dir()
    assert (ROOT / "fmc").is_dir()
    assert (ROOT / "fdm").is_dir()


def test_legacy_parser_path_is_only_a_compatibility_facade():
    facade = Path(__file__).parents[3] / "src" / "fwmigrate" / "parsers" / "cisco_ftd"
    assert "vendors.cisco_ftd" in (facade / "__init__.py").read_text(encoding="utf-8")
