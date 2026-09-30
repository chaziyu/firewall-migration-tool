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
