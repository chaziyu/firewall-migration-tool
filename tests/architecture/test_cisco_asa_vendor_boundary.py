import ast
from pathlib import Path

ASA = Path(__file__).parents[2] / "src" / "fwmigrate" / "vendors" / "cisco_asa"
FORBIDDEN = (
    "phase10_17", "model_phase10_17", "phase10_17_safety",
    "apply_phase_10_17_patches", "apply_phase_10_17_safety",
    "get_asa_parser_class", "_PATCHED", "_ORIGINALS", "_postprocess_", "_wrap_",
)


def test_asa_production_has_no_phase_parser_scaffolding():
    for path in ASA.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert not any(token in source for token in FORBIDDEN), path
        ast.parse(source)


def test_asa_entry_point_uses_the_public_parser():
    source = (ASA / "source_report.py").read_text(encoding="utf-8")
    assert "CiscoASAParser(text" in source
    assert "get_asa_parser_class" not in source


def test_parser_dispatch_keeps_vendor_command_semantics_in_evaluators():
    tree = ast.parse((ASA / "parser.py").read_text(encoding="utf-8"))
    imports = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any("relationships" in module or "transforms" in module or
                   "web_report" in module or "export" in module for module in imports)
    parser = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "CiscoASAParser")
    methods = {node.name for node in parser.body if isinstance(node, ast.FunctionDef)}
    assert not methods.intersection({"_parse_route_line", "_parse_nat_line", "_parse_management_command_base",
                                     "_parse_crypto_map_line", "_parse_source_only_records", "_context_definition"})
