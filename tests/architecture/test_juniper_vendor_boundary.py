import ast
from pathlib import Path


ROOT = Path(__file__).parents[2]
VENDOR = ROOT / "src" / "fwmigrate" / "vendors" / "juniper_srx"


def _imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]


def test_juniper_source_model_and_relationship_layers_do_not_import_presentation():
    paths = [VENDOR / "model.py", VENDOR / "relationships.py", VENDOR / "derived.py"]
    paths.extend(sorted((VENDOR / "transforms").glob("*.py")))
    for path in paths:
        assert not any(".export" in item or ".web_report" in item for item in _imports(path)), path


def test_juniper_handlers_and_validation_do_not_import_presentation():
    paths = [VENDOR / "validation.py", *sorted((VENDOR / "handlers").glob("*.py"))]
    for path in paths:
        assert not any(".export" in item or ".web_report" in item for item in _imports(path)), path


def test_juniper_source_reporting_path_does_not_import_legacy_ir_or_target_generators():
    paths = [VENDOR / "parser.py", VENDOR / "source_report.py", VENDOR / "model.py",
             VENDOR / "relationships.py", VENDOR / "derived.py", VENDOR / "validation.py"]
    paths.extend(sorted((VENDOR / "handlers").glob("*.py")))
    paths.extend(sorted((VENDOR / "transforms").glob("*.py")))
    forbidden = ("fwmigrate.ir", "IRConfig", "fortigate", "palo_alto", "cisco_asa", "cisco_ftd")
    for path in paths:
        assert not any(any(term in item for term in forbidden) for item in _imports(path)), path


def test_juniper_presentation_does_not_import_parser_handlers():
    paths = [VENDOR / "web_report.py", *sorted((VENDOR / "export").glob("*.py"))]
    for path in paths:
        assert not any(".handlers" in item for item in _imports(path)), path
