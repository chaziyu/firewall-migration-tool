import ast
from pathlib import Path


VENDOR = Path(__file__).parents[2] / "src" / "fwmigrate" / "vendors" / "palo_alto"


def _imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]


def test_palo_source_model_and_relationships_do_not_import_presentation_or_extraction():
    assert not any(".export" in item or ".web_report" in item for item in _imports(VENDOR / "source_model.py"))
    assert not any(".export" in item or ".web_report" in item for item in _imports(VENDOR / "relationships" / "references.py"))


def test_palo_extraction_does_not_import_excel():
    assert not any(".export" in item for item in _imports(VENDOR / "extraction" / "extractor.py"))
