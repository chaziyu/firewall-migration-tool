import ast
from pathlib import Path


ROOT = Path(__file__).parents[2]
VENDOR = ROOT / "src" / "fwmigrate" / "vendors" / "checkpoint"


def test_checkpoint_reporting_modules_are_ir_free():
    paths = [
        VENDOR / "source_model.py",
        VENDOR / "source_report.py",
        VENDOR / "derived.py",
        VENDOR / "web_report.py",
        *sorted((VENDOR / "validation").glob("*.py")),
        *sorted((VENDOR / "export").glob("*.py")),
    ]
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        assert all(
            "fwmigrate.ir" not in (getattr(node, "module", "") or "")
            and all(name.name != "IRConfig" for name in getattr(node, "names", ()))
            for node in imports
        ), path


def test_checkpoint_ir_adapter_is_removed():
    assert not (VENDOR / "ir_adapter.py").exists()
    assert (VENDOR / "source_report.py").is_file()


def test_checkpoint_layers_keep_directional_boundaries():
    assert not any(".export" in item for item in _imports(VENDOR / "loader.py"))
    assert not any(".extraction" in item for item in _imports(VENDOR / "source_model.py"))
    assert not any(".export" in item for item in _imports(VENDOR / "extraction" / "common.py"))
    assert not any(".web_report" in item or ".export" in item for item in _imports(VENDOR / "relationships" / "references.py"))


def _imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
