import ast
from pathlib import Path


ROOT = Path(__file__).parents[2]
VENDOR = ROOT / "src" / "fwmigrate" / "vendors" / "checkpoint"


def test_checkpoint_reporting_modules_are_ir_free():
    paths = [
        VENDOR / "source_model.py",
        VENDOR / "source_report.py",
        VENDOR / "derived.py",
        VENDOR / "validation.py",
        VENDOR / "web_report.py",
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
            "fwmigrate.ir" not in (node.module or "")
            and all(name.name != "IRConfig" for name in getattr(node, "names", ()))
            for node in imports
        ), path


def test_checkpoint_ir_adapter_is_separate_from_source_reporting():
    assert (VENDOR / "ir_adapter.py").is_file()
    assert (VENDOR / "source_report.py").is_file()
