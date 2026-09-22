import ast
from pathlib import Path

import pytest

from fwmigrate.extraction.models import ExtractionStatus
import fwmigrate.web as web
from fwmigrate.source_reporting import SourceReportRegistry


SOURCE_REPORTING = Path(__file__).parents[2] / "src" / "fwmigrate" / "source_reporting"
SOURCE_ROOT = Path(__file__).parents[2] / "src" / "fwmigrate"


def test_source_reporting_modules_do_not_import_legacy_ir():
    for path in SOURCE_REPORTING.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        assert all(
            "fwmigrate.ir" not in (node.module or "")
            and all(name.name != "IRConfig" for name in getattr(node, "names", ()))
            for node in imports
        ), path


class _Reporter:
    vendor_id = "Example"
    supported_extensions = (".CFG",)

    def analyze_source(self, source, **options):
        return {"source": source}

    def build_preview(self, analysis, **options):
        return analysis

    def export_excel(self, analysis, output, **options):
        output.write(analysis)


def test_source_report_registry_dispatches_without_interpreting_results():
    registry = SourceReportRegistry()
    reporter = _Reporter()
    registry.register(reporter)

    assert registry.get(" example ") is reporter
    assert registry.for_extension("cfg") == (reporter,)
    assert reporter.build_preview(reporter.analyze_source("vendor data")) == {
        "source": "vendor data"
    }


def test_source_report_registry_rejects_duplicate_vendors():
    registry = SourceReportRegistry()
    registry.register(_Reporter())
    with pytest.raises(ValueError):
        registry.register(_Reporter())


def test_source_excel_endpoint_does_not_use_legacy_ir_exporter():
    tree = ast.parse((Path(web.__file__)).read_text(encoding="utf-8"))
    endpoint = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "extract_excel"
    )
    assert not any(
        isinstance(node, ast.Name) and node.id == "IRExcelExporter"
        for node in ast.walk(endpoint)
    )
    assert any(
        isinstance(node, ast.Attribute) and node.attr == "export_excel"
        for node in ast.walk(endpoint)
    )


def test_source_models_do_not_reintroduce_migration_fields():
    forbidden = {"migration_status", "migration_impact"}
    found = []
    for path in SOURCE_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for class_node in (node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)):
            for node in class_node.body:
                target = node.target if isinstance(node, ast.AnnAssign) else None
                if target is None and isinstance(node, ast.Assign) and len(node.targets) == 1:
                    target = node.targets[0]
                if isinstance(target, ast.Name) and target.id in forbidden:
                    found.append(f"{path}:{target.id}")

    assert not found, "Forbidden source-model fields: " + ", ".join(found)


def test_shared_extraction_status_has_no_migration_enum_members():
    assert not {"NORMALIZED", "PARTIALLY_NORMALIZED"} & ExtractionStatus.__members__.keys()
