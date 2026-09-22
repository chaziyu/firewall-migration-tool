import ast
from pathlib import Path

import pytest

import fwmigrate.web as web
from fwmigrate.source_reporting import SourceReportRegistry


SOURCE_REPORTING = Path(__file__).parents[2] / "src" / "fwmigrate" / "source_reporting"


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
