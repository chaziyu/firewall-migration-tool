"""Protect vendor ownership without importing application modules for inspection."""

import ast
from importlib.util import resolve_name
from pathlib import Path


ROOT = Path(__file__).parents[2] / "src" / "fwmigrate"


def _imports(source, package):
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = resolve_name("." * node.level + (node.module or ""), package) if node.level else node.module or ""
            yield module
            yield from (f"{module}.{alias.name}" for alias in node.names)


def _file_imports(path):
    package = ".".join(("fwmigrate", *path.parent.relative_to(ROOT).parts))
    return _imports(path.read_text(encoding="utf-8-sig"), package)


def _within(module, package):
    return module == package or module.startswith(package + ".")


def test_import_scan_resolves_relative_and_function_local_imports():
    source = """
from ... import conversion
def deferred():
    from ...conversion import registry
    import fwmigrate.conversion.builtin
"""
    assert "fwmigrate.conversion" in set(_imports(source, "fwmigrate.vendors.fortigate"))
    assert "fwmigrate.conversion.registry" in set(_imports(source, "fwmigrate.vendors.fortigate"))
    assert "fwmigrate.conversion.builtin" in set(_imports(source, "fwmigrate.vendors.fortigate"))


def test_vendor_source_and_reporting_layers_do_not_import_conversion():
    violations = []
    for layer in ("vendors", "source_reporting", "extraction", "parsers"):
        for path in (ROOT / layer).rglob("*.py"):
            forbidden = sorted(module for module in _file_imports(path) if _within(module, "fwmigrate.conversion"))
            if forbidden:
                violations.append((str(path.relative_to(ROOT)), forbidden))
    assert not violations, violations


def test_directional_pair_implementations_do_not_import_other_pairs():
    pairs = sorted(path for path in (ROOT / "conversion").iterdir() if path.is_dir() and "_to_" in path.name)
    violations = []
    for pair in pairs:
        other_pairs = [f"fwmigrate.conversion.{other.name}" for other in pairs if other != pair]
        for path in pair.rglob("*.py"):
            forbidden = sorted(module for module in _file_imports(path)
                               if any(_within(module, other) for other in other_pairs))
            if forbidden:
                violations.append((str(path.relative_to(ROOT)), forbidden))
    assert not violations, violations
