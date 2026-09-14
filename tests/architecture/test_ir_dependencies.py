import ast
import importlib
from pathlib import Path


ROOT = Path(__file__).parents[2]
IR_ROOT = ROOT / "src" / "fwmigrate" / "ir"
DOMAIN_MODULES = (
    "common",
    "metadata",
    "provenance",
    "network",
    "address",
    "service",
    "policy",
    "nat",
    "routing",
    "vpn",
    "security_profiles",
)


def test_irconfig_has_one_aggregate_root_and_core_is_compatibility_only():
    from fwmigrate.ir.config import IRConfig
    from fwmigrate.ir.core import IRConfig as LegacyIRConfig

    core = ast.parse((IR_ROOT / "core.py").read_text(encoding="utf-8"))
    assert IRConfig is LegacyIRConfig
    assert not any(isinstance(node, ast.ClassDef) for node in core.body)


def test_each_domain_has_unique_exports_and_does_not_import_config():
    exported = {}
    for module in DOMAIN_MODULES:
        path = IR_ROOT / f"{module}.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.ImportFrom):
                assert node.module != "config"
                assert "fwmigrate.generators" not in (node.module or "")
                assert "fwmigrate.parsers" not in (node.module or "")
        imported = importlib.import_module(f"fwmigrate.ir.{module}")
        for name in imported.__all__:
            assert name not in exported, f"{name} exported twice"
            exported[name] = module

    assert len(exported) == 216
