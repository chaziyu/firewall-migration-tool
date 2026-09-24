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
