from pathlib import Path

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source
from fwmigrate.vendors.checkpoint.web_report import build_checkpoint_preview


def test_web_report_contains_source_and_validation_sections():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "multidomain_full.json").read_text()
    report = extract_checkpoint_source(source)
    preview = build_checkpoint_preview(report)
    assert preview["vendor"] == "checkpoint"
    assert "access_rules" in preview["sections"]
