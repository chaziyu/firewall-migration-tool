from pathlib import Path

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source


def test_unknown_commands_and_permission_failures_are_validation_evidence():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "partial_collection.json").read_text()
    result = extract_checkpoint_source(source)
    assert result.validation.issues
