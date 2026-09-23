from pathlib import Path

from fwmigrate.vendors.checkpoint.source_report import extract_checkpoint_source


def test_incomplete_collection_is_reported_not_treated_as_empty():
    source = (Path(__file__).parents[2] / "fixtures" / "checkpoint" / "partial_collection.json").read_text()
    result = extract_checkpoint_source(source)
    assert any(not item.complete for item in result.collection)
    assert any(issue.category == "collection" for issue in result.validation.issues)
